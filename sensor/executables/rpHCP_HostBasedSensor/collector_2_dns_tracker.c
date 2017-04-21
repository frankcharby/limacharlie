/*
Copyright 2015 refractionPOINT

Licensed under the Apache License, Version 2.0 ( the "License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <libOs/libOs.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>

#define RPAL_FILE_ID          71

#ifdef RPAL_PLATFORM_WINDOWS
#include <windows_undocumented.h>
#pragma warning( disable: 4214 )
#include <WinDNS.h>

RPRIVATE HMODULE hDnsApi = NULL;
RPRIVATE DnsGetCacheDataTable_f getCache = NULL;
RPRIVATE DnsFree_f freeCacheEntry = NULL;
#endif

#define DNS_LABEL_MAX_SIZE      254
#define DNS_A_RECORD            0x0001
#define DNS_AAAA_RECORD         0x001C
#define DNS_CNAME_RECORD        0x0005


typedef struct
{
    RU16 type;
    RU16 unused;
    RU32 flags;
    RPNCHAR name;

} _dnsRecord;


#pragma pack(push, 1)
typedef struct
{
    RU16 msgId;
    RU8 rd : 1;
    RU8 tc : 1;
    RU8 aa : 1;
    RU8 opCode : 4;
    RU8 qr : 1;
    RU8 rCode : 4;
    RU8 reserved : 3;
    RU8 ra : 1;
    RU16 qdCount;
    RU16 anCount;
    RU16 nsCount;
    RU16 arCount;
    RU8 data[];

} DnsHeader;

typedef struct
{
    RU8 nChar;
    RU8 label[];

} DnsLabel;

typedef struct
{
    RU16 recordType;
    RU16 recordClass;

} DnsQuestionInfo;

typedef struct
{
    RU16 recordType;
    RU16 recordClass;
    RU32 ttl;
    RU16 rDataLength;
    RU8 rData[];

} DnsResponseInfo;
#pragma pack(pop)

RPRIVATE
DnsLabel*
    dnsReadLabels
    (
        DnsLabel* pLabel,
        RCHAR humanLabel[ DNS_LABEL_MAX_SIZE ],
        RPU8 packetStart,
        RSIZET packetSize,
        RU32 labelOffset,
        RU32 depth
    )
{
    RU32 copied = labelOffset;

    if( 3 < depth )
    {
        return NULL;
    }

    if( NULL != pLabel )
    {
        while( IS_WITHIN_BOUNDS( pLabel, sizeof( *pLabel ), packetStart, packetSize ) &&
               ( 0xC0 <= pLabel->nChar ||
                 ( IS_WITHIN_BOUNDS( pLabel, sizeof( *pLabel ) + pLabel->nChar, packetStart, packetSize ) &&
                   0 != pLabel->nChar ) ) )
        {
            // It's possible for a pointer to be terminating a traditional label
            if( 0xC0 <= pLabel->nChar )
            {
                // Pointer to a label
                DnsLabel* tmpLabel = NULL;
                RU16 offset = rpal_ntoh16( *(RU16*)pLabel ) - 0xC000;

                if( !IS_WITHIN_BOUNDS( (RPU8)packetStart + offset, sizeof( RU16 ), packetStart, packetSize ) )
                {
                    rpal_debug_warning( "error parsing dns packet" );
                    return NULL;
                }

                tmpLabel = (DnsLabel*)( (RPU8)packetStart + offset );

                dnsReadLabels( tmpLabel, humanLabel, packetStart, packetSize, copied, depth + 1 );

                // Pointers are always terminating the label.
                pLabel = (DnsLabel*)( (RPU8)pLabel + sizeof( RU16 ) );
                break;
            }
            else
            {
                if( NULL != humanLabel &&
                    DNS_LABEL_MAX_SIZE >= copied + 1 + pLabel->nChar )
                {
                    if( 0 != copied )
                    {
                        humanLabel[ copied ] = '.';
                        copied++;
                    }
                    rpal_memory_memcpy( (RPU8)humanLabel + copied, pLabel->label, pLabel->nChar );
                    copied += pLabel->nChar;
                }
                else if( NULL != humanLabel )
                {
                    rpal_debug_warning( "error parsing dns packet" );
                }

                pLabel = (DnsLabel*)( (RPU8)pLabel + pLabel->nChar + 1 );
            }
        }
    }

    return pLabel;
}

RPRIVATE
RVOID
    _freeRecords
    (
        rBlob recs
    )
{
    RU32 i = 0;
    _dnsRecord* pRec = NULL;

    if( NULL != recs )
    {
        i = 0;
        while( NULL != ( pRec = rpal_blob_arrElem( recs, sizeof( *pRec ), i++ ) ) )
        {
            if( NULL != pRec->name )
            {
                rpal_memory_free( pRec->name );
            }
        }
    }
}

RPRIVATE
RS32
    _cmpDns
    (
        _dnsRecord* rec1,
        _dnsRecord* rec2
    )
{
    RS32 ret = 0;

    if( NULL != rec1 &&
        NULL != rec2 )
    {
        if( 0 == ( ret = rpal_memory_memcmp( rec1, 
                                             rec2, 
                                             sizeof( *rec1 ) - sizeof( RPWCHAR ) ) ) )
        {
            ret = rpal_string_strcmp( rec1->name, rec2->name );
        }
    }

    return ret;
}

RPRIVATE
RVOID
    dnsUmDiffThread
    (
        rEvent isTimeToStop
    )
{
    rSequence notif = NULL;
    rBlob snapCur = NULL;
    rBlob snapPrev = NULL;
    _dnsRecord rec = { 0 };
    _dnsRecord* pCurRec = NULL;
    RU32 i = 0;
    LibOsPerformanceProfile perfProfile = { 0 };
    
#ifdef RPAL_PLATFORM_WINDOWS
    PDNSCACHEENTRY pDnsEntry = NULL;
    PDNSCACHEENTRY pPrevDnsEntry = NULL;
#endif

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 10 );
    perfProfile.lastTimeoutValue = 100;
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 1;

    while( !rEvent_wait( isTimeToStop, 0 ) &&
           !kAcq_isAvailable() )
    {
        libOs_timeoutWithProfile( &perfProfile, FALSE, isTimeToStop );

        if( NULL != ( snapCur = rpal_blob_create( 0, 10 * sizeof( rec ) ) ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            if( TRUE == getCache( &pDnsEntry ) )
            {
                while( NULL != pDnsEntry )
                {
                    rec.flags = pDnsEntry->dwFlags;
                    rec.type = pDnsEntry->wType;
                    if( NULL != ( rec.name = rpal_string_strdup( pDnsEntry->pszName ) ) )
                    {
                        rpal_blob_add( snapCur, &rec, sizeof( rec ) );
                    }

                    pPrevDnsEntry = pDnsEntry;
                    pDnsEntry = pDnsEntry->pNext;

                    freeCacheEntry( pPrevDnsEntry->pszName, DnsFreeFlat );
                    freeCacheEntry( pPrevDnsEntry, DnsFreeFlat );
                }

                rpal_sort_array( rpal_blob_getBuffer( snapCur ), 
                                 rpal_blob_getSize( snapCur ) / sizeof( rec ), 
                                 sizeof( rec ), 
                                 _cmpDns );
            }
#endif

            // Do a general diff of the snapshots to find new entries.
            if( NULL != snapPrev )
            {
                i = 0;
                while( !rEvent_wait( isTimeToStop, 0 ) &&
                       NULL != ( pCurRec = rpal_blob_arrElem( snapCur, sizeof( rec ), i++ ) ) )
                {
                    if( -1 == rpal_binsearch_array( rpal_blob_getBuffer( snapPrev ), 
                                                    rpal_blob_getSize( snapPrev ) / sizeof( rec ), 
                                                    sizeof( rec ), 
                                                    pCurRec,
                                                    (rpal_ordering_func)_cmpDns ) )
                    {
                        if( NULL != ( notif = rSequence_new() ) )
                        {
                            rSequence_addSTRINGN( notif, RP_TAGS_DOMAIN_NAME, pCurRec->name );
                            rSequence_addRU16( notif, RP_TAGS_DNS_TYPE, pCurRec->type );
                            rSequence_addRU32( notif, RP_TAGS_DNS_FLAGS, pCurRec->flags );
                            hbs_timestampEvent( notif, 0 );

                            hbs_publish( RP_TAGS_NOTIFICATION_DNS_REQUEST, notif );

                            rSequence_free( notif );
                        }
                    }
                }
            }
        }

        if( NULL != snapPrev )
        {
            _freeRecords( snapPrev );
            rpal_blob_free( snapPrev );
            snapPrev = NULL;
        }

        snapPrev = snapCur;
        snapCur = NULL;

        libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );
    }

    if( NULL != snapPrev )
    {
        _freeRecords( snapPrev );
        rpal_blob_free( snapPrev );
        snapPrev = NULL;
    }
}

RPRIVATE
RVOID
    processDnsPacket
    (
        KernelAcqDnsPacket* pDns
    )
{
    rSequence notification = NULL;
    RU32 i = 0;
    DnsLabel* pLabel = NULL;
    DnsHeader* dnsHeader = NULL;
    DnsResponseInfo* pResponseInfo = NULL;
    RCHAR domain[ DNS_LABEL_MAX_SIZE ] = { 0 };
    RU16 recordType = 0;
    RU64 timestamp = 0;
    Atom parentAtom = { 0 };

    if( NULL != pDns )
    {
        dnsHeader = (DnsHeader*)( (RPU8)pDns + sizeof( *pDns ) );
        pLabel = (DnsLabel*)dnsHeader->data;

        // We may receive DNS requests from the kernel, so we will discard packets without Answers
        if( 0 == dnsHeader->anCount || 0 == dnsHeader->qr )
        {
            return;
        }

        for( i = 0; i < rpal_ntoh16( dnsHeader->qdCount ); i++ )
        {
            DnsQuestionInfo* pQInfo = NULL;

            pLabel = dnsReadLabels( pLabel, NULL, (RPU8)dnsHeader, pDns->packetSize, 0, 0 );

            pQInfo = (DnsQuestionInfo*)( (RPU8)pLabel + 1 );
            if( !IS_WITHIN_BOUNDS( pQInfo, sizeof( *pQInfo ), dnsHeader, pDns->packetSize ) )
            {
                rpal_debug_warning( "error parsing dns packet" );
                break;
            }

            pLabel = (DnsLabel*)( (RPU8)pQInfo + sizeof( *pQInfo ) );
        }

        if( !IS_WITHIN_BOUNDS( pLabel, sizeof( RU16 ), dnsHeader, pDns->packetSize ) )
        {
            rpal_debug_warning( "error parsing dns packet" );
            return;
        }

        for( i = 0; i < rpal_ntoh16( dnsHeader->anCount ); i++ )
        {
            pResponseInfo = NULL;
            
            rpal_memory_zero( domain, sizeof( domain ) );
            pLabel = dnsReadLabels( pLabel, domain, (RPU8)dnsHeader, pDns->packetSize, 0, 0 );

            pResponseInfo = (DnsResponseInfo*)pLabel;
            pLabel = (DnsLabel*)( (RPU8)pResponseInfo + sizeof( *pResponseInfo ) + rpal_ntoh16( pResponseInfo->rDataLength ) );

            if( !IS_WITHIN_BOUNDS( pResponseInfo, sizeof( *pResponseInfo ), dnsHeader, pDns->packetSize ) )
            {
                rpal_debug_warning( "error parsing dns packet" );
                break;
            }

            if( NULL == ( notification = rSequence_new() ) )
            {
                rpal_debug_warning( "error parsing dns packet" );
                break;
            }

            timestamp = pDns->ts;
            timestamp += MSEC_FROM_SEC( rpal_time_getGlobalFromLocal( 0 ) );

            parentAtom.key.process.pid = pDns->pid;
            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
            if( atoms_query( &parentAtom, timestamp ) )
            {
                HbsSetParentAtom( notification, parentAtom.id );
            }

            rSequence_addTIMESTAMP( notification, RP_TAGS_TIMESTAMP, timestamp );
            rSequence_addSTRINGA( notification, RP_TAGS_DOMAIN_NAME, domain );
            rSequence_addRU32( notification, RP_TAGS_PROCESS_ID, pDns->pid );

            recordType = rpal_ntoh16( pResponseInfo->recordType );

            rSequence_addRU16( notification, RP_TAGS_MESSAGE_ID, rpal_ntoh16( dnsHeader->msgId ) );
            rSequence_addRU16( notification, RP_TAGS_DNS_TYPE, recordType );

            if( DNS_A_RECORD == recordType )
            {
                rSequence_addIPV4( notification, RP_TAGS_IP_ADDRESS, *(RU32*)pResponseInfo->rData );
            }
            else if( DNS_AAAA_RECORD == recordType )
            {
                rSequence_addIPV6( notification, RP_TAGS_IP_ADDRESS, pResponseInfo->rData );
            }
            else if( DNS_CNAME_RECORD == recordType )
            {
                rpal_memory_zero( domain, sizeof( domain ) );
                dnsReadLabels( (DnsLabel*)pResponseInfo->rData, domain, (RPU8)dnsHeader, pDns->packetSize, 0, 0 );
                rSequence_addSTRINGA( notification, RP_TAGS_CNAME, domain );
            }
            else
            {
                // Right now we only care for A, CNAME and AAAA records.
                rSequence_free( notification );
                notification = NULL;
                continue;
            }

            hbs_publish( RP_TAGS_NOTIFICATION_DNS_REQUEST, notification );
            rSequence_free( notification );
            notification = NULL;
        }
    }
}

RPRIVATE
RVOID
    dnsKmDiffThread
    (
        rEvent isTimeToStop
    )
{
    RU8 new_from_kernel[ 128 * 1024 ] = { 0 };
    RU8 prev_from_kernel[ 128 * 1024 ] = { 0 };

    RU32 sizeInNew = 0;
    RU32 sizeInPrev = 0;

    KernelAcqDnsPacket* pDns = NULL;

    while( !rEvent_wait( isTimeToStop, 1000 ) )
    {
        rpal_memory_zero( new_from_kernel, sizeof( new_from_kernel ) );
        sizeInNew = sizeof( new_from_kernel );

        if( !kAcq_getNewDnsPackets( (KernelAcqDnsPacket*)new_from_kernel, &sizeInNew ) )
        {
            rpal_debug_warning( "kernel acquisition for new dns packets failed" );
            break;
        }

        pDns = (KernelAcqDnsPacket*)prev_from_kernel;
        while( IS_WITHIN_BOUNDS( pDns, sizeof( *pDns ), prev_from_kernel, sizeInPrev ) &&
               0 != pDns->ts &&
               IS_WITHIN_BOUNDS( pDns, sizeof( *pDns ) + pDns->packetSize, prev_from_kernel, sizeInPrev ) )
        {
            processDnsPacket( pDns );

            pDns = (KernelAcqDnsPacket*)( (RPU8)pDns + sizeof( *pDns ) + pDns->packetSize );
        }

        rpal_memory_memcpy( prev_from_kernel, new_from_kernel, sizeInNew );
        sizeInPrev = sizeInNew;
    }
}

RPRIVATE
RPVOID
    dnsDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( kAcq_isAvailable() )
        {
            rpal_debug_info( "running kernelmode acquisition dns notification" );
            dnsKmDiffThread( isTimeToStop );
        }
        else if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            rpal_debug_info( "running usermode acquisition dns notification" );
            dnsUmDiffThread( isTimeToStop );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_2_events[] = { RP_TAGS_NOTIFICATION_DNS_REQUEST,
                                  0 };

RBOOL
    collector_2_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RWCHAR apiName[] = _WCH( "dnsapi.dll" );
        RCHAR funcName1[] = "DnsGetCacheDataTable";
        RCHAR funcName2[] = "DnsFree";

        if( NULL != ( hDnsApi = LoadLibraryW( (RPWCHAR)&apiName ) ) )
        {
            // TODO: investigate the DnsQuery API on Windows to get the DNS resolutions.
            if( NULL != ( getCache = (DnsGetCacheDataTable_f)GetProcAddress( hDnsApi, (RPCHAR)&funcName1 ) ) &&
                NULL != ( freeCacheEntry = (DnsFree_f)GetProcAddress( hDnsApi, (RPCHAR)&funcName2 ) ) )
            {
                isSuccess = TRUE;
            }
            else
            {
                rpal_debug_warning( "failed to get dns undocumented function" );
                FreeLibrary( hDnsApi );
            }
        }
        else
        {
            rpal_debug_warning( "failed to load dns api" );
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        isSuccess = TRUE;
#endif
        if( isSuccess )
        {
            isSuccess = FALSE;

            if( rThreadPool_task( hbsState->hThreadPool, dnsDiffThread, NULL ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_2_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        if( NULL != hDnsApi )
        {
            getCache = NULL;
            freeCacheEntry = NULL;
            FreeLibrary( hDnsApi );
        }
#endif
        isSuccess = TRUE;
    }

    return isSuccess;
}

//=============================================================================
//  Collector Testing
//=============================================================================
HBS_TEST_SUITE( 2 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}