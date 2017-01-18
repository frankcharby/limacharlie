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

#define RPAL_FILE_ID          71

#ifdef RPAL_PLATFORM_WINDOWS
#include <windows_undocumented.h>
#pragma warning( disable: 4214 )
#include <WinDNS.h>

RPRIVATE HMODULE hDnsApi = NULL;
RPRIVATE DnsGetCacheDataTable_f getCache = NULL;
RPRIVATE DnsFree_f freeCacheEntry = NULL;
#endif

typedef struct
{
    RU16 type;
    RU16 unused;
    RU32 flags;
    RPNCHAR name;

} _dnsRecord;


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
RPVOID
    dnsDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
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

    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
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
