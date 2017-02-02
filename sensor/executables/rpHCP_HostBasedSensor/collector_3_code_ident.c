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
#include <rpHostCommonPlatformLib/rTags.h>
#include <cryptoLib/cryptoLib.h>
#include <libOs/libOs.h>

#define RPAL_FILE_ID 72

#define _MAX_FILE_HASH_SIZE                 (1024 * 1024 * 20)
#define _CLEANUP_INEERVAL                   MSEC_FROM_SEC(60)
#define _CODE_INFO_TTL                      MSEC_FROM_SEC(60 * 60 * 24)

static rMutex g_mutex = NULL;
static rBTree g_reportedCode = NULL;
static RU64 g_lastCleanup = 0;

typedef struct
{
    struct
    {
        RNCHAR fileName[ RPAL_MAX_PATH ];
        CryptoLib_Hash fileHash;
    } info;
    struct
    {
        RERROR lastError;
        RU64 timeGenerated;
        RU64 lastCodeHitTime;
        RU8 thisCodeHitAtom[ HBS_ATOM_ID_SIZE ];
        RU8 parentCodeHitAtom[ HBS_ATOM_ID_SIZE ];
    } mtd;
} CodeInfo;

RPRIVATE
RS32
    _compCodeInfo
    (
        CodeInfo* info1,
        CodeInfo* info2
    )
{
    RS32 ret = 0;

    if( NULL != info1 &&
        NULL != info2 )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        ret = rpal_string_stricmp( info1->info.fileName, info2->info.fileName );
#else
        ret = rpal_string_strcmp( info1->info.fileName, info2->info.fileName );
#endif
    }

    return ret;
}

RPRIVATE
RBOOL
    cleanupTree
    (

    )
{
    RBOOL isSuccess = FALSE;
    CodeInfo info = { 0 };
    RU64 curTime = rpal_time_getGlobalPreciseTime();

    if( g_lastCleanup > curTime - _CLEANUP_INEERVAL )
    {
        // Not time to cleanup yet
        return TRUE;
    }

    rpal_debug_info( "initiate a tree cleanup" );
    g_lastCleanup = curTime;
    isSuccess = TRUE;

    if( rpal_btree_minimum( g_reportedCode, &info, TRUE ) )
    {
        do
        {
            if( info.mtd.timeGenerated < curTime - _CODE_INFO_TTL )
            {
                // Over TTL, remove.
                if( rpal_btree_remove( g_reportedCode, &info, NULL, TRUE ) )
                {
                    //rpal_debug_info( "REMOVED OLD ENTRY" );
                }
                else
                {
                    isSuccess = FALSE;
                }
            }
        }
        while( rpal_btree_after( g_reportedCode, &info, &info, TRUE ) );
    }

    if( !isSuccess )
    {
        rpal_debug_error( "error removing old code info" );
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    populateCodeInfo
    (
        CodeInfo* tmpInfo,
        CryptoLib_Hash* pHash,
        rSequence originalEvent
    )
{
    RBOOL isCanBeReported = TRUE;

    if( NULL != tmpInfo )
    {
        if( !rSequence_getTIMESTAMP( originalEvent, RP_TAGS_TIMESTAMP, &tmpInfo->mtd.timeGenerated ) )
        {
            tmpInfo->mtd.timeGenerated = rpal_time_getGlobalPreciseTime();
        }

        if( NULL != pHash )
        {
            // We already have a hash so use it.
            rpal_memory_memcpy( &tmpInfo->info.fileHash, pHash, sizeof( *pHash ) );
        }
        else
        {
            // We need to try to hash this file.
            if( _MAX_FILE_HASH_SIZE < rpal_file_getSize( tmpInfo->info.fileName, TRUE ) )
            {
                // Too big for us to try to hash it.
                tmpInfo->mtd.lastError = RPAL_ERROR_FILE_TOO_LARGE;
            }
            else
            {
                if( !CryptoLib_hashFile( tmpInfo->info.fileName, &tmpInfo->info.fileHash, TRUE ) )
                {
                    rpal_debug_info( "unable to fetch file hash for ident" );
                    tmpInfo->mtd.lastError = RPAL_ERROR_FILE_NOT_FOUND;
                }
            }
        }

        if( !rpal_btree_add( g_reportedCode, tmpInfo, TRUE ) &&
            !rpal_btree_update( g_reportedCode, tmpInfo, tmpInfo, TRUE ) )
        {
            // To avoid a situation where for whatever reason we cannot add to
            // history and we start spamming the same code over and over.
            rpal_debug_error( "error adding to known code" );
            isCanBeReported = FALSE;
        }
    }

    return isCanBeReported;
}

RPRIVATE
RBOOL
    checkNewIdent
    (
        CodeInfo* tmpInfo,
        CryptoLib_Hash* pHash,
        rSequence originalEvent,
        RBOOL isBypassMutex
    )
{
    RBOOL isNeedsReporting = FALSE;
    CodeInfo infoFound = { 0 };
    RPU8 tmpAtom = NULL;
    RU32 atomSize = 0;
    CryptoLib_Hash emptyHash = { 0 };

    if( NULL != tmpInfo )
    {
        if( isBypassMutex ||
            rMutex_lock( g_mutex ) )
        {
            // Check if it's time to cull the tree.
            cleanupTree();

            // First can we find this file name.
            if( rpal_btree_search( g_reportedCode, tmpInfo, &infoFound, TRUE ) )
            {
                // So the path matches, if a hash was already provided, check to see if the hash matches.
                if( 0 != rpal_memory_memcmp( &tmpInfo->info.fileHash, &infoFound.info.fileHash, sizeof( infoFound.info.fileHash ) ) &&
                    0 != rpal_memory_memcmp( &emptyHash, &tmpInfo->info.fileHash, sizeof( emptyHash ) ) )
                {
                    // Never seen this hash, report it.
                    isNeedsReporting = populateCodeInfo( tmpInfo, pHash, originalEvent );

                    // We only keep the last hash at a specific file.
                    *tmpInfo = infoFound;
                }
                else
                {
                    // Ok we've seen this path before, add ourselves to the code hit list.
                    if( !rSequence_getTIMESTAMP( originalEvent, RP_TAGS_TIMESTAMP, &infoFound.mtd.lastCodeHitTime ) )
                    {
                        infoFound.mtd.lastCodeHitTime = rpal_time_getGlobalPreciseTime();
                    }

                    if( HbsGetThisAtom( originalEvent, &tmpAtom ) )
                    {
                        rpal_memory_memcpy( infoFound.mtd.thisCodeHitAtom,
                                            tmpAtom,
                                            MIN_OF( atomSize, sizeof( infoFound.mtd.thisCodeHitAtom ) ) );
                    }

                    if( HbsGetParentAtom( originalEvent, &tmpAtom ) )
                    {
                        rpal_memory_memcpy( infoFound.mtd.parentCodeHitAtom,
                                            tmpAtom,
                                            MIN_OF( atomSize, sizeof( infoFound.mtd.parentCodeHitAtom ) ) );
                    }

                    if( !rpal_btree_update( g_reportedCode, tmpInfo, &infoFound, TRUE ) )
                    {
                        rpal_debug_error( "error updating last code hit" );
                    }
                }
            }
            else
            {
                // We've never seen this file, process it.
                isNeedsReporting = populateCodeInfo( tmpInfo, pHash, originalEvent );
            }

            if( !isBypassMutex )
            {
                rMutex_unlock( g_mutex );
            }
        }
    }

    return isNeedsReporting;
}

RPRIVATE
RVOID
    processCodeIdent
    (
        RPNCHAR name,
        CryptoLib_Hash* pFileHash,
        rSequence originalEvent,
        RPU8 pThisAtom,
        RPU8 pParentAtom,
        RBOOL isBypassMutex
    )
{
    rSequence notif = NULL;
    rSequence sig = NULL;
    RBOOL isSigned = FALSE;
    RBOOL isVerifiedLocal = FALSE;
    RBOOL isVerifiedGlobal = FALSE;
    RPU8 pAtomId = NULL;
    RU32 atomSize = 0;
    CodeInfo tmpInfo = { 0 };
    RU8 emptyHash[ CRYPTOLIB_HASH_SIZE ] = { 0 };

    UNREFERENCED_PARAMETER( pParentAtom );
    
    if( NULL != name )
    {
        rpal_memory_memcpy( tmpInfo.info.fileName,
                            name,
                            MIN_OF( sizeof( tmpInfo.info.fileName ),
                                    rpal_string_strsize( name ) ) );
    }

    if( NULL != pFileHash )
    {
        rpal_memory_memcpy( &tmpInfo.info.fileHash, pFileHash, sizeof( *pFileHash ) );
    }

    if( checkNewIdent( &tmpInfo, pFileHash, originalEvent, isBypassMutex ) )
    {
        if( NULL != ( notif = rSequence_new() ) )
        {
            hbs_markAsRelated( originalEvent, notif );

            if( rSequence_addSTRINGN( notif, RP_TAGS_FILE_PATH, name )  &&
                hbs_timestampEvent( notif, 0 ) )
            {
                if( NULL == originalEvent &&
                    NULL != pThisAtom )
                {
                    HbsSetParentAtom( notif, pThisAtom );
                }
                else if( rSequence_getBUFFER( originalEvent, RP_TAGS_HBS_THIS_ATOM, &pAtomId, &atomSize ) )
                {
                    HbsSetParentAtom( notif, pAtomId );
                }

                if( 0 != rpal_memory_memcmp( emptyHash, (RPU8)&tmpInfo.info.fileHash, sizeof( emptyHash ) ) )
                {
                    rSequence_addBUFFER( notif, RP_TAGS_HASH, (RPU8)&tmpInfo.info.fileHash, sizeof( tmpInfo.info.fileHash ) );
                }
                rSequence_addRU32( notif, RP_TAGS_ERROR, tmpInfo.mtd.lastError );

                if( libOs_getSignature( name,
                                        &sig,
                                        ( OSLIB_SIGNCHECK_NO_NETWORK | OSLIB_SIGNCHECK_CHAIN_VERIFICATION ),
                                        &isSigned,
                                        &isVerifiedLocal,
                                        &isVerifiedGlobal ) )
                {
                    if( !rSequence_addSEQUENCE( notif, RP_TAGS_SIGNATURE, sig ) )
                    {
                        rSequence_free( sig );
                    }
                }

                hbs_publish( RP_TAGS_NOTIFICATION_CODE_IDENTITY, notif );
            }

            rSequence_free( notif );
        }
    }
}

RPRIVATE
RVOID
    processNewProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPNCHAR nameN = NULL;
    
    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &nameN ) )
        {
            processCodeIdent( nameN, NULL, event, NULL, NULL, FALSE );
        }
    }
}


RPRIVATE
RVOID
    processNewModule
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPNCHAR nameN = NULL;
    
    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &nameN ) )
        {
            processCodeIdent( nameN, NULL, event, NULL, NULL, FALSE );
        }
    }
}


RPRIVATE
RVOID
    processHashedEvent
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPNCHAR nameN = NULL;
    CryptoLib_Hash* pHash = NULL;
    
    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &nameN ) ||
            rSequence_getSTRINGN( event, RP_TAGS_DLL, &nameN ) ||
            rSequence_getSTRINGN( event, RP_TAGS_EXECUTABLE, &nameN ) )
        {
            if( !rSequence_getBUFFER( event, RP_TAGS_HASH, (RPU8*)&pHash, NULL ) )
            {
                pHash = NULL;
            }

            processCodeIdent( nameN, pHash, event, NULL, NULL, FALSE );
        }
    }
}

RPRIVATE
RVOID
    processGenericSnapshot
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    rList entityList = NULL;
    rSequence entity = NULL;

    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getLIST( event, RP_TAGS_AUTORUNS, &entityList ) ||
            rSequence_getLIST( event, RP_TAGS_SVCS, &entityList ) ||
            rSequence_getLIST( event, RP_TAGS_PROCESSES, &entityList ) )
        {
            // Go through the elements, whatever tag
            while( rList_getSEQUENCE( entityList, RPCM_INVALID_TAG, &entity ) )
            {
                processHashedEvent( notifType, entity );
            }
        }
    }
}

RPRIVATE
RVOID
    processFileEvents
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPNCHAR nameN = NULL;
    CodeInfo infoFound = { 0 };
    RTIME curTime = 0;
    RBOOL isRerunCodeHit = FALSE;
    UNREFERENCED_PARAMETER( notifType );

    if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &nameN ) )
    {
        rpal_memory_memcpy( infoFound.info.fileName,
                            nameN,
                            MIN_OF( sizeof( infoFound.info.fileName ),
                                    rpal_string_strsize( nameN ) ) );

        if( rMutex_lock( g_mutex ) )
        {
            if( rpal_btree_search( g_reportedCode, &infoFound, &infoFound, TRUE ) )
            {
                // We've reported on this file before. Before expelling it, check to see
                // if we've had a race condition with a load.
                if( rSequence_getTIMESTAMP( event, RP_TAGS_TIMESTAMP, &curTime ) &&
                    curTime <= infoFound.mtd.lastCodeHitTime )
                {
                    // Ok so there is a race condition, let's report this code hit.
                    isRerunCodeHit = TRUE;
                }

                // Expell the entry.
                rpal_btree_remove( g_reportedCode, &infoFound, NULL, TRUE );

                // If we need to rerun the code hit, do it.
                if( isRerunCodeHit )
                {
                    processCodeIdent( nameN, 
                                      NULL, 
                                      NULL, 
                                      infoFound.mtd.thisCodeHitAtom, 
                                      infoFound.mtd.parentCodeHitAtom, 
                                      TRUE );
                }
            }

            rMutex_unlock( g_mutex );
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_3_events[] = { RP_TAGS_NOTIFICATION_CODE_IDENTITY,
                                  0 };

RBOOL
    collector_3_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( NULL != ( g_mutex = rMutex_create() ) )
        {
            if( NULL != ( g_reportedCode = rpal_btree_create( sizeof( CodeInfo ), (rpal_btree_comp_f)_compCodeInfo, NULL ) ) )
            {
                isSuccess = FALSE;

                if( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, processNewProcesses ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, 0, NULL, processNewModule ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_SERVICE_CHANGE, NULL, 0, NULL, processHashedEvent ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_DRIVER_CHANGE, NULL, 0, NULL, processHashedEvent ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_AUTORUN_CHANGE, NULL, 0, NULL, processHashedEvent ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REP, NULL, 0, NULL, processGenericSnapshot ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REP, NULL, 0, NULL, processGenericSnapshot ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, NULL, 0, NULL, processGenericSnapshot ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP, NULL, 0, NULL, processGenericSnapshot ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, 0, NULL, processFileEvents ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, 0, NULL, processFileEvents ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, 0, NULL, processFileEvents ) )
                {
                    isSuccess = TRUE;
                }
                else
                {
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, processNewModule );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_SERVICE_CHANGE, NULL, processHashedEvent );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_DRIVER_CHANGE, NULL, processHashedEvent );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_AUTORUN_CHANGE, NULL, processHashedEvent );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REP, NULL, processGenericSnapshot );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REP, NULL, processGenericSnapshot );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, NULL, processGenericSnapshot );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP, NULL, processGenericSnapshot );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, processFileEvents );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, processFileEvents );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, processFileEvents );
                    
                    rpal_btree_destroy( g_reportedCode, TRUE );
                    g_reportedCode = NULL;
                    rMutex_free( g_mutex );
                    g_mutex = NULL;
                }
            }
            else
            {
                rMutex_free( g_mutex );
                g_mutex = NULL;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_3_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, processNewModule ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_SERVICE_CHANGE, NULL, processHashedEvent ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DRIVER_CHANGE, NULL, processHashedEvent ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_AUTORUN_CHANGE, NULL, processHashedEvent ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REP, NULL, processGenericSnapshot ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REP, NULL, processGenericSnapshot ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, NULL, processGenericSnapshot ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP, NULL, processGenericSnapshot ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, processFileEvents ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, processFileEvents ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, processFileEvents ) )
        {
            isSuccess = TRUE;
        }

        rpal_btree_destroy( g_reportedCode, TRUE );
        g_reportedCode = NULL;

        rMutex_free( g_mutex );
        g_mutex = NULL;
    }

    return isSuccess;
}

//=============================================================================
//  Collector Testing
//=============================================================================
RBOOL
    collector_3_test
    (
        HbsState* hbsState,
        SelfTestContext* testContext
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}