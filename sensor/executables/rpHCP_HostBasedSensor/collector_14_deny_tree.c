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


#define RPAL_FILE_ID                  97

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <processLib/processLib.h>

RPRIVATE rBlob g_denied = NULL;
RPRIVATE rMutex g_deniedMutex = NULL;

RPRIVATE
RS32
    cmpAtoms
    (
        RPU8 atomId1,
        RPU8 atomId2
    )
{
    return (RS32)rpal_memory_memcmp( atomId1, atomId2, HBS_ATOM_ID_SIZE );
}

RPRIVATE
RVOID
    addAtomToDeny
    (
        RPU8 atomId
    )
{
    if( rMutex_lock( g_deniedMutex ) )
    {
        rpal_blob_add( g_denied, atomId, HBS_ATOM_ID_SIZE );
        rpal_sort_array( rpal_blob_getBuffer( g_denied ), 
                         rpal_blob_getSize( g_denied ) / HBS_ATOM_ID_SIZE, 
                         HBS_ATOM_ID_SIZE, 
                         cmpAtoms );

        rMutex_unlock( g_deniedMutex );
    }
}

RPRIVATE
RBOOL
    isAtomDenied
    (
        RPU8 atomId
    )
{
    RBOOL isDenied = FALSE;

    if( rMutex_lock( g_deniedMutex ) )
    {
        if( ( -1 ) != rpal_binsearch_array( rpal_blob_getBuffer( g_denied ),
                                            rpal_blob_getSize( g_denied ) / HBS_ATOM_ID_SIZE,
                                            HBS_ATOM_ID_SIZE,
                                            atomId,
                                            cmpAtoms ) )
        {
            isDenied = TRUE;
        }

        rMutex_unlock( g_deniedMutex );
    }

    return isDenied;
}

RPRIVATE
RVOID
    denyNewTree
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPU8 atomId = NULL;
    RU32 size = 0;
    rList atomList = NULL;

    UNREFERENCED_PARAMETER( notifType );

    // We accept a single atom, or a list of atoms
    if( rSequence_getBUFFER( event, RP_TAGS_HBS_THIS_ATOM, &atomId, &size ) &&
        HBS_ATOM_ID_SIZE == size )
    {
        addAtomToDeny( atomId );
    }
    else if( rSequence_getLIST( event, RP_TAGS_HBS_THIS_ATOM, &atomList ) )
    {
        while( rList_getBUFFER( atomList, RP_TAGS_HBS_THIS_ATOM, &atomId, &size ) &&
               HBS_ATOM_ID_SIZE == size )
        {
            addAtomToDeny( atomId );
        }
    }
}

RPRIVATE
RVOID
    denyNewProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPU8 atomId = NULL;
    RU32 pid = 0;

    UNREFERENCED_PARAMETER( notifType );
    
    if( HbsGetParentAtom( event, &atomId ) &&
        isAtomDenied( atomId ) )
    {
        // This atom is part of a tree that needs to be denied, so we do two things:
        // 1- Add its atom to the list of denied atoms.
        if( HbsGetThisAtom( event, &atomId ) )
        {
            addAtomToDeny( atomId );
        }

        // 2- As this is a process, we deny by killing it.
        if( rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) )
        {
            if( processLib_killProcess( pid ) )
            {
                rpal_debug_info( "denied process id " RF_U32, pid );
            }
            else
            {
                rpal_debug_warning( "failed to deny process id " RF_U32, pid );
            }
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_14_events[] = { 0 };

RBOOL
    collector_14_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );
    UNREFERENCED_PARAMETER( hbsState );

    if( notifications_subscribe( RP_TAGS_NOTIFICATION_DENY_TREE_REQ, NULL, 0, NULL, denyNewTree ) &&
        notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, denyNewProcesses ) &&
        NULL != ( g_deniedMutex = rMutex_create() ) &&
        NULL != ( g_denied = rpal_blob_create( 0, 0 ) ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_14_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( config );

    notifications_unsubscribe( RP_TAGS_NOTIFICATION_DENY_TREE_REQ, NULL, denyNewTree );
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, denyNewProcesses );
    rMutex_lock( g_deniedMutex );
    rpal_blob_free( g_denied );
    g_denied = NULL;
    rMutex_free( g_deniedMutex );
    g_deniedMutex = NULL;
    
    isSuccess = TRUE;

    return isSuccess;
}

//=============================================================================
//  Collector Testing
//=============================================================================
HBS_TEST_SUITE( 14 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}