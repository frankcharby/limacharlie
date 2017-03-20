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

#include "commands.h"
#include <rpHostCommonPlatformLib/rTags.h>
#include "configurations.h"
#include "globalContext.h"
#include "crypto.h"
#include <MemoryModule/MemoryModule.h>
#include "obfuscated.h"
#include <obfuscationLib/obfuscationLib.h>
#include "beacon.h"
#include "crashHandling.h"

#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
#include <dlfcn.h>
#include <sys/stat.h>
#endif

#define RPAL_FILE_ID    51

RPRIVATE
RVOID
    _cleanupModuleEntry
    (
        rpHCPModuleInfo* mod
    )
{
    rEvent_free( mod->context.isTimeToStop );
    rpal_thread_free( mod->hThread );

    if( mod->isOsLoaded )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        FreeLibrary( (HMODULE)(mod->hModule) );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        dlclose( mod->hModule );
#endif
    }
    else
    {
        MemoryFreeLibrary( mod->hModule );
    }

    rpal_debug_info( "module %d cleaned up", mod->id );
    rpal_memory_zero( mod, sizeof( *mod ) );
}

RPRIVATE
RU32
    RPAL_THREAD_FUNC thread_quitAndCleanup
    (
        RPVOID context
    )
{
    UNREFERENCED_PARAMETER( context );

    if( 0 == rInterlocked_decrement32( &g_hcpContext.isRunning ) )
    {
        rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );

        stopAllModules();

        stopBeacons();

        if( NULL != g_hcpContext.enrollmentToken &&
            0 != g_hcpContext.enrollmentTokenSize )
        {
            rpal_memory_free( g_hcpContext.enrollmentToken );
        }

        // If the default crashContext is still present, remove it since
        // we are shutting down properly. If it's non-default leave it since
        // somehow we may have had a higher order crash we want to keep
        // track of but we are still leaving through our normal code path.
        if( 1 == getCrashContextSize() )
        {
            cleanCrashContext();
        }

        rpal_Context_cleanup();

        rpal_Context_deinitialize();
    }
    else
    {
        rInterlocked_increment32( &g_hcpContext.isRunning );
    }

    return 0;
}

RPRIVATE_TESTABLE
RBOOL 
    loadModule
    (
        rpHCPContext* hcpContext,
        rSequence seq
    )
{
    RBOOL isSuccess = FALSE;

    RU32 moduleIndex = (RU32)(-1);

    RPU8 tmpBuff = NULL;
    RU32 tmpSize = 0;

    RPU8 tmpSig = NULL;
    RU32 tmpSigSize = 0;

    rpal_thread_func pEntry = NULL;

    rpHCPModuleContext* modContext = NULL;

    OBFUSCATIONLIB_DECLARE( entryName, RP_HCP_CONFIG_MODULE_ENTRY );
    OBFUSCATIONLIB_DECLARE( recvMessage, RP_HCP_CONFIG_MODULE_RECV_MESSAGE );

    if( NULL != seq &&
        NULL != hcpContext )
    {
        for( moduleIndex = 0; moduleIndex < RP_HCP_CONTEXT_MAX_MODULES; moduleIndex++ )
        {
            if( 0 == hcpContext->modules[ moduleIndex ].hThread )
            {
                // Found an empty spot
                break;
            }
        }
    }

    if( RP_HCP_CONTEXT_MAX_MODULES != moduleIndex &&
        (RU32)(-1) != moduleIndex )
    {
        // We got an empty spot for our module
        if( rSequence_getRU8( seq, 
                              RP_TAGS_HCP_MODULE_ID, 
                              &(hcpContext->modules[ moduleIndex ].id ) ) &&
            rSequence_getBUFFER( seq,
                                 RP_TAGS_BINARY, 
                                 &tmpBuff, 
                                 &tmpSize ) &&
            rSequence_getBUFFER( seq,
                                 RP_TAGS_SIGNATURE,
                                 &tmpSig,
                                 &tmpSigSize ) &&
            CRYPTOLIB_SIGNATURE_SIZE <= tmpSigSize )
        {
            // We got the data, now verify the buffer signature
            if( CryptoLib_verify( tmpBuff, tmpSize, getRootPublicKey(), tmpSig ) )
            {
                // Ready to load the module
                rpal_debug_info( "loading module in memory" );
                hcpContext->modules[ moduleIndex ].hModule = MemoryLoadLibrary( tmpBuff, tmpSize );

                if( NULL != hcpContext->modules[ moduleIndex ].hModule )
                {
                    OBFUSCATIONLIB_TOGGLE( entryName );

                    pEntry = (rpal_thread_func)MemoryGetProcAddress( hcpContext->modules[ moduleIndex ].hModule,
                                                            (RPCHAR)entryName );

                    OBFUSCATIONLIB_TOGGLE( entryName );

                    if( NULL != pEntry )
                    {
                        modContext = &(hcpContext->modules[ moduleIndex ].context);

                        modContext->pCurrentId = &( hcpContext->currentId );
                        modContext->func_sendHome = doSend;
                        modContext->isTimeToStop = rEvent_create( TRUE );
                        modContext->rpalContext = rpal_Context_get();
                        modContext->isOnlineEvent = hcpContext->isCloudOnline;

                        if( NULL != modContext->isTimeToStop )
                        {
                            hcpContext->modules[ moduleIndex ].isTimeToStop = modContext->isTimeToStop;

                            OBFUSCATIONLIB_TOGGLE( recvMessage );
                            hcpContext->modules[ moduleIndex ].func_recvMessage =
                                    (rpHCPModuleMsgEntry)MemoryGetProcAddress( hcpContext->modules[ moduleIndex ].hModule,
                                                                               (RPCHAR)recvMessage );
                            OBFUSCATIONLIB_TOGGLE( recvMessage );

                            hcpContext->modules[ moduleIndex ].hThread = rpal_thread_new( pEntry, modContext );

                            if( 0 != hcpContext->modules[ moduleIndex ].hThread )
                            {
                                CryptoLib_hash( tmpBuff, tmpSize, &(hcpContext->modules[ moduleIndex ].hash ) );
                                hcpContext->modules[ moduleIndex ].isOsLoaded = FALSE;
                                isSuccess = TRUE;
                            }
                            else
                            {
                                rpal_debug_warning( "Error creating handler thread for new module." );
                            }
                        }
                    }
                    else
                    {
                        rpal_debug_warning( "Could not find new module's entry point." );
                    }
                }
                else
                {
                    rpal_debug_warning( "Error loading module in memory." );
                }
            }
            else
            {
                rpal_debug_warning( "New module signature invalid." );
            }
        }
        else
        {
            rpal_debug_warning( "Could not find core module components to load." );
        }

        // Main cleanup
        if( !isSuccess )
        {
            if( NULL != modContext )
            {
                IF_VALID_DO( modContext->isTimeToStop, rEvent_free );
            }

            if( NULL != hcpContext->modules[ moduleIndex ].hModule )
            {
                MemoryFreeLibrary( hcpContext->modules[ moduleIndex ].hModule );
            }

            rpal_memory_zero( &(hcpContext->modules[ moduleIndex ] ),
                              sizeof( hcpContext->modules[ moduleIndex ] ) );
        }
    }
    else
    {
        rpal_debug_error( "Could not find a spot for new module, or invalid module id!" );
    }

    return isSuccess;
}


RPRIVATE_TESTABLE
RBOOL 
    unloadModule
    (
        rpHCPContext* hcpContext,
        rSequence seq
    )
{
    RBOOL isSuccess = FALSE;

    RpHcp_ModuleId moduleId = (RU8)(-1);
    RU32 moduleIndex = (RU32)(-1);

    if( NULL != seq &&
        NULL != hcpContext )
    {
        if( rSequence_getRU8( seq, 
                              RP_TAGS_HCP_MODULE_ID, 
                              &moduleId ) )
        {
            for( moduleIndex = 0; moduleIndex < RP_HCP_CONTEXT_MAX_MODULES; moduleIndex++ )
            {
                if( moduleId == hcpContext->modules[ moduleIndex ].id )
                {
                    break;
                }
            }
        }
    }

    if( (RU32)(-1) != moduleIndex &&
        RP_HCP_CONTEXT_MAX_MODULES != moduleIndex )
    {
#ifdef RP_HCP_LOCAL_LOAD
        if( hcpContext->modules[ moduleIndex ].isOsLoaded )
        {
            // We do not unload modules loaded by the OS in debug since
            // they are used to debug modules during development.
            return FALSE;
        }
#endif
        if( rEvent_set( hcpContext->modules[ moduleIndex ].isTimeToStop ) &&
            rpal_thread_wait( hcpContext->modules[ moduleIndex ].hThread, ( 30 * 1000 ) ) )
        {
            isSuccess = TRUE;

            _cleanupModuleEntry( &( hcpContext->modules[ moduleIndex ] ) );
        }
    }

    return isSuccess;
}


RPRIVATE_TESTABLE
RBOOL
    saveHcpId
    (
        RPNCHAR storePath,
        rpHCPIdentStore* ident,
        RPU8 token,
        RU32 tokenSize
    )
{
    RBOOL isSet = FALSE;
    rFile hStore = NULL;

    if( NULL != storePath &&
        NULL != ident &&
        NULL != token &&
        0 != tokenSize )
    {
        ident->enrollmentTokenSize = tokenSize;

        if( rFile_open( storePath, &hStore, RPAL_FILE_OPEN_ALWAYS | RPAL_FILE_OPEN_WRITE ) )
        {
            if( rFile_write( hStore, sizeof( *ident ), ident ) &&
                rFile_write( hStore, tokenSize, token ) )
            {
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                chmod( storePath, S_IRUSR | S_IWUSR );
#endif
                isSet = TRUE;
            }

            rFile_close( hStore );
    }
        else
        {
            rpal_debug_warning( "could not write enrollment token to disk" );
        }
    }
    else
    {
        rpal_debug_error( "invalid ident info" );
    }

    return isSet;
}


RBOOL
    processMessage
    (
        rSequence seq
    )
{
    RBOOL isSuccess = FALSE;
    RU8 command = 0;
    rSequence idSeq = NULL;
    rpHCPId tmpId = { 0 };
    rpHCPId emptyId = { 0 };
    RU64 tmpTime = 0;
    rThread hQuitThread = 0;

    rpHCPIdentStore identStore = {0};
    RPU8 token = NULL;
    RU32 tokenSize = 0;

    OBFUSCATIONLIB_DECLARE( store, RP_HCP_CONFIG_IDENT_STORE );

    if( NULL != seq )
    {
        if( rSequence_getRU8( seq, RP_TAGS_OPERATION, &command ) )
        {
            rpal_debug_info( "Received command 0x%0X.", command );
            switch( command )
            {
            case RP_HCP_COMMAND_LOAD_MODULE:
                isSuccess = loadModule( &g_hcpContext, seq );
                break;
            case RP_HCP_COMMAND_UNLOAD_MODULE:
                isSuccess = unloadModule( &g_hcpContext, seq );
                break;
            case RP_HCP_COMMAND_SET_HCP_ID:
                if( rSequence_getSEQUENCE( seq, RP_TAGS_HCP_IDENT, &idSeq ) )
                {
                    tmpId = seqToHcpId( idSeq );

                    if( 0 != rpal_memory_memcmp( &emptyId, &tmpId, sizeof( emptyId ) ) )
                    {
                        g_hcpContext.currentId = tmpId;
                        
                        OBFUSCATIONLIB_TOGGLE( store );
                        
                        if( rSequence_getBUFFER( seq, RP_TAGS_HCP_ENROLLMENT_TOKEN, &token, &tokenSize ) )
                        {
                            identStore.agentId = tmpId;

                            if( saveHcpId( (RPNCHAR)store, &identStore, token, tokenSize ) )
                            {
                                isSuccess = TRUE;
                            }

                            if( NULL != g_hcpContext.enrollmentToken )
                            {
                                rpal_memory_free( g_hcpContext.enrollmentToken );
                                g_hcpContext.enrollmentToken = NULL;
                            }

                            if( NULL != ( g_hcpContext.enrollmentToken = rpal_memory_alloc( tokenSize ) ) )
                            {
                                rpal_memory_memcpy( g_hcpContext.enrollmentToken, token, tokenSize );
                                g_hcpContext.enrollmentTokenSize = tokenSize;

                                isSuccess = TRUE;
                            }
                        }
                        else
                        {
                            rpal_debug_warning( "hcp id is missing token" );
                        }

                        OBFUSCATIONLIB_TOGGLE( store );
                    }
                }
                break;
            case RP_HCP_COMMAND_SET_GLOBAL_TIME:
                if( rSequence_getTIMESTAMP( seq, RP_TAGS_TIMESTAMP, &tmpTime ) )
                {
                    rpal_time_setGlobalOffset( tmpTime - rpal_time_getLocal() );
                    isSuccess = TRUE;
                }
                break;
            case RP_HCP_COMMAND_QUIT:
                if( 0 != ( hQuitThread = rpal_thread_new( thread_quitAndCleanup, NULL ) ) )
                {
                    rpal_thread_free( hQuitThread );
                    isSuccess = TRUE;
                }
                break;
            default:
                break;
            }

            if( isSuccess )
            {
                rpal_debug_info( "Command was successful." );
            }
            else
            {
                rpal_debug_warning( "Command was not successful." );
            }
        }
    }

    return isSuccess;
}

RBOOL
    stopAllModules
    (

    )
{
    RBOOL isSuccess = TRUE;

    RU32 moduleIndex = 0;

    for( moduleIndex = 0; moduleIndex < RP_HCP_CONTEXT_MAX_MODULES; moduleIndex++ )
    {
        rpal_debug_info( "stopping module at %d", moduleIndex );

        if( 0 != g_hcpContext.modules[ moduleIndex ].hThread )
        {
            if( rEvent_set( g_hcpContext.modules[ moduleIndex ].isTimeToStop ) &&
                rpal_thread_wait( g_hcpContext.modules[ moduleIndex ].hThread, RP_HCP_CONTEXT_MODULE_TIMEOUT ) )
            {
                _cleanupModuleEntry( &( g_hcpContext.modules[ moduleIndex ] ) );

                rpal_debug_info( "finished stopping module." );
            }
            else
            {
                isSuccess = FALSE;
            }
        }
    }

    rpal_debug_info( "finished stopping all modules" );

    return isSuccess;
}


