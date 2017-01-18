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

#include "beacon.h"
#include "configurations.h"
#include "globalContext.h"
#include "obfuscated.h"
#include <obfuscationLib/obfuscationLib.h>
#include <zlib/zlib.h>
#include <cryptoLib/cryptoLib.h>
#include "crypto.h"
#include <rpHostCommonPlatformLib/rTags.h>
#include <libOs/libOs.h>
#include "commands.h"
#include "crashHandling.h"
#include <networkLib/networkLib.h>
#include "git_info.h"

#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
#include <dlfcn.h>
#endif

#define RPAL_FILE_ID     50

//=============================================================================
//  Private defines and datastructures
//=============================================================================
#define FRAME_MAX_SIZE  (1024 * 1024 * 50)
#define CLOUD_SYNC_TIMEOUT  (MSEC_FROM_SEC(60 * 10))

//=============================================================================
//  Helpers
//=============================================================================
RPRIVATE
rBlob
    wrapFrame
    (
        RpHcp_ModuleId moduleId,
        rList messages
    )
{
    rBlob blob = NULL;
    RPU8 buffer = NULL;
    RSIZET size = 0;

    if( NULL != messages &&
        NULL != ( blob = rpal_blob_create( 0, 0 ) ) )
    {
        if( !rpal_blob_add( blob, &moduleId, sizeof( moduleId ) ) ||
            !rList_serialise( messages, blob ) )
        {
            rpal_blob_free( blob );
            blob = NULL;
        }
        else
        {
            size = compressBound( rpal_blob_getSize( blob ) );
            if( NULL == ( buffer = rpal_memory_alloc( size ) ) ||
                Z_OK != compress( buffer, 
                                  (uLongf*)&size, 
                                  rpal_blob_getBuffer( blob ), 
                                  rpal_blob_getSize( blob ) ) ||
              !rpal_blob_freeBufferOnly( blob ) ||
              !rpal_blob_setBuffer( blob, buffer, (RU32)size ) )
            {
                rpal_memory_free( buffer );
                rpal_blob_free( blob );
                buffer = NULL;
                blob = NULL;
            }
        }
    }

    return blob;
}

RPRIVATE
RBOOL
    sendFrame
    (
        RpHcp_ModuleId moduleId,
        rList messages
    )
{
    RBOOL isSent = FALSE;
    rBlob buffer = NULL;
    RU32 frameSize = 0;

    if( NULL != messages )
    {
        if( NULL != ( buffer = wrapFrame( moduleId, messages ) ) )
        {
            if( CryptoLib_symEncrypt( buffer,
                                      NULL, 
                                      NULL,
                                      g_hcpContext.session.symSendCtx ) &&
                0 != ( frameSize = rpal_blob_getSize( buffer ) ) &&
                0 != ( frameSize = rpal_hton32( frameSize ) ) &&
                rpal_blob_insert( buffer, &frameSize, sizeof( frameSize ), 0 ) )
            {
                if( NetLib_TcpSend( g_hcpContext.cloudConnection, 
                                    rpal_blob_getBuffer( buffer ), 
                                    rpal_blob_getSize( buffer ), 
                                    g_hcpContext.isBeaconTimeToStop ) )
                {
                    isSent = TRUE;
                }
            }

            rpal_blob_free( buffer );
        }
    }

    return isSent;
}

RPRIVATE
RBOOL
    recvFrame
    (
        RpHcp_ModuleId* targetModuleId,
        rList* pMessages,
        RU32 timeoutSec
    )
{
    RBOOL isSuccess = FALSE;
    RU32 frameSize = 0;
    rBlob frame = NULL;
    RPU8 uncompressedFrame = NULL;
    RSIZET uncompressedSize = 0;
    RU32 uncompErr = 0;
    RU32 bytesConsumed = 0;

    if( NULL != targetModuleId &&
        NULL != pMessages )
    {
        if( NetLib_TcpReceive( g_hcpContext.cloudConnection, 
                               &frameSize, 
                               sizeof( frameSize ), 
                               g_hcpContext.isBeaconTimeToStop,
                               timeoutSec ) )
        {
            frameSize = rpal_ntoh32( frameSize );
            if( FRAME_MAX_SIZE >= frameSize &&
                NULL != ( frame = rpal_blob_create( frameSize, 0 ) ) &&
                rpal_blob_add( frame, NULL, frameSize ) )
            {
                if( NetLib_TcpReceive( g_hcpContext.cloudConnection,
                                       rpal_blob_getBuffer( frame ),
                                       rpal_blob_getSize( frame ),
                                       g_hcpContext.isBeaconTimeToStop,
                                       timeoutSec ) )
                {
                    if( CryptoLib_symDecrypt( frame, NULL, NULL, g_hcpContext.session.symRecvCtx ) &&
                        NULL != rpal_blob_getBuffer( frame ) )
                    {
                        uncompressedSize = rpal_ntoh32( *(RU32*)rpal_blob_getBuffer( frame ) );
                        if( FRAME_MAX_SIZE >= uncompressedSize &&
                            NULL != ( uncompressedFrame = rpal_memory_alloc( uncompressedSize ) ) )
                        {
                            if( Z_OK == ( uncompErr = uncompress( uncompressedFrame,
                                                                  (uLongf*)&uncompressedSize,
                                                                  (RPU8)(rpal_blob_getBuffer( frame )) + sizeof(RU32),
                                                                  rpal_blob_getSize( frame ) ) ) )
                            {
                                *targetModuleId = *(RpHcp_ModuleId*)uncompressedFrame;

                                if( rList_deserialise( pMessages, 
                                                       uncompressedFrame + sizeof( RpHcp_ModuleId ), 
                                                       (RU32)uncompressedSize, 
                                                       &bytesConsumed ) )
                                {
                                    if( bytesConsumed + sizeof( RpHcp_ModuleId ) == uncompressedSize )
                                    {
                                        isSuccess = TRUE;
                                    }
                                    else
                                    {
                                        rpal_debug_warning( "deserialization buffer size mismatch" );
                                        rList_free( *pMessages );
                                        *pMessages = NULL;
                                    }
                                }
                                else
                                {
                                    rpal_debug_warning( "failed to deserialize frame" );
                                }
                            }
                            else
                            {
                                rpal_debug_warning( "failed to decompress frame: %d", uncompErr );
                            }

                            rpal_memory_free( uncompressedFrame );
                        }
                        else
                        {
                            rpal_debug_warning( "invalid decompressed size %d", uncompressedSize );
                        }
                    }
                    else
                    {
                        rpal_debug_warning( "failed to decrypt frame" );
                    }
                }
                else
                {
                    rpal_debug_warning( "failed to receive frame %d bytes", rpal_blob_getSize( frame ) );
                }

                rpal_blob_free( frame );
            }
            else
            {
                rpal_debug_warning( "frame size invalid" );
            }
        }
        else
        {
            rpal_debug_warning( "failed to get frame size" );
        }
    }

    return isSuccess;
}

RPRIVATE
rSequence
    generateHeaders
    (

    )
{
    rList wrapper = NULL;
    rSequence headers = NULL;
    rSequence hcpId = NULL;
    RPCHAR hostName = NULL;

    RPU8 crashContext = NULL;
    RU32 crashContextSize = 0;
    RU8 defaultCrashContext = 1;

    if( NULL != ( wrapper = rList_new( RP_TAGS_MESSAGE, RPCM_SEQUENCE ) ) )
    {
        if( NULL != ( headers = rSequence_new() ) )
        {
            if( rList_addSEQUENCE( wrapper, headers ) )
            {
                // First let's check if we have a crash context already present
                // which would indicate we did not shut down properly
                if( !acquireCrashContextPresent( &crashContext, &crashContextSize ) )
                {
                    crashContext = NULL;
                    crashContextSize = 0;
                }
                else
                {
                    rSequence_addBUFFER( headers, RP_TAGS_HCP_CRASH_CONTEXT, crashContext, crashContextSize );
                    rpal_memory_free( crashContext );
                    crashContext = NULL;
                    crashContextSize = 0;
                }

                // Set a default crashContext to be removed before exiting
                setCrashContext( &defaultCrashContext, sizeof( defaultCrashContext ) );

                // This is our identity
                if( NULL != ( hcpId = hcpIdToSeq( g_hcpContext.currentId ) ) )
                {
                    if( !rSequence_addSEQUENCE( headers, RP_TAGS_HCP_IDENT, hcpId ) )
                    {
                        rSequence_free( hcpId );
                    }
                }

                // The current host name
                if( NULL != ( hostName = libOs_getHostName() ) )
                {
                    rSequence_addSTRINGA( headers, RP_TAGS_HOST_NAME, hostName );
                    rpal_memory_free( hostName );
                }

                // Current internal IP address
                rSequence_addIPV4( headers, RP_TAGS_IP_ADDRESS, libOs_getMainIp() );

                // Enrollment token as received during enrollment
                if( NULL != g_hcpContext.enrollmentToken &&
                    0 != g_hcpContext.enrollmentTokenSize )
                {
                    rSequence_addBUFFER( headers,
                        RP_TAGS_HCP_ENROLLMENT_TOKEN,
                        g_hcpContext.enrollmentToken,
                        g_hcpContext.enrollmentTokenSize );
                }

                // The current version running.
                rSequence_addRU32( headers, RP_TAGS_PACKAGE_VERSION, GIT_REVISION );

                // Deployment key as set in installer
                if( NULL != g_hcpContext.deploymentKey )
                {
                    rSequence_addSTRINGA( headers, RP_TAGS_HCP_DEPLOYMENT_KEY, g_hcpContext.deploymentKey );
                }
            }
            else
            {
                rSequence_free( headers );
                rList_free( wrapper );
                wrapper = NULL;
            }
        }
        else
        {
            rList_free( wrapper );
            wrapper = NULL;
        }
    }

    return wrapper;
}

//=============================================================================
//  Base beacon
//=============================================================================
RPRIVATE
RU32
    RPAL_THREAD_FUNC thread_sync
    (
        RPVOID context
    )
{
    rList wrapper = NULL;
    rSequence message = NULL;
    rList modList = NULL;
    rSequence modEntry = NULL;
    RU32 moduleIndex = 0;

    RU32 timeout = MSEC_FROM_SEC( 30 );

    UNREFERENCED_PARAMETER( context );

    // Blanket wait initially to give it a chance to connect.
    rEvent_wait( g_hcpContext.isCloudOnline, MSEC_FROM_SEC( 5 ) );

    do
    {
        if( !rEvent_wait( g_hcpContext.isCloudOnline, 0 ) )
        {
            // Not online, no need to try.
            continue;
        }

        rpal_debug_info( "Currently online, sync." );

        if( NULL != ( wrapper = rList_new( RP_TAGS_MESSAGE, RPCM_SEQUENCE ) ) )
        {
            if( NULL != ( message = rSequence_new() ) )
            {
                // Add some basic info
                rSequence_addRU32( message, RP_TAGS_MEMORY_USAGE, rpal_memory_totalUsed() );
                rSequence_addTIMESTAMP( message, RP_TAGS_TIMESTAMP, rpal_time_getGlobal() );

                if( NULL != ( modList = rList_new( RP_TAGS_HCP_MODULE, RPCM_SEQUENCE ) ) )
                {
                    for( moduleIndex = 0; moduleIndex < RP_HCP_CONTEXT_MAX_MODULES; moduleIndex++ )
                    {
                        if( NULL != g_hcpContext.modules[ moduleIndex ].hModule )
                        {
                            if( NULL != ( modEntry = rSequence_new() ) )
                            {
                                if( !rSequence_addBUFFER( modEntry,
                                                          RP_TAGS_HASH,
                                                          (RPU8)&( g_hcpContext.modules[ moduleIndex ].hash ),
                                                          sizeof( g_hcpContext.modules[ moduleIndex ].hash ) ) ||
                                    !rSequence_addRU8( modEntry,
                                                       RP_TAGS_HCP_MODULE_ID,
                                                       g_hcpContext.modules[ moduleIndex ].id ) ||
                                    !rList_addSEQUENCE( modList, modEntry ) )
                                {
                                    break;
                                }

                                // We take the opportunity to cleanup the list of modules...
                                if( rpal_thread_wait( g_hcpContext.modules[ moduleIndex ].hThread, 0 ) )
                                {
                                    // This thread has exited, which is our signal that the module
                                    // has stopped executing...
                                    rEvent_free( g_hcpContext.modules[ moduleIndex ].isTimeToStop );
                                    rpal_thread_free( g_hcpContext.modules[ moduleIndex ].hThread );
                                    if( g_hcpContext.modules[ moduleIndex ].isOsLoaded )
                                    {
#ifdef RPAL_PLATFORM_WINDOWS
                                        FreeLibrary( (HMODULE)( g_hcpContext.modules[ moduleIndex ].hModule ) );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                                        dlclose( g_hcpContext.modules[ moduleIndex ].hModule );
#endif
                                    }
                                    else
                                    {
                                        MemoryFreeLibrary( g_hcpContext.modules[ moduleIndex ].hModule );
                                    }
                                    rpal_memory_zero( &( g_hcpContext.modules[ moduleIndex ] ),
                                                      sizeof( g_hcpContext.modules[ moduleIndex ] ) );

                                    if( !rSequence_addRU8( modEntry, RP_TAGS_HCP_MODULE_TERMINATED, 1 ) )
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if( !rSequence_addLIST( message, RP_TAGS_HCP_MODULES, modList ) )
                    {
                        rList_free( modList );
                    }
                }

                if( !rList_addSEQUENCE( wrapper, message ) )
                {
                    rSequence_free( message );
                }
            }

            if( doSend( RP_HCP_MODULE_ID_HCP, wrapper ) )
            {
                // On successful sync, wait full period before another sync.
                timeout = CLOUD_SYNC_TIMEOUT;
            }
            else
            {
                rpal_debug_warning( "sending sync failed, we may be offline" );
            }

            rList_free( wrapper );
        }
    } while( !rEvent_wait( g_hcpContext.isBeaconTimeToStop, timeout ) );

    // We attempt to close the connection quickly, so either
    // the beaconing thread gets to it first or we do.
    rEvent_unset( g_hcpContext.isCloudOnline );

    if( rMutex_lock( g_hcpContext.cloudConnectionMutex ) )
    {
        if( 0 != g_hcpContext.cloudConnection )
        {
            NetLib_TcpDisconnect( g_hcpContext.cloudConnection );
            g_hcpContext.cloudConnection = 0;
        }
        rMutex_unlock( g_hcpContext.cloudConnectionMutex );
    }

    return 0;
}

RPRIVATE
RU32
    RPAL_THREAD_FUNC thread_conn
    (
        RPVOID context
    )
{
    OBFUSCATIONLIB_DECLARE( url1, RP_HCP_CONFIG_HOME_URL_PRIMARY );
    OBFUSCATIONLIB_DECLARE( url2, RP_HCP_CONFIG_HOME_URL_SECONDARY );

    RPCHAR effectivePrimary = (RPCHAR)url1;
    RU16 effectivePrimaryPort = RP_HCP_CONFIG_HOME_PORT_PRIMARY;
    RPCHAR effectiveSecondary = (RPCHAR)url2;
    RU16 effectiveSecondaryPort = RP_HCP_CONFIG_HOME_PORT_SECONDARY;
    RPCHAR currentDest = NULL;
    RU16 currentPort = 0;
    rThread syncThread = NULL;
    
    UNREFERENCED_PARAMETER( context );

    // Now load the various possible destinations
    if( NULL != g_hcpContext.primaryUrl )
    {
        effectivePrimary = g_hcpContext.primaryUrl;
        effectivePrimaryPort = g_hcpContext.primaryPort;
    }
    else
    {
        OBFUSCATIONLIB_TOGGLE( url1 );
    }
    if( NULL != g_hcpContext.secondaryUrl )
    {
        effectiveSecondary = g_hcpContext.secondaryUrl;
        effectiveSecondaryPort = g_hcpContext.secondaryPort;
    }
    else
    {
        OBFUSCATIONLIB_TOGGLE( url2 );
    }

    currentDest = effectivePrimary;
    currentPort = effectivePrimaryPort;

    if( NULL == ( syncThread = rpal_thread_new( thread_sync, NULL ) ) )
    {
        rpal_debug_error( "could not start sync thread" );
        return 0;
    }
    
    while( !rEvent_wait( g_hcpContext.isBeaconTimeToStop, 0 ) )
    {
        rMutex_lock( g_hcpContext.cloudConnectionMutex );

        if( 0 != ( g_hcpContext.cloudConnection = NetLib_TcpConnect( currentDest, currentPort ) ) )
        {
            RBOOL isHandshakeComplete = FALSE;
            RBOOL isHeadersSent = FALSE;
            RU8 key[ CRYPTOLIB_ASYM_2048_MIN_SIZE ] = { 0 };
            RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ] = { 0 };

            rpal_debug_info( "cloud connected" );

            // Handshake and establish secure channel.
            // Generate the session keys
            if( CryptoLib_genRandomBytes( key,
                                          CRYPTOLIB_SYM_KEY_SIZE ) &&
                CryptoLib_genRandomBytes( iv,
                                          sizeof( iv ) ) )
            {
                RPU8 handshake = NULL;
                RU32 encryptedSize = 0;
                if( CryptoLib_asymEncrypt( key,
                                           CRYPTOLIB_SYM_KEY_SIZE,
                                           getC2PublicKey(),
                                           &handshake,
                                           &encryptedSize ) )
                {
                    if( NULL != ( handshake = rpal_memory_reAlloc( handshake, encryptedSize + sizeof( iv ) ) ) )
                    {
                        rpal_memory_memcpy( handshake + encryptedSize, iv, sizeof( iv ) );
                        encryptedSize += sizeof( iv );

                        isHandshakeComplete = NetLib_TcpSend( g_hcpContext.cloudConnection,
                                                              handshake,
                                                              encryptedSize,
                                                              g_hcpContext.isBeaconTimeToStop );

                        if( isHandshakeComplete )
                        {
                            rpal_debug_info( "handshake sent" );
                            // Initialze the session symetric crypto
                            if( NULL != ( g_hcpContext.session.symSendCtx = CryptoLib_symEncInitContext( key, iv ) ) &&
                                NULL != ( g_hcpContext.session.symRecvCtx = CryptoLib_symDecInitContext( key, iv ) ) )
                            {
                                RPU8 handshakeResponse = NULL;
                                RU32 handshakeResponseSize = 0;
                                RpHcp_ModuleId tmpModuleId = 0;
                                rList messages = NULL;
                                rSequence message = NULL;

                                // The handshake response is supposed to be a single message
                                // that contains a buffer with whatever was sent initially.
                                isHandshakeComplete = recvFrame( &tmpModuleId, &messages, 5 );

                                if( isHandshakeComplete )
                                {
                                    if( !rList_getSEQUENCE( messages, RP_TAGS_MESSAGE, &message ) ||
                                        !rSequence_getBUFFER( message,
                                                              RP_TAGS_BINARY,
                                                              &handshakeResponse,
                                                              &handshakeResponseSize ) ||
                                        handshakeResponseSize != encryptedSize ||
                                        0 != rpal_memory_memcmp( handshakeResponse,
                                                                 handshake,
                                                                 handshakeResponseSize ) )
                                    {
                                        isHandshakeComplete = FALSE;
                                    }

                                    rList_free( messages );
                                }
                            }
                        }

                        rpal_memory_free( handshake );
                    }
                }
            }

            if( isHandshakeComplete )
            {
                // Send the headers
                rSequence headers = generateHeaders();
                rpal_debug_info( "handshake received" );
                if( NULL != headers )
                {
                    if( sendFrame( RP_HCP_MODULE_ID_HCP, headers ) )
                    {
                        rpal_debug_info( "headers sent" );
                        isHeadersSent = TRUE;
                    }

                    rSequence_free( headers );
                }
            }
            else
            {
                rpal_debug_warning( "failed to handshake" );
            }

            if( !isHeadersSent )
            {
                rpal_debug_warning( "failed to send headers" );

                // Clean up all crypto primitives
                CryptoLib_symFreeContext( g_hcpContext.session.symSendCtx );
                g_hcpContext.session.symSendCtx = NULL;
                CryptoLib_symFreeContext( g_hcpContext.session.symRecvCtx );
                g_hcpContext.session.symRecvCtx = NULL;

                // We failed to truly establish the connection so we'll reset.
                NetLib_TcpDisconnect( g_hcpContext.cloudConnection );
                g_hcpContext.cloudConnection = 0;
            }

            rMutex_unlock( g_hcpContext.cloudConnectionMutex );

            if( 0 != g_hcpContext.cloudConnection )
            {
                // Notify the modules of the connect.
                RU32 moduleIndex = 0;
                rpal_debug_info( "comms channel up with the cloud" );

                // Secure channel is up and running, start receiving messages.
                rEvent_set( g_hcpContext.isCloudOnline );

                do
                {
                    rList messages = NULL;
                    rSequence message = NULL;
                    RpHcp_ModuleId targetModuleId = 0;

                    if( !recvFrame( &targetModuleId, &messages, 0 ) )
                    {
                        rpal_debug_warning( "error receiving frame" );
                        break;
                    }

                    // HCP is not a module so check manually
                    if( RP_HCP_MODULE_ID_HCP == targetModuleId )
                    {
                        while( rList_getSEQUENCE( messages, RP_TAGS_MESSAGE, &message ) )
                        {
                            processMessage( message );
                        }
                    }
                    else
                    {
                        // Look for the module this message is destined to
                        for( moduleIndex = 0; moduleIndex < ARRAY_N_ELEM( g_hcpContext.modules ); moduleIndex++ )
                        {
                            if( targetModuleId == g_hcpContext.modules[ moduleIndex ].id )
                            {
                                if( NULL != g_hcpContext.modules[ moduleIndex ].func_recvMessage )
                                {
                                    while( rList_getSEQUENCE( messages, RP_TAGS_MESSAGE, &message ) )
                                    {
                                        g_hcpContext.modules[ moduleIndex ].func_recvMessage( message );
                                    }
                                }

                                break;
                            }
                        }
                    }

                    rList_free( messages );
                } while( !rEvent_wait( g_hcpContext.isBeaconTimeToStop, 0 ) );

                rEvent_unset( g_hcpContext.isCloudOnline );

                if( rMutex_lock( g_hcpContext.cloudConnectionMutex ) )
                {
                    if( 0 != g_hcpContext.cloudConnection )
                    {
                        NetLib_TcpDisconnect( g_hcpContext.cloudConnection );
                        g_hcpContext.cloudConnection = 0;
                    }
                    rMutex_unlock( g_hcpContext.cloudConnectionMutex );
                }

                rpal_debug_info( "comms with cloud down" );
            }
        }
        else
        {
            rMutex_unlock( g_hcpContext.cloudConnectionMutex );
        }

        // Clean up all crypto primitives
        CryptoLib_symFreeContext( g_hcpContext.session.symSendCtx );
        g_hcpContext.session.symSendCtx = NULL;
        CryptoLib_symFreeContext( g_hcpContext.session.symRecvCtx );
        g_hcpContext.session.symRecvCtx = NULL;

        rEvent_wait( g_hcpContext.isBeaconTimeToStop, MSEC_FROM_SEC( 10 ) );
        rpal_debug_warning( "failed connecting, cycling destination" );
        if( currentDest == effectivePrimary )
        {
            currentDest = effectiveSecondary;
            currentPort = effectiveSecondaryPort;
        }
        else
        {
            currentDest = effectivePrimary;
            currentPort = effectivePrimaryPort;
        }
    }

    rpal_thread_wait( syncThread, MSEC_FROM_SEC( 10 ) );
    rpal_thread_free( syncThread );

    return 0;
}

//=============================================================================
//  API
//=============================================================================
RBOOL
    startBeacons
    (

    )
{
    RBOOL isSuccess = FALSE;

    g_hcpContext.isBeaconTimeToStop = rEvent_create( TRUE );

    if( NULL != g_hcpContext.isBeaconTimeToStop )
    {
        g_hcpContext.hBeaconThread = rpal_thread_new( thread_conn, NULL );

        if( 0 != g_hcpContext.hBeaconThread )
        {
            isSuccess = TRUE;
        }
        else
        {
            rEvent_free( g_hcpContext.isBeaconTimeToStop );
            g_hcpContext.isBeaconTimeToStop = NULL;
        }
    }

    return isSuccess;
}



RBOOL
    stopBeacons
    (

    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != g_hcpContext.isBeaconTimeToStop )
    {
        rEvent_set( g_hcpContext.isBeaconTimeToStop );

        if( 0 != g_hcpContext.hBeaconThread )
        {
            rpal_thread_wait( g_hcpContext.hBeaconThread, MSEC_FROM_SEC( 40 ) );
            rpal_thread_free( g_hcpContext.hBeaconThread );

            isSuccess = TRUE;
        }

        rEvent_free( g_hcpContext.isBeaconTimeToStop );
        g_hcpContext.isBeaconTimeToStop = NULL;
    }

    return isSuccess;
}

RBOOL
    doSend
    (
        RpHcp_ModuleId sourceModuleId,
        rList toSend
    )
{
    RBOOL isSuccess = FALSE;

    if( rMutex_lock( g_hcpContext.cloudConnectionMutex ) )
    {
        isSuccess = sendFrame( sourceModuleId, toSend );

        rMutex_unlock( g_hcpContext.cloudConnectionMutex );
    }

    return isSuccess;
}
