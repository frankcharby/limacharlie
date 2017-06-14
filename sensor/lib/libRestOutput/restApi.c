/*
Copyright 2017 Google, Inc

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

#define RPAL_FILE_ID 112

#include <rpal/rpal.h>
#include <libRestOutput/libRestOutput.h>

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#ifdef RPAL_PLATFORM_MACOSX
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

typedef struct
{
    rString headers;
    RPCHAR destUrl;
    RPCHAR destPort;
    RPCHAR destPage;

    struct
    {
        mbedtls_net_context server_fd;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt cacert;
    } tlsConnection;

} _restOutputContext;


RPRIVATE
RVOID
    _printMbedError
    (
        RS32 mbedRet
    )
{
#ifdef RPAL_PLATFORM_DEBUG
    RCHAR tmpError[ 512 ] = { 0 };
    mbedtls_strerror( mbedRet, tmpError, sizeof( tmpError ) );
    rpal_debug_error( "TLS Error %d: %s", mbedRet, tmpError );
#else
    rpal_debug_error( "TLS Error: %d", mbedRet );
#endif
}

RPRIVATE
RBOOL
    _loadOsCerts
    (
        restOutputContext pContext
    )
{
    RBOOL isSuccess = FALSE;
    _restOutputContext* ctx = pContext;
    RS32 mbedRet = 0;

    if( NULL != pContext )
    {
        mbedtls_x509_crt_init( &ctx->tlsConnection.cacert );

#ifdef RPAL_PLATFORM_WINDOWS
        {
            HCERTSTORE hCertStore = NULL;
            PCCERT_CONTEXT cert = NULL;
            if( NULL != ( hCertStore = CertOpenSystemStoreA( (HCRYPTPROV)NULL, "ROOT" ) ) )
            {
                isSuccess = TRUE;

                while( NULL != ( cert = CertEnumCertificatesInStore( hCertStore, cert ) ) )
                {
                    if( IS_FLAG_ENABLED( cert->dwCertEncodingType, X509_ASN_ENCODING ) )
                    {
                        if( 0 != ( mbedRet = mbedtls_x509_crt_parse( &ctx->tlsConnection.cacert,
                                                                     cert->pbCertEncoded,
                                                                     cert->cbCertEncoded ) ) )
                        {
                            _printMbedError( mbedRet );
                        }
                    }
                }

                CertCloseStore( hCertStore, 0 );
            }
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        {
            OSStatus err = 0;
            RU32 i = 0;
            RU32 nCerts = 0;
            CFArrayRef certs = NULL;
            SecCertificateRef cert = NULL;
            CFDataRef data = NULL;

            if( noErr == ( err = SecTrustCopyAnchorCertificates( &certs ) ) )
            {
                isSuccess = TRUE;

                nCerts = CFArrayGetCount( certs );

                for( i = 0; i < nCerts; i++ )
                {
                    if( NULL != ( cert = (SecCertificateRef)CFArrayGetValueAtIndex( certs, i ) ) )
                    {
                        if( noErr == ( err = SecItemExport( cert, kSecFormatX509Cert, 0, NULL, &data ) ) )
                        {
                            if( 0 != ( mbedRet = mbedtls_x509_crt_parse( &ctx->tlsConnection.cacert,
                                                                         CFDataGetBytePtr( data ),
                                                                         CFDataGetLength( data ) ) ) )
                            {
                                _printMbedError( mbedRet );
                            }
                            
                            CFRelease( data );
                        }
                    }
                }

                CFRelease( certs );
            }
        }
#endif
    }

    return isSuccess;
}


restOutputContext
    restOutput_newContext
    (
        RPCHAR destUrl,
        RPCHAR apiKeyHeader
    )
{
    _restOutputContext* ctx = NULL;
    RS32 mbedRet = 0;
    RBOOL isSuccess = FALSE;

    if( NULL != ( ctx = rpal_memory_alloc( sizeof( _restOutputContext ) ) ) )
    {
        isSuccess = TRUE;

        mbedtls_x509_crt_init( &ctx->tlsConnection.cacert );
        mbedtls_ctr_drbg_init( &ctx->tlsConnection.ctr_drbg );
        mbedtls_entropy_init( &ctx->tlsConnection.entropy );

        if( 0 != ( mbedRet = mbedtls_ctr_drbg_seed( &ctx->tlsConnection.ctr_drbg,
                                                    mbedtls_entropy_func,
                                                    &ctx->tlsConnection.entropy,
                                                    NULL,
                                                    0 ) ) ||
            !_loadOsCerts( ctx ) )
        {
            if( 0 != mbedRet )
            {
                _printMbedError( mbedRet );
            }
            isSuccess = FALSE;
        }
    }

    if( isSuccess )
    {
        ctx->destUrl = rpal_string_strdupA( destUrl );
        // Look for a / which represents the start of the target page.
        if( NULL != ( ctx->destPage = rpal_string_strstrA( ctx->destUrl, "/" ) ) )
        {
            *ctx->destPage = 0;
            ctx->destPage++;
        }
        else
        {
            ctx->destPage = "";
        }

        // Look for a : which represents the start of the port.
        if( NULL != ( ctx->destPort = rpal_string_strstrA( ctx->destUrl, ":" ) ) )
        {
            *ctx->destPort = 0;
            ctx->destPort++;
        }
        else
        {
            ctx->destPort = "443";
        }

        // All 3 components are required.
        if( NULL == ctx->destUrl || NULL == ctx->destPort || NULL == ctx->destPage )
        {
            mbedtls_x509_crt_free( &ctx->tlsConnection.cacert );
            mbedtls_ctr_drbg_free( &ctx->tlsConnection.ctr_drbg );
            mbedtls_entropy_free( &ctx->tlsConnection.entropy );

            rpal_memory_free( ctx->destUrl );
            rpal_memory_free( ctx );
            ctx = NULL;
        }
    }

    if( isSuccess )
    {
        RCHAR header_1[] = { "POST /" };
        RCHAR header_2[] = { " HTTP/1.0\nUser-Agent: lc-bulk\nContent-Type: application/json" };
        if( NULL == ( ctx->headers = rpal_stringbuffer_new( 0, 0 ) ) ||
            !rpal_stringbuffer_addA( ctx->headers, header_1 ) ||
            !rpal_stringbuffer_addA( ctx->headers, ctx->destPage ) ||
            !rpal_stringbuffer_addA( ctx->headers, header_2 ) ||
            ( NULL != apiKeyHeader &&
              ( !rpal_stringbuffer_addA( ctx->headers, "\n" ) ||
                !rpal_stringbuffer_addA( ctx->headers, apiKeyHeader ) ) ) )
        {
            // Something failed while assembling the header.
            isSuccess = FALSE;
        }
    }

    if( !isSuccess && NULL != ctx )
    {
        mbedtls_x509_crt_free( &ctx->tlsConnection.cacert );
        mbedtls_ctr_drbg_free( &ctx->tlsConnection.ctr_drbg );
        mbedtls_entropy_free( &ctx->tlsConnection.entropy );

        rpal_stringbuffer_free( ctx->headers );
        rpal_memory_free( ctx->destUrl );
        rpal_memory_free( ctx );
        ctx = NULL;
    }

    return (restOutputContext)ctx;
}

RVOID
    restOutput_freeContext
    (
        restOutputContext pContext
    )
{
    _restOutputContext* ctx = pContext;
    
    if( NULL != ctx )
    {
        rpal_stringbuffer_free( ctx->headers );
        rpal_memory_free( ctx->destUrl );

        mbedtls_x509_crt_free( &ctx->tlsConnection.cacert );
        mbedtls_ctr_drbg_free( &ctx->tlsConnection.ctr_drbg );
        mbedtls_entropy_free( &ctx->tlsConnection.entropy );

        rpal_memory_free( ctx );
    }
}

RPRIVATE
RBOOL
    _sendUntil
    (
        _restOutputContext* ctx,
        RPCHAR data,
        RTIME until
    )
{
    RBOOL isSuccess = FALSE;
    RU32 mbedRet = 0;
    RU32 offset = 0;
    RU32 toSend = 0;

    if( NULL != ctx &&
        NULL != data &&
        0 != ( toSend = rpal_string_strlenA( data ) ) )
    {

        do
        {
            mbedRet = 0;

            mbedRet = mbedtls_ssl_write( &ctx->tlsConnection.ssl, (RPU8)data + offset, toSend - offset );

            if( 0 < mbedRet )
            {
                offset += mbedRet;
                if( offset == toSend )
                {
                    isSuccess = TRUE;
                    break;
                }
            }
            else if( MBEDTLS_ERR_SSL_WANT_READ != mbedRet &&
                     MBEDTLS_ERR_SSL_WANT_WRITE != mbedRet )
            {
                _printMbedError( mbedRet );
                break;
            }

            rpal_thread_sleep( 100 );
        } while( rpal_time_getLocal() < until );
    }

    return isSuccess;
}

RBOOL
    restOutput_send
    (
        restOutputContext pContext,
        RPCHAR payload,
        RU32* pStatusCode,
        RU32 timeout
    )
{
    RBOOL isSuccess = FALSE;
    _restOutputContext* ctx = pContext;
    RS32 mbedRet = 0;
    RTIME endTime = rpal_time_getLocal() + timeout;
    RCHAR contentLenth[] = { "\nContent-Length: " };
    RCHAR tmpLength[ 16 ] = { 0 };
    RCHAR hdrTerminator[] = { "\n\n" };
    RU8 response[ 128 ] = { 0 };
    RU32 readOffset = 0;
    RCHAR expectedResponse[] = { "HTTP/1.0 " };
    RU64 tmpCode = 0;

    if( NULL != ctx )
    {
        mbedtls_net_init( &ctx->tlsConnection.server_fd );
        mbedtls_ssl_init( &ctx->tlsConnection.ssl );
        mbedtls_ssl_config_init( &ctx->tlsConnection.conf );

        if( 0 == ( mbedRet = mbedtls_net_connect( &ctx->tlsConnection.server_fd,
                                                  ctx->destUrl,
                                                  ctx->destPort,
                                                  MBEDTLS_NET_PROTO_TCP ) ) )
        {
            mbedtls_net_set_nonblock( &ctx->tlsConnection.server_fd );

            if( 0 == ( mbedRet = mbedtls_ssl_config_defaults( &ctx->tlsConnection.conf,
                                                              MBEDTLS_SSL_IS_CLIENT,
                                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                                              MBEDTLS_SSL_PRESET_DEFAULT ) ) )
            {
                mbedtls_ssl_conf_authmode( &ctx->tlsConnection.conf, MBEDTLS_SSL_VERIFY_REQUIRED );
                mbedtls_ssl_conf_ca_chain( &ctx->tlsConnection.conf, &ctx->tlsConnection.cacert, NULL );
                mbedtls_ssl_conf_rng( &ctx->tlsConnection.conf, mbedtls_ctr_drbg_random, &ctx->tlsConnection.ctr_drbg );

                if( 0 == ( mbedRet = mbedtls_ssl_setup( &ctx->tlsConnection.ssl, &ctx->tlsConnection.conf ) ) )
                {
                    mbedtls_ssl_set_bio( &ctx->tlsConnection.ssl,
                                         &ctx->tlsConnection.server_fd,
                                         mbedtls_net_send,
                                         mbedtls_net_recv,
                                         NULL );
                    while( 0 != ( mbedRet = mbedtls_ssl_handshake( &ctx->tlsConnection.ssl ) ) &&
                           rpal_time_getLocal() < endTime )
                    {
                        if( MBEDTLS_ERR_SSL_WANT_READ != mbedRet &&
                            MBEDTLS_ERR_SSL_WANT_WRITE != mbedRet )
                        {
                            _printMbedError( mbedRet );
                            break;
                        }

                        rpal_thread_sleep( 100 );
                    }

                    // Check if we timed out and were successful.
                    if( 0 == mbedRet &&
                        rpal_time_getLocal() <= endTime )
                    {
                        if( 0 == ( mbedRet = mbedtls_ssl_get_verify_result( &ctx->tlsConnection.ssl ) ) )
                        {
                            // Assemble the payload content length,
                            if( NULL != rpal_string_itosA( rpal_string_strlenA( payload ), tmpLength, 10 ) )
                            {
                                // Ok now we can send the payload.
                                // First we send the static header.
                                // Then we send the payload.
                                if( _sendUntil( ctx, rpal_stringbuffer_getStringA( ctx->headers ), endTime ) &&
                                    _sendUntil( ctx, contentLenth, endTime ) &&
                                    _sendUntil( ctx, tmpLength, endTime ) &&
                                    _sendUntil( ctx, hdrTerminator, endTime ) &&
                                    _sendUntil( ctx, payload, endTime ) )
                                {
                                    // The first 128 bytes will tell us what we need. We expect to get the status
                                    // from the first successful read.
                                    do
                                    {
                                        mbedRet = mbedtls_ssl_read( &ctx->tlsConnection.ssl, 
                                                                    response + readOffset, 
                                                                    sizeof( response ) - readOffset );

                                        if( 0 < mbedRet )
                                        {
                                            readOffset += mbedRet;
                                            break;
                                        }

                                        rpal_thread_sleep( 100 );
                                    } while( rpal_time_getLocal() < endTime );


                                    // Check to see if we got at least the bare minimum for a status code.
                                    if( sizeof( expectedResponse ) + 3 <= readOffset )
                                    {
                                        // At this point we consider the POST was a success.
                                        isSuccess = TRUE;

                                        // But it doesn't mean the server liked it, check to see what the status code was.
                                        // Terminate the status.
                                        response[ sizeof( expectedResponse ) + 3 ] = 0;
                                        // Conver the status to an int.
                                        if( !rpal_string_stoiA( (RPCHAR)( response + sizeof( expectedResponse ) - 1 ), &tmpCode ) )
                                        {
                                            tmpCode = 0;
                                        }

                                        if( NULL != pStatusCode )
                                        {
                                            *pStatusCode = (RU32)tmpCode;
                                        }
                                    }
                                    else
                                    {
                                        rpal_debug_warning( "could not find status code in response." );
                                    }
                                }
                                else
                                {
                                    rpal_debug_warning( "failure while sending payload." );
                                }
                            }
                        }
                        else
                        {
                            _printMbedError( mbedRet );
                        }
                    }
                    else if( 0 == mbedRet )
                    {
                        rpal_debug_warning( "timeout while sending." );
                    }
                }
                else
                {
                    _printMbedError( mbedRet );
                }
            }
            else
            {
                _printMbedError( mbedRet );
            }
        }
        else
        {
            _printMbedError( mbedRet );
        }

        mbedtls_ssl_config_free( &ctx->tlsConnection.conf );
        mbedtls_ssl_close_notify( &ctx->tlsConnection.ssl );
        mbedtls_ssl_session_reset( &ctx->tlsConnection.ssl );
        mbedtls_net_free( &ctx->tlsConnection.server_fd );
    }

    return isSuccess;
}