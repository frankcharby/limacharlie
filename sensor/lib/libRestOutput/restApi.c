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

typedef struct
{
#ifdef RPAL_PLATFORM_WINDOWS
    HMODULE hWininet;

    InternetCrackUrl_f pInternetCrackUrl;
    InternetOpen_f pInternetOpen;
    InternetConnect_f pInternetConnect;
    InternetCloseHandle_f pInternetCloseHandle;
    HttpOpenRequest_f pHttpOpenRequest;
    HttpSendRequest_f pHttpSendRequest;
    InternetQueryDataAvailable_f pInternetQueryDataAvailable;
    InternetReadFile_f pInternetReadFile;
    InternetSetOption_f pInternetSetOption;

    INTERNET_SCHEME scheme;
    RU32 flags;
    HINTERNET hInternet;
    HINTERNET hConnect;

    RPCHAR server;
    RPCHAR page;
    RU16 port;
#else

#endif
} _restOutputContext;




restOutputContext
    restOutput_newContext
    (
        RPCHAR destUrl,
        RPCHAR apiKey
    )
{
    _restOutputContext* ctx = NULL;

    if( NULL != ( ctx = rpal_memory_alloc( sizeof( _restOutputContext ) ) ) )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RNCHAR wininet[] = _NC( "wininet.dll" );
        RCHAR import1[] = "InternetCrackUrlA";
        RCHAR import2[] = "InternetOpenA";
        RCHAR import3[] = "InternetConnectA";
        RCHAR import4[] = "InternetCloseHandle";
        RCHAR import5[] = "HttpOpenRequestA";
        RCHAR import6[] = "HttpSendRequestA";
        RCHAR import7[] = "InternetQueryDataAvailable";
        RCHAR import8[] = "InternetReadFile";
        RCHAR import9[] = "InternetSetOptionA";
        RCHAR userAgent[] = "rpHCP";

        URL_COMPONENTSA components;
        RBOOL isSecure = FALSE;
        RCHAR pUser[ 1024 ] = { 0 };
        RCHAR pPass[ 1024 ] = { 0 };
        RCHAR pUrl[ 1024 ] = { 0 };
        RCHAR pPage[ 1024 ] = { 0 };
        INTERNET_PORT port = 0;
        RPCHAR pPortDelim = NULL;
        RU32 tmpPort = 0;
        RU32 timeout = MSEC_FROM_SEC( 10 );

        if( NULL == ( ctx->hWininet = LoadLibraryW( wininet ) ) ||
            NULL == ( ctx->pInternetCrackUrl = (InternetCrackUrl_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import1 ) ) ||
            NULL == ( ctx->pInternetOpen = (InternetOpen_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import2 ) ) ||
            NULL == ( ctx->pInternetConnect = (InternetConnect_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import3 ) ) ||
            NULL == ( ctx->pInternetCloseHandle = (InternetCloseHandle_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import4 ) ) ||
            NULL == ( ctx->pHttpOpenRequest = (HttpOpenRequest_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import5 ) ) ||
            NULL == ( ctx->pHttpSendRequest = (HttpSendRequest_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import6 ) ) ||
            NULL == ( ctx->pInternetQueryDataAvailable = (InternetQueryDataAvailable_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import7 ) ) ||
            NULL == ( ctx->pInternetReadFile = (InternetReadFile_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import8 ) ) ||
            NULL == ( ctx->pInternetSetOption = (InternetSetOption_f)GetProcAddress( ctx->hWininet, (RPCHAR)&import9 ) ) )
        {
            rpal_debug_error( "Failed to wininet imports: %x", GetLastError() );

            if( NULL != ctx->hWininet )
            {
                FreeLibrary( ctx->hWininet );
            }
            rpal_memory_free( ctx );
            ctx = NULL;
        }

        if( NULL != ctx )
        {
            components.lpszHostName = pUrl;
            components.dwHostNameLength = sizeof( pUrl );
            components.lpszUrlPath = pPage;
            components.dwUrlPathLength = sizeof( pPage );
            components.lpszUserName = pUser;
            components.dwUserNameLength = sizeof( pUser );
            components.lpszPassword = pPass;
            components.dwPasswordLength = sizeof( pPass );
            components.dwStructSize = sizeof( components );

            if( !ctx->pInternetCrackUrl( destUrl, 0, 0, &components ) ||
                0 == components.nPort ||
                0 == rpal_string_strlenA( pUrl ) )
            {
                if( 0 == rpal_string_strlenA( pUrl ) &&
                    rpal_string_strlenA( destUrl ) < ARRAY_N_ELEM( pUrl ) )
                {
                    rpal_string_strcpyA( pUrl, destUrl );
                }
                components.nPort = 443;
                components.nScheme = INTERNET_SCHEME_HTTPS;

                if( NULL != ( pPortDelim = rpal_string_strstrA( pUrl, ":" ) ) )
                {
                    *pPortDelim = 0;
                    if( rpal_string_stoiA( pPortDelim + 1, &tmpPort ) )
                    {
                        components.nPort = (RU16)tmpPort;
                    }
                }
            }

            ctx->port = components.nPort;
            ctx->server = rpal_string_strdupA( pUrl );
            ctx->page = rpal_string_StrdupA( pPage );

            if( INTERNET_SCHEME_HTTPS == components.nScheme )
            {
                isSecure = TRUE;
            }

            ctx->flags = INTERNET_FLAG_NO_UI | 
                         INTERNET_FLAG_NO_CACHE_WRITE | 
                         INTERNET_FLAG_RELOAD;

            if( isSecure )
            {
                ctx->flags |= INTERNET_FLAG_SECURE;
            }

            if( NULL != ( ctx->hInternet = ctx->pInternetOpen( userAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 ) ) )
            {
                if( !ctx->pInternetSetOption( ctx->hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof( timeout ) ) )
                {
                    rpal_debug_warning( "Failed to set connection timeout." );
                }
            }
            else
            {
                rpal_debug_error( "Failed to open internet: %x", GetLastError() );
                rpal_memory_free( ctx->server );
                rpal_memory_free( ctx->page );
                FreeLibrary( ctx->hWininet );
                rpal_memory_free( ctx );
                ctx = NULL;
            }
        }

        if( NULL != ctx )
        {
            if( NULL == ( ctx->hConnect = ctx->pInternetConnect( ctx->hInternet,
                                                                 ctx->server,
                                                                 ctx->port,
                                                                 NULL,
                                                                 NULL,
                                                                 ctx->scheme,
                                                                 ctx->flags,
                                                                 (DWORD_PTR)NULL ) ) )
            {
                rpal_debug_error( "Failed to connect internet: %x", GetLastError() );
                ctx->pInternetCloseHandle( ctx->hInternet );
                rpal_memory_free( ctx->server );
                rpal_memory_free( ctx->page );
                FreeLibrary( ctx->hWininet );
                rpal_memory_free( ctx );
                ctx = NULL;
            }
        }
#else

#endif
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
#ifdef RPAL_PLATFORM_WINDOWS
        if( NULL != ctx->hWininet )
        {
            FreeLibrary( ctx->hWininet );
        }
        if( NULL != ctx->hInternet &&
            NULL != ctx->pInternetCloseHandle )
        {
            ctx->pInternetCloseHandle( ctx->hInternet );
        }
        rpal_memory_free( ctx->server );
        rpal_memory_free( ctx->page );

        rpal_memory_free( ctx );
#else
        rpal_memory_free( ctx );
#endif
    }
}

RBOOL
    restOutput_send
    (
        restOutputContext pContext,
        JsonElem dataElements[],
        RU32 nDataElements
    )
{
    RBOOL isSuccess = FALSE;
    _restOutputContext* ctx = pContext;

    if( NULL != ctx )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        HINTERNET hHttp = NULL;
        RCHAR verb[] = "POST";
        rString payload = NULL;

        if( NULL != ctx->hConnect &&
            NULL != ctx->pHttpOpenRequest )
        {
            if( NULL != ( hHttp = ctx->pHttpOpenRequest( ctx->hConnect, 
                                                         verb, ctx->page ? ctx->page : "", 
                                                         NULL, 
                                                         NULL, 
                                                         NULL, 
                                                         ctx->flags, 
                                                         NULL ) ) )
            {

            }
        }
#else

#endif
    }

    return isSuccess;
}