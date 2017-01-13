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

#include "collectors.h"
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/kpi_mbuf.h>
#include <netinet/in.h>
#include <sys/types.h>

#define _NUM_BUFFERED_CONNECTIONS   200
#define _FLT_HANDLE_BASE            0x52484350// RHCP
#define _FLT_NAME                   "com.refractionpoint.hbs.acq.net"

static rMutex g_collector_4_mutex = NULL;
static KernelAcqNetwork g_connections[ _NUM_BUFFERED_CONNECTIONS ] = { 0 };
static uint32_t g_nextConnection = 0;
static uint32_t g_socketsPending = 0;
static RBOOL g_shuttingDown = FALSE;

typedef struct
{
    RBOOL isReported;
    RBOOL isConnected;
    int addrFamily;
    int sockType;
    struct sockaddr_in peerAtConnect4;
    struct sockaddr_in6 peerAtConnect6;
    KernelAcqNetwork netEvent;
    
} SockCookie;

static void
    next_connection
    (

    )
{
    g_nextConnection++;
    if( g_nextConnection == _NUM_BUFFERED_CONNECTIONS )
    {
        g_nextConnection = 0;
        rpal_debug_warning( "overflow of the network conenction buffer" );
    }
}

static
errno_t
    cbAttach
    (
        void** cookie,
        socket_t so
    )
{
    errno_t ret = EINVAL;
    RBOOL isShuttingDown = FALSE;
    int addrFamily = 0;
    int sockType = 0;
    int protocol = 0;
    SockCookie* sc = NULL;
    
    rpal_mutex_lock( g_collector_4_mutex );
    if( g_shuttingDown )
    {
        isShuttingDown = TRUE;
    }
    else
    {
        g_socketsPending++;
    }
    rpal_mutex_unlock( g_collector_4_mutex );
    
    if( isShuttingDown ) return ret;
    
    if( KERN_SUCCESS == sock_gettype( so, &addrFamily, &sockType, &protocol ) )
    {
        if( ( PF_INET == addrFamily || PF_INET6 == addrFamily ) &&
            ( IPPROTO_TCP == protocol || IPPROTO_UDP == protocol ) )
        {
            if( NULL != ( sc = rpal_memory_alloc( sizeof( SockCookie ) ) ) )
            {
                sc->addrFamily = addrFamily;
                sc->sockType = sockType;
                sc->netEvent.proto = (RU8)protocol;
                sc->netEvent.ts = rpal_time_getLocal();
                sc->isReported = FALSE;
                
                *cookie = sc;
                ret = KERN_SUCCESS;
            }
            else
            {
                ret = ENOMEM;
            }
        }
        else
        {
            ret = EPROTONOSUPPORT;
        }
    }
    
    if( 0 != ret )
    {
        rpal_mutex_lock( g_collector_4_mutex );
        g_socketsPending--;
        rpal_mutex_unlock( g_collector_4_mutex );
    }
    
    return ret;
}

static
void
    cbDetach
    (
        void* cookie,
        socket_t so
    )
{
    if( NULL != cookie )
    {
        rpal_memory_free( cookie );
        rpal_mutex_lock( g_collector_4_mutex );
        g_socketsPending--;
        rpal_mutex_unlock( g_collector_4_mutex );
    }
}

static
RBOOL
    populateCookie
    (
        SockCookie* sc,
        socket_t so,
        const struct sockaddr* remote
    )
{
    RBOOL isPopulated = FALSE;
    
    errno_t ret = KERN_SUCCESS;
    RBOOL isIpV6 = FALSE;
    struct sockaddr_in local4 = { 0 };
    struct sockaddr_in remote4 = { 0 };
    struct sockaddr_in6 local6 = { 0 };
    struct sockaddr_in6 remote6 = { 0 };
    
    if( NULL != sc )
    {
        if( PF_INET == sc->addrFamily )
        {
            isIpV6 = FALSE;
        }
        else
        {
            isIpV6 = TRUE;
        }
        
        sc->netEvent.pid = proc_selfpid();
        
        if( !isIpV6 )
        {
            if( 0 != ( ret = sock_getsockname( so, (struct sockaddr*)&local4, sizeof( local4 ) ) ) )
            {
                rpal_debug_info( "^^^^^^ ERROR getting local sockname4: %d", ret );
            }
            
            if( 0 != ( ret = sock_getpeername( so, (struct sockaddr*)&remote4, sizeof( remote4 ) ) ) ||
                0 == remote4.sin_addr.s_addr )
            {
                if( NULL != remote )
                {
                    memcpy( &remote4, (struct sockaddr_in*)remote, sizeof( remote4 ) );
                }
                else if( 0 != sc->peerAtConnect4.sin_addr.s_addr )
                {
                    memcpy( &remote4, &sc->peerAtConnect4, sizeof( remote4 ) );
                }
            }
        }
        else
        {
            // We only receive IP4 or IP6 so this is always IP6
            if( 0 != ( ret = sock_getsockname( so, (struct sockaddr*)&local6, sizeof( local6 ) ) ) )
            {
                rpal_debug_info( "^^^^^^ ERROR getting local sockname6: %d", ret );
            }
            if( 0 != ( ret = sock_getpeername( so, (struct sockaddr*)&remote6, sizeof( remote6 ) ) ) &&
                NULL != remote )
            {
                memcpy( &remote6, (struct sockaddr_in6*)remote, sizeof( remote6 ) );
            }
        }
        
        if( sc->netEvent.isIncoming )
        {
            if( !isIpV6 )
            {
                sc->netEvent.srcIp.isV6 = FALSE;
                sc->netEvent.srcIp.v4 = remote4.sin_addr.s_addr;
                sc->netEvent.srcPort = ntohs( remote4.sin_port );
                sc->netEvent.dstIp.isV6 = FALSE;
                sc->netEvent.dstIp.v4 = local4.sin_addr.s_addr;
                sc->netEvent.dstPort = ntohs( local4.sin_port );
            }
            else
            {
                sc->netEvent.srcIp.isV6 = TRUE;
                memcpy( &sc->netEvent.srcIp.v6.byteArray,
                        &remote6.sin6_addr,
                        sizeof( sc->netEvent.srcIp.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( remote6.sin6_port );
                sc->netEvent.dstIp.isV6 = TRUE;
                memcpy( &sc->netEvent.dstIp.v6.byteArray,
                        &local6.sin6_addr,
                        sizeof( sc->netEvent.dstIp.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( local6.sin6_port );
            }
        }
        else
        {
            if( !isIpV6 )
            {
                sc->netEvent.srcIp.isV6 = FALSE;
                sc->netEvent.srcIp.v4 = local4.sin_addr.s_addr;
                sc->netEvent.srcPort = ntohs( local4.sin_port );
                sc->netEvent.dstIp.isV6 = FALSE;
                sc->netEvent.dstIp.v4 = remote4.sin_addr.s_addr;
                sc->netEvent.dstPort = ntohs( remote4.sin_port );
            }
            else
            {
                sc->netEvent.srcIp.isV6 = TRUE;
                memcpy( &sc->netEvent.srcIp.v6.byteArray,
                        &local6.sin6_addr,
                        sizeof( sc->netEvent.srcIp.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( local6.sin6_port );
                sc->netEvent.dstIp.isV6 = TRUE;
                memcpy( &sc->netEvent.dstIp.v6.byteArray,
                        &remote6.sin6_addr,
                        sizeof( sc->netEvent.dstIp.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( remote6.sin6_port );
            }
        }
        
        if( !isIpV6 )
        {
            rpal_debug_info( "^^^^^^ CONNECTION V4 (%d): incoming=%d 0x%08X:%d ---> 0x%08X:%d", (RU32)sc->netEvent.proto, (RU32)sc->netEvent.isIncoming, sc->netEvent.srcIp.v4, (RU32)sc->netEvent.srcPort, sc->netEvent.dstIp.v4, (RU32)sc->netEvent.dstPort );
        }
        else
        {
            rpal_debug_info( "^^^^^^ CONNECTION V6 (%d): incoming=%d %d ---> %d", (RU32)sc->netEvent.proto, (RU32)sc->netEvent.isIncoming, (RU32)sc->netEvent.srcPort, (RU32)sc->netEvent.dstPort );
        }
        
        isPopulated = TRUE;
    }
    
    return isPopulated;
}

static
errno_t
    cbDataIn
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* from,
        mbuf_t* data,
        mbuf_t* control,
        sflt_data_flag_t flags
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    
    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( control );
    UNREFERENCED_PARAMETER( flags );
    
    if( NULL != cookie &&
        !sc->isReported )
    {
        if( !sc->isConnected )
        {
            sc->netEvent.isIncoming = TRUE;
        }
        
        populateCookie( sc, so, from );
        
        rpal_mutex_lock( g_collector_4_mutex );
    
        sc->isReported = TRUE;
        g_connections[ g_nextConnection ] = sc->netEvent;
        next_connection();
        
        rpal_mutex_unlock( g_collector_4_mutex );
    }
    
    return KERN_SUCCESS;
}


static
errno_t
    cbDataOut
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* to,
        mbuf_t* data,
        mbuf_t* control,
        sflt_data_flag_t flags
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    
    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( control );
    UNREFERENCED_PARAMETER( flags );
    
    if( NULL != cookie &&
        !sc->isReported )
    {
        if( !sc->isConnected )
        {
            sc->netEvent.isIncoming = FALSE;
        }
        
        populateCookie( sc, so, to );
        
        rpal_mutex_lock( g_collector_4_mutex );
    
        sc->isReported = TRUE;
        g_connections[ g_nextConnection ] = sc->netEvent;
        next_connection();
        
        rpal_mutex_unlock( g_collector_4_mutex );
    }
    
    return KERN_SUCCESS;
}

static
errno_t
    cbConnectIn
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* from
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    
    if( NULL != cookie )
    {
        sc->netEvent.isIncoming = TRUE;
        sc->isConnected = TRUE;
        
        if( NULL != from )
        {
            if( PF_INET == sc->addrFamily )
            {
                memcpy( &sc->peerAtConnect4, (struct sockaddr_in*)from, sizeof( sc->peerAtConnect4 ) );
            }
            else
            {
                memcpy( &sc->peerAtConnect6, (struct sockaddr_in6*)from, sizeof( sc->peerAtConnect6 ) );
            }
        }
    }
    
    return KERN_SUCCESS;
}

static
errno_t
    cbConnectOut
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* to
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    
    if( NULL != cookie )
    {
        sc->netEvent.isIncoming = FALSE;
        sc->isConnected = TRUE;
        
        if( NULL != to )
        {
            if( PF_INET == sc->addrFamily )
            {
                memcpy( &sc->peerAtConnect4, (struct sockaddr_in*)to, sizeof( sc->peerAtConnect4 ) );
            }
            else
            {
                memcpy( &sc->peerAtConnect6, (struct sockaddr_in6*)to, sizeof( sc->peerAtConnect6 ) );
            }
        }
    }
    
    return KERN_SUCCESS;
}

static
RBOOL
    register_filter
    (
        int fltHandle,
        int addrFamily,
        int sockType,
        int protocol
    )
{
    RBOOL isSuccess = FALSE;
    
    struct sflt_filter flt = { 0 };
    flt.sf_handle = _FLT_HANDLE_BASE + fltHandle;
    flt.sf_flags = SFLT_GLOBAL;
    flt.sf_name = _FLT_NAME;
    flt.sf_attach = cbAttach;
    flt.sf_detach = cbDetach;
    flt.sf_connect_in = cbConnectIn;
    flt.sf_connect_out = cbConnectOut;
    flt.sf_data_in = cbDataIn;
    flt.sf_data_out = cbDataOut;
    
    if( 0 == sflt_register( &flt, addrFamily, sockType, protocol ) )
    {
        isSuccess = TRUE;
    }
    
    return isSuccess;
}

static
RBOOL
    unregister_filter
    (
        int fltHandle
    )
{
    RBOOL isUnregistered = FALSE;
    
    if( 0 == sflt_unregister( _FLT_HANDLE_BASE + fltHandle ) )
    {
        isUnregistered = TRUE;
    }
    
    return isUnregistered;
}

int
    task_get_new_connections
    (
        void* pArgs,
        int argsSize,
        void* pResult,
        uint32_t* resultSize
    )
{
    int ret = 0;
    
    int toCopy = 0;
    
    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        rpal_mutex_lock( g_collector_4_mutex );
        toCopy = (*resultSize) / sizeof( KernelAcqNetwork );
        
        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextConnection ? g_nextConnection : toCopy );
            
            *resultSize = toCopy * sizeof( KernelAcqNetwork );
            memcpy( pResult, g_connections, *resultSize );
            
            g_nextConnection -= toCopy;
            memmove( g_connections, g_connections + toCopy, g_nextConnection );
        }
        
        rpal_mutex_unlock( g_collector_4_mutex );
    }
    else
    {
        ret = EINVAL;
    }
    
    return ret;
}

int
    collector_4_initialize
    (
        void* d
    )
{
    int isSuccess = 0;
    
    if( NULL != ( g_collector_4_mutex = rpal_mutex_create() ) )
    {
        if( register_filter( 0, AF_INET, SOCK_STREAM, IPPROTO_TCP ) &&
            register_filter( 1, AF_INET6, SOCK_STREAM, IPPROTO_TCP ) &&
            register_filter( 2, AF_INET, SOCK_DGRAM, IPPROTO_UDP ) &&
            register_filter( 3, AF_INET6, SOCK_DGRAM, IPPROTO_UDP ) )
        {
            isSuccess = 1;
        }
        else
        {
            unregister_filter( 0 );
            unregister_filter( 1 );
            unregister_filter( 2 );
            unregister_filter( 3 );
        }

        if( !isSuccess )
        {
            rpal_mutex_free( g_collector_4_mutex );
        }
    }
    
    return isSuccess;
}

int
    collector_4_deinitialize
    (

    )
{
    RBOOL isDone = FALSE;
    
    rpal_mutex_lock( g_collector_4_mutex );
    g_shuttingDown = TRUE;
    rpal_mutex_unlock( g_collector_4_mutex );
    
    unregister_filter( 0 );
    unregister_filter( 1 );
    unregister_filter( 2 );
    unregister_filter( 3 );
    
    while( !isDone )
    {
        rpal_mutex_lock( g_collector_4_mutex );
        if( 0 == g_socketsPending )
        {
            isDone = TRUE;
        }
        rpal_mutex_unlock( g_collector_4_mutex );
        
        if( !isDone )
        {
            //IOSleep( 500 );
        }
    }
    
    rpal_mutex_free( g_collector_4_mutex );
    
    return 1;
}
