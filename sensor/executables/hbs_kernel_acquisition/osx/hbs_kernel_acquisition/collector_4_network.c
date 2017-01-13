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
#include <IOKit/IOLib.h>

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
    int addrFamily;
    int sockType;
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
    
    if( KERN_SUCCESS == sock_gettype( so, &addrFamily, &sockType, &protocol) )
    {
        if( ( PF_INET == addrFamily || PF_INET6 == addrFamily ) &&
            ( IPPROTO_TCP == protocol || IPPROTO_UDP == protocol ) )
        {
            if( NULL != ( sc = rpal_memory_alloc( sizeof( SockCookie ) ) ) )
            {
                sc->netEvent.pid = proc_selfpid();
                sc->addrFamily = addrFamily;
                sc->sockType = sockType;
                sc->netEvent.proto = protocol;
                sc->netEvent.ts = rpal_time_getLocal();
                
                *cookie = sc;
                ret = 0;
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
    cbDettach
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
errno_t
    cbConnectIn
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* from
    )
{
    errno_t ret = EINVAL;
    SockCookie* sc = (SockCookie*)cookie;
    
    struct sockaddr_in to4 = { 0 };
    struct sockaddr_in realFrom4 = { 0 };
    
    struct sockaddr_in6 to6 = { 0 };
    struct sockaddr_in6 realFrom6 = { 0 };
    
    if( NULL != cookie )
    {
        sc->netEvent.isIncoming = TRUE;
        
        if( PF_INET == sc->addrFamily )
        {
            sock_getsockname( so, (struct sockaddr*)&to4, sizeof( to4 ) );
            if( 0 != sock_getpeername( so, (struct sockaddr*)&realFrom4, sizeof( realFrom4 ) ) &&
                NULL != from )
            {
                realFrom4 = *(struct sockaddr_in*)from;
            }
            sc->netEvent.dstPort = ntohs( to4.sin_port );
            sc->netEvent.dstIp.v4 = to4.sin_addr.s_addr;
            sc->netEvent.dstIp.isV6 = 0;
            sc->netEvent.srcPort = ntohs( realFrom4.sin_port );
            sc->netEvent.srcIp.v4 = realFrom4.sin_addr.s_addr;
            sc->netEvent.srcIp.isV6 = 0;
        }
        else
        {
            sock_getsockname( so, (struct sockaddr*)&to6, sizeof( to6 ) );
            if( 0 != sock_getpeername( so, (struct sockaddr*)&realFrom6, sizeof( realFrom6 ) ) &&
                NULL != from )
            {
                realFrom6 = *(struct sockaddr_in6*)from;
            }
            sc->netEvent.dstPort = ntohs( to6.sin6_port );
            memcpy( &sc->netEvent.dstIp.v6.byteArray,
                    &to6.sin6_addr,
                    sizeof( sc->netEvent.dstIp.v6.byteArray ) );
            sc->netEvent.dstIp.isV6 = 1;
            sc->netEvent.srcPort = ntohs( realFrom6.sin6_port );
            memcpy( &sc->netEvent.srcIp.v6.byteArray,
                    &realFrom6.sin6_addr,
                    sizeof( sc->netEvent.srcIp.v6.byteArray ) );
            sc->netEvent.srcIp.isV6 = 1;
        }
        
        rpal_mutex_lock( g_collector_4_mutex );
    
        g_connections[ g_nextConnection ] = sc->netEvent;
        next_connection();
        
        rpal_mutex_lock( g_collector_4_mutex );
    }
    
    return ret;
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
    errno_t ret = EINVAL;
    SockCookie* sc = (SockCookie*)cookie;
    
    struct sockaddr_in realTo4 = { 0 };
    struct sockaddr_in from4 = { 0 };
    
    struct sockaddr_in6 realTo6 = { 0 };
    struct sockaddr_in6 from6 = { 0 };
    
    if( NULL != cookie )
    {
        sc->netEvent.isIncoming = FALSE;
        
        if( PF_INET == sc->addrFamily )
        {
            sock_getsockname( so, (struct sockaddr*)&from4, sizeof( from4 ) );
            if( 0 != sock_getpeername( so, (struct sockaddr*)&realTo4, sizeof( realTo4 ) ) &&
                NULL != to )
            {
                realTo4 = *(struct sockaddr_in*)to;
            }
            sc->netEvent.dstPort = ntohs( realTo4.sin_port );
            sc->netEvent.dstIp.v4 = realTo4.sin_addr.s_addr;
            sc->netEvent.dstIp.isV6 = 0;
            sc->netEvent.srcPort = ntohs( from4.sin_port );
            sc->netEvent.srcIp.v4 = from4.sin_addr.s_addr;
            sc->netEvent.srcIp.isV6 = 0;
        }
        else
        {
            sock_getsockname( so, (struct sockaddr*)&from6, sizeof( from6 ) );
            if( 0 != sock_getpeername( so, (struct sockaddr*)&realTo6, sizeof( realTo6 ) ) &&
                NULL != to )
            {
                realTo6 = *(struct sockaddr_in6*)to;
            }
            sc->netEvent.dstPort = ntohs( realTo6.sin6_port );
            memcpy( &sc->netEvent.dstIp.v6.byteArray,
                    &realTo6.sin6_addr,
                    sizeof( sc->netEvent.dstIp.v6.byteArray ) );
            sc->netEvent.dstIp.isV6 = 1;
            sc->netEvent.srcPort = ntohs( from6.sin6_port );
            memcpy( &sc->netEvent.srcIp.v6.byteArray,
                    &from6.sin6_addr,
                    sizeof( sc->netEvent.srcIp.v6.byteArray ) );
            sc->netEvent.srcIp.isV6 = 1;
        }
        
        rpal_mutex_lock( g_collector_4_mutex );
    
        g_connections[ g_nextConnection ] = sc->netEvent;
        next_connection();
        
        rpal_mutex_lock( g_collector_4_mutex );
    }
    
    return ret;
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
    flt.sf_detach = cbDettach;
    flt.sf_connect_in = cbConnectIn;
    flt.sf_connect_out = cbConnectOut;
    
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
            IOSleep( 500 );
        }
    }
    
    return 1;
}
