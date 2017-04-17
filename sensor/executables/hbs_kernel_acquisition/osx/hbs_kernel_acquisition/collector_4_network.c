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
#define _NUM_BUFFERED_DNS           200
#define _FLT_HANDLE_BASE            0x52484350// RHCP
#define _FLT_NAME                   "com.refractionpoint.hbs.acq.net"

static rMutex g_collector_4_mutex = NULL;
static KernelAcqNetwork g_connections[ _NUM_BUFFERED_CONNECTIONS ] = { 0 };
static uint32_t g_nextConnection = 0;
static rMutex g_collector_4_mutex_dns = NULL;
static KernelAcqDnsResp g_dns[ _NUM_BUFFERED_DNS ] = { 0 };
static uint32_t g_nextDns = 0;
static uint32_t g_socketsPending = 0;
static RBOOL g_shuttingDown = FALSE;

#define DNS_A_RECORD    0x0001
#define DNS_AAAA_RECORD 0x001C

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

#pragma pack(push, 1)
typedef struct
{
    RU16 msgId;
    RU8 rd:1;
    RU8 tc:1;
    RU8 aa:1;
    RU8 opCode:4;
    RU8 qr:1;
    RU8 rCode:4;
    RU8 reserved:3;
    RU8 ra:1;
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

static void
    next_connection
    (

    )
{
    g_nextConnection++;
    if( g_nextConnection == _NUM_BUFFERED_CONNECTIONS )
    {
        g_nextConnection = 0;
        rpal_debug_warning( "overflow of the network connection buffer" );
    }
}

static void
    next_dns
    (

    )
{
    g_nextDns++;
    if( g_nextDns == _NUM_BUFFERED_DNS )
    {
        g_nextDns = 0;
        rpal_debug_warning( "overflow of the dns buffer" );
    }
}

static
RBOOL
    getPacket
    (
        mbuf_t* mbuf,
        RPU8* pPacket,
        RSIZET* pPacketSize
    )
{
    mbuf_t data = NULL;
    RPU8 packet = NULL;
    RSIZET packetLength = 0;
    
    if( NULL == mbuf ||
        NULL == pPacket ||
        NULL == pPacketSize )
    {
        return FALSE;
    }
    
    data = *mbuf;
    while( NULL != data && MBUF_TYPE_DATA != mbuf_type( data ) )
    {
        data = mbuf_next( data );
    }
    
    if( NULL == data )
    {
        return FALSE;
    }
    
    if( NULL == ( packet = mbuf_data( data ) ) )
    {
        return FALSE;
    }
    
    if( 0 == (packetLength = mbuf_len( data ) ) )
    {
        return FALSE;
    }
    
    *pPacket = packet;
    *pPacketSize = packetLength;
    
    return TRUE;
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
    
    if( NULL == cookie ) return ret;
    
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
                sc->netEvent.srcIp.value.v4 = remote4.sin_addr.s_addr;
                sc->netEvent.srcPort = ntohs( remote4.sin_port );
                sc->netEvent.dstIp.isV6 = FALSE;
                sc->netEvent.dstIp.value.v4 = local4.sin_addr.s_addr;
                sc->netEvent.dstPort = ntohs( local4.sin_port );
            }
            else
            {
                sc->netEvent.srcIp.isV6 = TRUE;
                memcpy( &sc->netEvent.srcIp.value.v6.byteArray,
                        &remote6.sin6_addr,
                        sizeof( sc->netEvent.srcIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( remote6.sin6_port );
                sc->netEvent.dstIp.isV6 = TRUE;
                memcpy( &sc->netEvent.dstIp.value.v6.byteArray,
                        &local6.sin6_addr,
                        sizeof( sc->netEvent.dstIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( local6.sin6_port );
            }
        }
        else
        {
            if( !isIpV6 )
            {
                sc->netEvent.srcIp.isV6 = FALSE;
                sc->netEvent.srcIp.value.v4 = local4.sin_addr.s_addr;
                sc->netEvent.srcPort = ntohs( local4.sin_port );
                sc->netEvent.dstIp.isV6 = FALSE;
                sc->netEvent.dstIp.value.v4 = remote4.sin_addr.s_addr;
                sc->netEvent.dstPort = ntohs( remote4.sin_port );
            }
            else
            {
                sc->netEvent.srcIp.isV6 = TRUE;
                memcpy( &sc->netEvent.srcIp.value.v6.byteArray,
                        &local6.sin6_addr,
                        sizeof( sc->netEvent.srcIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( local6.sin6_port );
                sc->netEvent.dstIp.isV6 = TRUE;
                memcpy( &sc->netEvent.dstIp.value.v6.byteArray,
                        &remote6.sin6_addr,
                        sizeof( sc->netEvent.dstIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( remote6.sin6_port );
            }
        }
        
        if( !isIpV6 )
        {
            // rpal_debug_info( "^^^^^^ CONNECTION V4 (%d): incoming=%d 0x%08X:%d ---> 0x%08X:%d",
            //                  (RU32)sc->netEvent.proto,
            //                  (RU32)sc->netEvent.isIncoming,
            //                  sc->netEvent.srcIp.value.v4,
            //                  (RU32)sc->netEvent.srcPort,
            //                  sc->netEvent.dstIp.value.v4,
            //                  (RU32)sc->netEvent.dstPort );
        }
        else
        {
            // rpal_debug_info( "^^^^^^ CONNECTION V6 (%d): incoming=%d %d ---> %d",
            //                  (RU32)sc->netEvent.proto,
            //                  (RU32)sc->netEvent.isIncoming,
            //                  (RU32)sc->netEvent.srcPort,
            //                  (RU32)sc->netEvent.dstPort );
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
    RPU8 packet = NULL;
    RSIZET packetSize = 0;
    
    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( control );
    UNREFERENCED_PARAMETER( flags );
    
    if( NULL != cookie )
    {
        // Report on the connection event
        if( !sc->isReported )
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
        
        // See if we need to report on any content based parsing
        // Looking for DNS responses
        if( 53 == sc->netEvent.srcPort &&
            ( IPPROTO_TCP == sc->netEvent.proto ||
              IPPROTO_UDP == sc->netEvent.proto ) &&
            getPacket( data, &packet, &packetSize ) &&
            sizeof( DnsHeader ) < packetSize )
        {
            RU32 i = 0;
            DnsLabel* pLabel = NULL;
            DnsHeader* dnsHeader = (DnsHeader*)packet;
            rpal_debug_info("DNS response (%d): ID %d, QR %d, OPCODE %d, RCODE %d, QD %d, AN %d, NS %d, AR %d", (RU32)packetSize, (RU32)ntohs( dnsHeader->msgId ), (RU32)ntohs(dnsHeader->qr), (RU32)ntohs(dnsHeader->opCode), (RU32)ntohs(dnsHeader->rCode), (RU32)ntohs(dnsHeader->qdCount), (RU32)ntohs(dnsHeader->anCount), (RU32)ntohs(dnsHeader->nsCount), (RU32)ntohs(dnsHeader->arCount) );
            
            // Parsing the questions
            pLabel = (DnsLabel*)dnsHeader->data;
            for( i = 0; i < ntohs( dnsHeader->qdCount ); i++ )
            {
                DnsQuestionInfo* pQInfo = NULL;
                
                while( IS_WITHIN_BOUNDS( pLabel, sizeof( *pLabel ) + pLabel->nChar, dnsHeader, packetSize ) &&
                       0 != pLabel->nChar )
                {
                    /*
                    RU8 tmpTerminator = pLabel->label[ pLabel->nChar ];
                    pLabel->label[ pLabel->nChar ] = 0;
                    rpal_debug_info( "Label:: %s", pLabel->label );
                    pLabel->label[ pLabel->nChar ] = tmpTerminator;
                    */
                    
                    pLabel = (DnsLabel*)( (RPU8)pLabel + pLabel->nChar + 1 );
                }
                
                pQInfo = (DnsQuestionInfo*)( (RPU8)pLabel + 1 );
                if( !IS_WITHIN_BOUNDS( pQInfo, sizeof( *pQInfo ), dnsHeader, packetSize ) )
                {
                    break;
                }
                
                rpal_debug_info( "Type / Class:: %d / %d", ntohs( pQInfo->recordType ), ntohs( pQInfo->recordClass ) );
                
                pLabel = (DnsLabel*)( (RPU8)pQInfo + sizeof( *pQInfo ) );
            }
            
            if( !IS_WITHIN_BOUNDS( pLabel, sizeof( RU16 ), dnsHeader, packetSize ) )
            {
                rpal_debug_info( "OOPS" );
                return KERN_SUCCESS;
            }
            
            for( i = 0; i < ntohs( dnsHeader->anCount ); i++ )
            {
                DnsResponseInfo* pResponseInfo = NULL;
                KernelAcqDnsResp dnsRecord = {0};
                
                dnsRecord.ts = rpal_time_getLocal();
                
                // Labels can be pointers here (11xx xxxx)
                if( 0xC0 <= pLabel->nChar )
                {
                    // Pointer to a label
                    DnsLabel* tmpLabel = NULL;
                    RU16 offset = ntohs( *(RU16*)pLabel ) - 0xC000;
                    RU32 copied = 0;
                    
                    if( !IS_WITHIN_BOUNDS( (RPU8)dnsHeader + offset, sizeof( RU16 ), dnsHeader, packetSize ) )
                    {
                        rpal_debug_info( "OOPS" );
                        break;
                    }
                    
                    tmpLabel = (DnsLabel*)( (RPU8)dnsHeader + offset );
                    while( IS_WITHIN_BOUNDS( tmpLabel, sizeof( *tmpLabel ) + tmpLabel->nChar, dnsHeader, packetSize ) &&
                           0 != tmpLabel->nChar )
                    {
                        /*
                        RU8 tmpTerminator = tmpLabel->label[ tmpLabel->nChar ];
                        tmpLabel->label[ tmpLabel->nChar ] = 0;
                        rpal_debug_info( "Ptr Label:: %s", tmpLabel->label );
                        tmpLabel->label[ tmpLabel->nChar ] = tmpTerminator;
                        */
                        
                        if( sizeof( dnsRecord.domain ) < copied + 1 + tmpLabel->nChar )
                        {
                            rpal_debug_info( "OOPS" );
                            break;
                        }
                        
                        if( 0 != copied )
                        {
                            dnsRecord.domain[ copied ] = '.';
                            copied++;
                        }
                        memcpy( &dnsRecord.domain + copied, tmpLabel->label, tmpLabel->nChar );
                        copied += tmpLabel->nChar;
                        
                        tmpLabel = (DnsLabel*)( (RPU8)tmpLabel + tmpLabel->nChar + 1 );
                    }
                    
                    pLabel = (DnsLabel*)( (RPU8)pLabel + sizeof( RU16 ) );
                }
                else
                {
                    RU32 copied = 0;
                    
                    // Classic labels
                    while( IS_WITHIN_BOUNDS( pLabel, sizeof( *pLabel ) + pLabel->nChar, dnsHeader, packetSize ) &&
                           0 != pLabel->nChar )
                    {
                        RU8 tmpTerminator = pLabel->label[ pLabel->nChar ];
                        pLabel->label[ pLabel->nChar ] = 0;
                        rpal_debug_info( "Label:: %s", pLabel->label );
                        pLabel->label[ pLabel->nChar ] = tmpTerminator;
                        
                        if( sizeof( dnsRecord.domain ) < copied + 1 + pLabel->nChar )
                        {
                            rpal_debug_info( "OOPS" );
                            break;
                        }
                        
                        if( 0 != copied )
                        {
                            dnsRecord.domain[ copied ] = '.';
                        }
                        memcpy( &dnsRecord.domain + copied, pLabel->label, pLabel->nChar );
                        copied += pLabel->nChar;
                        
                        pLabel = (DnsLabel*)( (RPU8)pLabel + pLabel->nChar + 1 );
                    }
                }
                
                pResponseInfo = (DnsResponseInfo*)( (RPU8)pLabel + 1 );
                
                if( !IS_WITHIN_BOUNDS( pResponseInfo, sizeof( *pResponseInfo ), dnsHeader, packetSize ) )
                {
                    rpal_debug_info( "OOPS" );
                    break;
                }
                
                rpal_debug_info( "Resp Type / Class:: %d / %d", ntohs( pResponseInfo->recordType ), ntohs( pResponseInfo->recordClass ) );
                dnsRecord.qType = ntohs( pResponseInfo->recordType );
                dnsRecord.qClass = ntohs( pResponseInfo->recordClass );
                
                if( DNS_A_RECORD == dnsRecord.qType )
                {
                    dnsRecord.ip.isV6 = FALSE;
                    dnsRecord.ip.value.v4 = *(RU32*)pResponseInfo->rData;
                }
                else if( DNS_AAAA_RECORD == dnsRecord.qType )
                {
                    dnsRecord.ip.isV6 = TRUE;
                    memcpy( &dnsRecord.ip.value.v6, pResponseInfo->rData, sizeof( dnsRecord.ip.value.v6 ) );
                }
                else
                {
                    // Right now we only care for A and AAAA records.
                    continue;
                }
                
                rpal_mutex_lock( g_collector_4_mutex_dns );
                
                g_dns[ g_nextDns ] = dnsRecord;
                next_dns();
                
                rpal_mutex_unlock( g_collector_4_mutex_dns );
            }
        }
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
    task_get_new_dns
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
        rpal_mutex_lock( g_collector_4_mutex_dns );
        toCopy = (*resultSize) / sizeof( KernelAcqDnsResp );
        
        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextDns ? g_nextDns : toCopy );
            
            *resultSize = toCopy * sizeof( KernelAcqDnsResp );
            memcpy( pResult, g_dns, *resultSize );
            
            g_nextDns -= toCopy;
            memmove( g_dns, g_dns + toCopy, g_nextDns );
        }
        
        rpal_mutex_unlock( g_collector_4_mutex_dns );
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
    
    if( NULL != ( g_collector_4_mutex = rpal_mutex_create() ) &&
        NULL != ( g_collector_4_mutex_dns = rpal_mutex_create() ) )
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
    rpal_mutex_free( g_collector_4_mutex_dns );
    
    return 1;
}
