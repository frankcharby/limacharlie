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

#include <networkLib/networkLib.h>

#define RPAL_FILE_ID    41

#ifdef RPAL_PLATFORM_WINDOWS
    #ifdef RPAL_PLATFORM_WINDOWS_32
        // Includes are made messier by the use of the DDK so we need
        // some voodoo magic here.
        #include <tcpmib.h>
        #include <Iprtrmib.h>
        #define _NETIOAPI_H_
        #undef _WINSOCK2API_
    #endif
#include <IPHlpApi.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>

#define TCPF_ALL 0xFFF
#define UDPF_ALL 0xFFF

// From include/net/tcp_states.h
// As far as I can tell, these are still not exported to user space
// and cannot be included
enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,

	TCP_MAX_STATES
};
enum {
	TCPF_ESTABLISHED = (1 << 1),
	TCPF_SYN_SENT	 = (1 << 2),
	TCPF_SYN_RECV	 = (1 << 3),
	TCPF_FIN_WAIT1	 = (1 << 4),
	TCPF_FIN_WAIT2	 = (1 << 5),
	TCPF_TIME_WAIT	 = (1 << 6),
	TCPF_CLOSE	 = (1 << 7),
	TCPF_CLOSE_WAIT	 = (1 << 8),
	TCPF_LAST_ACK	 = (1 << 9),
	TCPF_LISTEN	 = (1 << 10),
	TCPF_CLOSING	 = (1 << 11) 
};

// Based on libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
#endif

#pragma warning( disable: 4127 ) // Disabling error on constant expression in condition

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

NetLib_Tcp4Table*
    NetLib_getTcp4Table
    (

    )
{
    NetLib_Tcp4Table* table = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    PMIB_TCPTABLE winTable = NULL;
    RU32 size = 0;
    RU32 error = 0;
    RBOOL isFinished = FALSE;
    RU32 i = 0;

    while( !isFinished )
    {
        if( NULL != GetExtendedTcpTable )
        {
            error = GetExtendedTcpTable( winTable, (DWORD*)&size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0 );
        }
        else
        {
            error = GetTcpTable( winTable, (PDWORD)&size, FALSE );
        }

        if( ERROR_INSUFFICIENT_BUFFER == error &&
            0 != size )
        {
            if( NULL == ( winTable = rpal_memory_realloc( winTable, size ) ) )
            {
                isFinished = TRUE;
            }
        }
        else if( ERROR_SUCCESS != error )
        {
            rpal_memory_free( winTable );
            winTable = NULL;
            isFinished = TRUE;
        }
        else
        {
            isFinished = TRUE;
        }
    }

    if( NULL != winTable )
    {
        if( NULL != ( table = rpal_memory_alloc( sizeof( NetLib_Tcp4Table ) + 
                                                    ( winTable->dwNumEntries * sizeof( NetLib_Tcp4TableRow ) ) ) ) )
        {
            table->nRows = winTable->dwNumEntries;

            for( i = 0; i < winTable->dwNumEntries; i++ )
            {
                if( NULL == GetExtendedTcpTable )
                {
                    table->rows[ i ].destIp = winTable->table[ i ].dwRemoteAddr;
                    table->rows[ i ].destPort = (RU16)winTable->table[ i ].dwRemotePort;
                    table->rows[ i ].sourceIp = winTable->table[ i ].dwLocalAddr;
                    table->rows[ i ].sourcePort = (RU16)winTable->table[ i ].dwLocalPort;
                    table->rows[ i ].state = winTable->table[ i ].dwState;
                    table->rows[ i ].pid = 0;
                }
                else
                {
                    table->rows[ i ].destIp = ((PMIB_TCPROW_OWNER_PID)winTable->table)[ i ].dwRemoteAddr;
                    table->rows[ i ].destPort = (RU16)((PMIB_TCPROW_OWNER_PID)winTable->table)[ i ].dwRemotePort;
                    table->rows[ i ].sourceIp = ((PMIB_TCPROW_OWNER_PID)winTable->table)[ i ].dwLocalAddr;
                    table->rows[ i ].sourcePort = (RU16)((PMIB_TCPROW_OWNER_PID)winTable->table)[ i ].dwLocalPort;
                    table->rows[ i ].state = ((PMIB_TCPROW_OWNER_PID)winTable->table)[ i ].dwState;
                    table->rows[ i ].pid = ((PMIB_TCPROW_OWNER_PID)winTable->table)[ i ].dwOwningPid;
                }
            }
        }

        rpal_memory_free( winTable );
    }
#else
    int nlSocket = 0;
    int numBytes = 0;
    int rtaLen = 0;
    struct nlmsghdr nlh;
    struct nlmsghdr *nlhPtr;
    uint8_t buffer[ SOCKET_BUFFER_SIZE ];
    uint8_t *pbuffer = NULL;
    struct inet_diag_msg *diagMsg;
    struct msghdr msg;
    struct inet_diag_req_v2 req;
    struct sockaddr_nl sa;
    struct iovec iov[ 2 ];
    struct rtattr *attr;
    struct tcp_info *tcpi;
    unsigned int size;
    int count;

    // Create the netlink socket
    if( ( nlSocket = socket( AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG ) ) == -1 )
    {
        rpal_debug_warning( "netlink socket creation failed" );
        return table;
    }
    
    // Increase the maximum size to avoid multiple calls
    size = 1048576;
    setsockopt( nlSocket, SOL_SOCKET, SO_RCVBUF, &size, sizeof( size ) );
    
    // Initialize all the structures to 0
    memset( &msg, 0, sizeof( msg ) );
    memset( &sa, 0, sizeof( sa ) );
    memset( &nlh, 0, sizeof( nlh ) );
    memset( &req, 0, sizeof( req ) );

    // For our purposes, the other fields can stay at 0
    sa.nl_family = AF_NETLINK;
    
    // We want IPv4 and TCP
    req.sdiag_family = AF_INET;
    req.sdiag_protocol = IPPROTO_TCP;
    
    // Filter out some unrequired states
    // TODO review this...
    req.idiag_states = TCPF_ALL & ~( TCPF_SYN_RECV | TCPF_TIME_WAIT | TCPF_CLOSE );

    // Request extended TCP information with bitmask of the extensions to acquire
    // See inet_diag.h (INET_DIAG_*-constants)
    req.idiag_ext |= ( 1 << ( INET_DIAG_INFO - 1 ) );
    
    nlh.nlmsg_len = NLMSG_LENGTH( sizeof( req ) );
    // Get every IP and port
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    // Use the family and protocol from the request
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    
    // Fill out the iovec
    iov[ 0 ].iov_base = ( void * )&nlh;
    iov[ 0 ].iov_len = sizeof( nlh );
    iov[ 1 ].iov_base = ( void * )&req;
    iov[ 1 ].iov_len = sizeof( req );

    // Fill out the message
    msg.msg_name = ( void * )&sa;
    msg.msg_namelen = sizeof( sa );
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    
    if( sendmsg( nlSocket, &msg, 0 ) < 0 )
    {
        rpal_debug_warning( "netlink send message failed" );
        close( nlSocket );
        return table;
    }

    // Here we'll just gather all the netlink messages in a single buffer
    // We should validate that we don't get too much data
    // The theoretical maximum size for all the messages in 4GiB
    size = 0;
    while( 1 )
    {
        // Have a look at the size of the buffer we'll get
        numBytes = recv( nlSocket, pbuffer, 0, MSG_PEEK | MSG_TRUNC );
        // In case of errer, we should do better handling
        if (numBytes <= 0)
        {
            break;
        }
        // Allocate memory on first pass or if we have more messages
        if (pbuffer == NULL || numBytes > 20)
        {
            // Add 20, which is the size of the NLMSG_DONE message
            // That way we don't have to reallocate and waste time
            if( NULL == ( pbuffer = rpal_memory_realloc( pbuffer, size + numBytes + 20 ) ) )
            {
                rpal_debug_warning( "realloc error" );
                break;
            }
        }
        // Fetch the data for real
        // TODO check if there could be a discrepancy between data expected and data received
        numBytes = recv( nlSocket, &pbuffer[size], numBytes, 0 );
        // In case of errer, we should do better handling
        if (numBytes <= 0)
        {
            break;
        }
        // Temporarily cast the buffer
        nlhPtr = ( struct nlmsghdr * )&pbuffer[size];
        // And check to see if we're done
        if( nlhPtr->nlmsg_type == NLMSG_DONE )
        {
            break;
        }
        if( nlhPtr->nlmsg_type == NLMSG_ERROR )
        {
            rpal_debug_warning( "netlink receive message error" );
            break;
        }
        size += numBytes;
    }
    
    // All done with this
    close( nlSocket );

    // Cast the buffer again
    nlhPtr = ( struct nlmsghdr * )pbuffer;
    // Count the messages
    count = 0;
    while( NLMSG_OK( nlhPtr, size ) )
    {
        nlhPtr = NLMSG_NEXT( nlhPtr, size );
        count++;
    }
    
    // Now allocate enough memory for the maximum possible amount
    if( NULL != ( table = rpal_memory_alloc( sizeof( NetLib_Tcp4Table ) + 
                                                    ( count * sizeof( NetLib_Tcp4TableRow ) ) ) ) )
    {
        // Start at 0 and increment, just in case some entries are not valid
        table->nRows = 0;
        // Cast the buffer
        nlhPtr = ( struct nlmsghdr * )pbuffer;
        // Iterate through the messages
        for( int i = 0; i < count; i++ )
        {
            diagMsg = ( struct inet_diag_msg * )NLMSG_DATA( nlhPtr );
            rtaLen = nlhPtr->nlmsg_len - NLMSG_LENGTH( sizeof( *diagMsg ) );
            if( diagMsg->idiag_family == AF_INET )
            {
                // IPv4
                // Parse the attributes of the netlink message
                if( rtaLen > 0 )
                {
                    attr = ( struct rtattr * )( diagMsg + 1 );
                    while( RTA_OK( attr, rtaLen ) )
                    {
                        if( attr->rta_type == INET_DIAG_INFO )
                        {
                            // Cast accordingly
                            tcpi = ( struct tcp_info * )RTA_DATA( attr );
                            
                            // Debug
                            /*char source[INET_ADDRSTRLEN];
                            char destination[INET_ADDRSTRLEN];
                            inet_ntop( AF_INET, ( struct in_addr * )&( diagMsg->id.idiag_src ), 
                                       source, INET_ADDRSTRLEN );
                            inet_ntop( AF_INET, ( struct in_addr * )&( diagMsg->id.idiag_dst ), 
                                       destination, INET_ADDRSTRLEN );
                            printf("%s:%d -> %s:%d, state:%d\n", source, ntohs( diagMsg->id.idiag_sport ), 
                                                       destination, ntohs( diagMsg->id.idiag_dport ), 
                                                       tcpi->tcpi_state );*/
                            
                            table->rows[ i ].destIp = diagMsg->id.idiag_dst[ 0 ];
                            table->rows[ i ].destPort = diagMsg->id.idiag_dport;
                            table->rows[ i ].sourceIp = diagMsg->id.idiag_src[ 0 ];
                            table->rows[ i ].sourcePort = diagMsg->id.idiag_sport;
                            // TODO improve this
                            table->rows[ i ].state = 5;
                            table->rows[ i ].pid = 0;
                            table->nRows++;
                        }
                        attr = RTA_NEXT( attr, rtaLen );
                    }
                }
            }
            // Go to the next message
            nlhPtr = ( struct nlmsghdr * )( ( char * )nlhPtr + NLMSG_ALIGN( nlhPtr->nlmsg_len ) );
        }
    }
    rpal_memory_free( pbuffer );
#endif
    return table;
}

NetLib_UdpTable*
    NetLib_getUdpTable
    (

    )
{
    NetLib_UdpTable* table = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    PMIB_UDPTABLE winTable = NULL;
    RU32 size = 0;
    RU32 error = 0;
    RBOOL isFinished = FALSE;
    RU32 i = 0;

    while( !isFinished )
    {
        if( NULL != GetExtendedUdpTable )
        {
            error = GetExtendedUdpTable( winTable, (DWORD*)&size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0 );
        }
        else
        {
            error = GetUdpTable( winTable, (PDWORD)&size, FALSE );
        }

        if( ERROR_INSUFFICIENT_BUFFER == error &&
            0 != size )
        {
            if( NULL == ( winTable = rpal_memory_realloc( winTable, size ) ) )
            {
                isFinished = TRUE;
            }
        }
        else if( ERROR_SUCCESS != error )
        {
            rpal_memory_free( winTable );
            winTable = NULL;
            isFinished = TRUE;
        }
        else
        {
            isFinished = TRUE;
        }
    }

    if( NULL != winTable )
    {
        if( NULL != ( table = rpal_memory_alloc( sizeof( NetLib_UdpTable ) + 
                                                    ( winTable->dwNumEntries * sizeof( NetLib_UdpTableRow ) ) ) ) )
        {
            table->nRows = winTable->dwNumEntries;

            for( i = 0; i < winTable->dwNumEntries; i++ )
            {
                if( NULL == GetExtendedUdpTable )
                {
                    table->rows[ i ].localIp = winTable->table[ i ].dwLocalAddr;
                    table->rows[ i ].localPort = (RU16)winTable->table[ i ].dwLocalPort;
                    table->rows[ i ].pid = 0;
                }
                else
                {
                    table->rows[ i ].localIp = ((PMIB_UDPROW_OWNER_PID)winTable->table)[ i ].dwLocalAddr;
                    table->rows[ i ].localPort = (RU16)((PMIB_UDPROW_OWNER_PID)winTable->table)[ i ].dwLocalPort;
                    table->rows[ i ].pid = ((PMIB_UDPROW_OWNER_PID)winTable->table)[ i ].dwOwningPid;
                }
            }
        }

        rpal_memory_free( winTable );
    }
#else
    int nlSocket = 0;
    int numBytes = 0;
    int rtaLen = 0;
    struct nlmsghdr nlh;
    struct nlmsghdr *nlhPtr;
    uint8_t buffer[ SOCKET_BUFFER_SIZE ];
    uint8_t *pbuffer = NULL;
    struct inet_diag_msg *diagMsg;
    struct msghdr msg;
    struct inet_diag_req_v2 req;
    struct sockaddr_nl sa;
    struct iovec iov[ 2 ];
    struct rtattr *attr;
    struct tcp_info *tcpi;
    unsigned int size;
    int count;

    // Create the netlink socket
    if( ( nlSocket = socket( AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG ) ) == -1 )
    {
        rpal_debug_warning( "netlink socket creation failed" );
        return table;
    }
    
    // Increase the maximum size to avoid multiple calls
    size = 1048576;
    setsockopt( nlSocket, SOL_SOCKET, SO_RCVBUF, &size, sizeof( size ) );
    
    // Initialize all the structures to 0
    memset( &msg, 0, sizeof( msg ) );
    memset( &sa, 0, sizeof( sa ) );
    memset( &nlh, 0, sizeof( nlh ) );
    memset( &req, 0, sizeof( req ) );

    // For our purposes, the other fields can stay at 0
    sa.nl_family = AF_NETLINK;
    
    // We want IPv4 and UDP
    req.sdiag_family = AF_INET;
    req.sdiag_protocol = IPPROTO_UDP;
    
    // TODO review this...is it even required?
    req.idiag_states = UDPF_ALL;

    // Request extended TCP information with bitmask of the extensions to acquire
    // See inet_diag.h (INET_DIAG_*-constants)
    req.idiag_ext |= ( 1 << ( INET_DIAG_INFO - 1 ) );
    
    nlh.nlmsg_len = NLMSG_LENGTH( sizeof( req ) );
    // Get every IP and port
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    // Use the family and protocol from the request
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    
    // Fill out the iovec
    iov[ 0 ].iov_base = ( void * )&nlh;
    iov[ 0 ].iov_len = sizeof( nlh );
    iov[ 1 ].iov_base = ( void * )&req;
    iov[ 1 ].iov_len = sizeof( req );

    // Fill out the message
    msg.msg_name = ( void * )&sa;
    msg.msg_namelen = sizeof( sa );
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    
    if( sendmsg( nlSocket, &msg, 0 ) < 0 )
    {
        rpal_debug_warning( "netlink send message failed" );
        close( nlSocket );
        return table;
    }

    // Here we'll just gather all the netlink messages in a single buffer
    // We should validate that we don't get too much data
    // The theoretical maximum size for all the messages in 4GiB
    size = 0;
    while( 1 )
    {
        // Have a look at the size of the buffer we'll get
        numBytes = recv( nlSocket, pbuffer, 0, MSG_PEEK | MSG_TRUNC );
        // In case of errer, we should do better handling
        if (numBytes <= 0)
        {
            break;
        }
        // Allocate memory on first pass or if we have more messages
        if (pbuffer == NULL || numBytes > 20)
        {
            // Add 20, which is the size of the NLMSG_DONE message
            // That way we don't have to reallocate and waste time
            if( NULL == ( pbuffer = rpal_memory_realloc( pbuffer, size + numBytes + 20 ) ) )
            {
                rpal_debug_warning( "realloc error" );
                break;
            }
        }
        // Fetch the data for real
        // TODO check if there could be a discrepancy between data expected and data received
        numBytes = recv( nlSocket, &pbuffer[size], numBytes, 0 );
        // In case of errer, we should do better handling
        if (numBytes <= 0)
        {
            break;
        }
        // Temporarily cast the buffer
        nlhPtr = ( struct nlmsghdr * )&pbuffer[size];
        // And check to see if we're done
        if( nlhPtr->nlmsg_type == NLMSG_DONE )
        {
            break;
        }
        if( nlhPtr->nlmsg_type == NLMSG_ERROR )
        {
            rpal_debug_warning( "netlink receive message error" );
            break;
        }
        size += numBytes;
    }
    
    // All done with this
    close( nlSocket );
    
    // Cast the buffer again
    nlhPtr = ( struct nlmsghdr * )pbuffer;
    // Count the messages
    count = 0;
    while( NLMSG_OK( nlhPtr, size ) )
    {
        nlhPtr = NLMSG_NEXT( nlhPtr, size );
        count++;
    }
    
    // Now allocate enough memory for the maximum possible amount
    if( NULL != ( table = rpal_memory_alloc( sizeof( NetLib_UdpTable ) + 
                                                    ( count * sizeof( NetLib_UdpTableRow ) ) ) ) )
    {
        // Start at 0 and increment, just in case some entries are not valid
        table->nRows = 0;
        // Cast the buffer
        nlhPtr = ( struct nlmsghdr * )pbuffer;
        // Iterate through the messages
        for( int i = 0; i < count; i++ )
        {
            diagMsg = ( struct inet_diag_msg * )NLMSG_DATA( nlhPtr );
            rtaLen = nlhPtr->nlmsg_len - NLMSG_LENGTH( sizeof( *diagMsg ) );
            
            if( diagMsg->idiag_family == AF_INET )
            {
                // Parse the attributes of the netlink message
                // Debug
                /*char source[INET_ADDRSTRLEN];
                char destination[INET_ADDRSTRLEN];
                inet_ntop( AF_INET, ( struct in_addr * )&( diagMsg->id.idiag_src ), 
                           source, INET_ADDRSTRLEN );
                inet_ntop( AF_INET, ( struct in_addr * )&( diagMsg->id.idiag_dst ), 
                           destination, INET_ADDRSTRLEN );
                printf("%s:%d -> %s:%d\n", source, ntohs( diagMsg->id.idiag_sport ), 
                                           destination, ntohs( diagMsg->id.idiag_dport ));*/
                
                table->rows[ i ].localIp = diagMsg->id.idiag_src[ 0 ];
                table->rows[ i ].localPort = diagMsg->id.idiag_sport;
                // TODO improve this
                table->rows[ i ].pid = 0;
                table->nRows++;
            }
            // Go to the next message
            nlhPtr = ( struct nlmsghdr * )( ( char * )nlhPtr + NLMSG_ALIGN( nlhPtr->nlmsg_len ) );
        }
    }
    rpal_memory_free( pbuffer );
#endif
    return table;
}


NetLibTcpConnection
    NetLib_TcpConnect
    (
        RPCHAR dest,
        RU16 port
    )
{
    NetLibTcpConnection conn = 0;

    if( NULL != dest )
    {
        RBOOL isConnected = FALSE;
        struct sockaddr_in server = { 0 };
        struct hostent* remoteHost = NULL;
        conn = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

#ifdef RPAL_PLATFORM_WINDOWS
        if( INVALID_SOCKET == conn && WSANOTINITIALISED == WSAGetLastError() )
        {
            WSADATA wsadata = { 0 };
            if( 0 != WSAStartup( MAKEWORD( 2, 2 ), &wsadata ) )
            {
                return 0;
            }
            conn = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
        }
#endif

        if( conn )
        {
            if( NULL != ( remoteHost = gethostbyname( dest ) ) )
            {
                rpal_memory_memcpy( &server.sin_addr, remoteHost->h_addr_list[ 0 ], remoteHost->h_length );
                server.sin_family = AF_INET;
                server.sin_port = htons( port );

                if( 0 == connect( conn, (struct sockaddr*)&server, sizeof( server ) ) )
                {
                    isConnected = TRUE;
                }
            }
        }

        if( !isConnected && 0 != conn )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            closesocket( conn );
#else
            close( conn );
#endif
            conn = 0;
        }
    }

    return conn;
}

NetLibTcpConnection
    NetLib_TcpListen
    (
        RPCHAR ifaceIp,
        RU16 port
    )
{
    NetLibTcpConnection conn = 0;

    if( NULL != ifaceIp )
    {
        RBOOL isConnected = FALSE;
        struct sockaddr_in server = { 0 };
        struct hostent* remoteHost = NULL;
        conn = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

#ifdef RPAL_PLATFORM_WINDOWS
        if( INVALID_SOCKET == conn && WSANOTINITIALISED == WSAGetLastError() )
        {
            WSADATA wsadata = { 0 };
            if( 0 != WSAStartup( MAKEWORD( 2, 2 ), &wsadata ) )
            {
                return 0;
            }
            conn = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
        }
#endif

        if( conn )
        {
            if( NULL != ( remoteHost = gethostbyname( ifaceIp ) ) )
            {
                rpal_memory_memcpy( &server.sin_addr, remoteHost->h_addr_list[ 0 ], remoteHost->h_length );
                server.sin_family = AF_INET;
                server.sin_port = htons( port );

                if( 0 == bind( conn, ( struct sockaddr* )&server, sizeof( server ) ) &&
                    0 == listen( conn, SOMAXCONN ) )
                {
                    isConnected = TRUE;
                }
            }
        }

        if( !isConnected && 0 != conn )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            closesocket( conn );
#else
            close( conn );
#endif
            conn = 0;
        }
    }

    return conn;
}

NetLibTcpConnection
    NetLib_TcpAccept
    (
        NetLibTcpConnection conn,
        rEvent stopEvent,
        RU32 timeoutSec
    )
{
    NetLibTcpConnection client = 0;
    fd_set sockets;
    struct timeval timeout = { 1, 0 };
    int waitVal = 0;
    RTIME expire = 0;
    int n = 0;

    if( 0 != conn &&
        NULL != stopEvent )
    {
        if( 0 != timeoutSec )
        {
            expire = rpal_time_getLocal() + timeoutSec;
        }

        while( !rEvent_wait( stopEvent, 0 ) &&
              ( 0 == timeoutSec || rpal_time_getLocal() <= expire ) )
        {
            FD_ZERO( &sockets );
            FD_SET( conn, &sockets );
            n = (int)conn + 1;

            waitVal = select( n, &sockets, NULL, NULL, &timeout );

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            if( 0 == waitVal )
            {
                FD_ZERO( &sockets );
                FD_SET( conn, &sockets );
                continue;
            }

            client = accept( conn, NULL, NULL );

#ifdef RPAL_PLATFORM_WINDOWS
            if( INVALID_SOCKET == client )
            {
                client = 0;
            }
#else
            if( ( -1 ) == client )
            {
                client = 0;
            }
#endif
            break;
        }
    }

    return client;
}


RBOOL
    NetLib_TcpDisconnect
    (
        NetLibTcpConnection conn
    )
{
    RBOOL isDisconnected = FALSE;

    if( 0 != conn )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        closesocket( conn );
#else
        close( conn );
#endif
    }

    return isDisconnected;
}

RBOOL
    NetLib_TcpSend
    (
        NetLibTcpConnection conn,
        RPVOID buffer,
        RU32 bufferSize,
        rEvent stopEvent
    )
{
    RBOOL isSent = FALSE;
    RU32 nSent = 0;
    RU32 ret = 0;
    fd_set sockets;
    struct timeval timeout = { 1, 0 };
    int waitVal = 0;
    int n = 0;

    if( 0 != conn &&
        NULL != buffer &&
        0 != bufferSize )
    {
        isSent = TRUE;

        while( nSent < bufferSize && !rEvent_wait( stopEvent, 0 ) )
        {
            FD_ZERO( &sockets );
            FD_SET( conn, &sockets );
            n = (int)conn + 1;

            waitVal = select( n, NULL, &sockets, NULL, &timeout );

            if( 0 == waitVal )
            {
                continue;
            }

            if( SOCKET_ERROR == waitVal ||
                SOCKET_ERROR == ( ret = send( conn, (const char*)( (RPU8)buffer ) + nSent, bufferSize - nSent, 0 ) ) )
            {
                isSent = FALSE;
                break;
            }

            nSent += ret;
        }

        if( nSent != bufferSize )
        {
            isSent = FALSE;
        }
    }

    return isSent;
}

RBOOL
    NetLib_TcpReceive
    (
        NetLibTcpConnection conn,
        RPVOID buffer,
        RU32 bufferSize,
        rEvent stopEvent,
        RU32 timeoutSec
    )
{
    RBOOL isReceived = FALSE;
    RU32 nReceived = 0;
    RU32 ret = 0;
    fd_set sockets;
    struct timeval timeout = { 1, 0 };
    int waitVal = 0;
    RTIME expire = 0;
    int n = 0;

    if( 0 != conn &&
        NULL != buffer &&
        0 != bufferSize )
    {
        isReceived = TRUE;

        if( 0 != timeoutSec )
        {
            expire = rpal_time_getLocal() + timeoutSec;
        }

        while( nReceived < bufferSize && 
               !rEvent_wait( stopEvent, 0 ) && 
               ( 0 == timeoutSec || rpal_time_getLocal() <= expire ) )
        {
            FD_ZERO( &sockets );
            FD_SET( conn, &sockets );
            n = (int)conn + 1;

            waitVal = select( n, &sockets, NULL, NULL, &timeout );

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            if( 0 == waitVal )
            {
                FD_ZERO( &sockets );
                FD_SET( conn, &sockets );
                continue;
            }

            if( SOCKET_ERROR == waitVal ||
                SOCKET_ERROR == ( ret = recv( conn, (char*)( (RPU8)buffer ) + nReceived, bufferSize - nReceived, 0 ) ) ||
                0 == ret )
            {
                isReceived = FALSE;
                break;
            }

            nReceived += ret;
        }

        if( nReceived != bufferSize )
        {
            isReceived = FALSE;
        }
    }

    return isReceived;
}
