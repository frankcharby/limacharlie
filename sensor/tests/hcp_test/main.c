#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include <networkLib/networkLib.h>
#include <cryptoLib/cryptoLib.h>
#include <Basic.h>

#include <../lib/rpHostCommonPlatformLib/_private.h>

#define RPAL_FILE_ID     92

RU16 g_server_port = 9199;
RU8 g_key[ CRYPTOLIB_SYM_KEY_SIZE ] = { 0 };
RU8 g_iv[ CRYPTOLIB_SYM_IV_SIZE ] = { 0 };
RBOOL g_serverIsRunning = TRUE;

RU32
    threadServer
    (
        RPVOID ctx
    )
{
    RpHcp_ModuleId moduleId = 0;
    rList messages = NULL;
    rpHCPContext hcpCtx = { 0 };
    NetLibTcpConnection serverSock = 0;
    NetLibTcpConnection clientSock = 0;

    UNREFERENCED_PARAMETER( ctx );

    if( NULL != ( hcpCtx.isBeaconTimeToStop = rEvent_create( TRUE ) ) )
    {
        if( 0 != ( serverSock = NetLib_TcpListen( "localhost", g_server_port ) ) )
        {
            while( g_serverIsRunning )
            {
                if( 0 != ( clientSock = NetLib_TcpAccept( serverSock ) ) )
                {
                    hcpCtx.session.symSendCtx = CryptoLib_symEncInitContext( g_key, g_iv );
                    hcpCtx.session.symRecvCtx = CryptoLib_symDecInitContext( g_key, g_iv );
                    hcpCtx.cloudConnection = clientSock;

                    while( recvFrame( &hcpCtx, &moduleId, &messages, 2 ) )  // Tested function
                    {
                        sendFrame( &hcpCtx, moduleId, messages );   // Tested function
                        rList_free( messages );
                    }

                    NetLib_TcpDisconnect( clientSock );

                    CryptoLib_symFreeContext( hcpCtx.session.symSendCtx );
                    CryptoLib_symFreeContext( hcpCtx.session.symRecvCtx );
                }
            }

            NetLib_TcpDisconnect( serverSock );
        }
    }
    
    return 0;
}

void test_memoryLeaks(void)
{
    RU32 memUsed = 0;

    rpal_Context_cleanup();

    memUsed = rpal_memory_totalUsed();

    CU_ASSERT_EQUAL( memUsed, 0 );

    if( 0 != memUsed )
    {
        rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
        printf( "\nMemory leak: %d bytes.\n", memUsed );

        rpal_memory_findMemory();
    }
}

void test_create_dummy_cloud( void )
{
    // Setup cloud connectivity
    CU_ASSERT_TRUE_FATAL( CryptoLib_genRandomBytes( g_key, sizeof( g_key ) ) );
    CU_ASSERT_TRUE_FATAL( CryptoLib_genRandomBytes( g_iv, sizeof( g_iv ) ) );

    rpal_thread_new( threadServer, NULL );
}

void test_destroy_dummy_cloud( void )
{
    g_serverIsRunning = FALSE;
}

void test_frames( void )
{
    rpHCPContext hcpCtx = { 0 };
    RpHcp_ModuleId moduleId = 1;
    RpHcp_ModuleId outMod = 0;
    rList messages = NULL;
    rList outMessages = NULL;
    
    // Connect to the fake server
    hcpCtx.cloudConnection = NetLib_TcpConnect( "localhost", g_server_port );
    CU_ASSERT_NOT_EQUAL_FATAL( hcpCtx.cloudConnection, 0 );

    hcpCtx.session.symRecvCtx = CryptoLib_symDecInitContext( g_key, g_iv );
    hcpCtx.session.symSendCtx = CryptoLib_symEncInitContext( g_key, g_iv );

    // Create and test frames
    messages = rList_new( 1, RPCM_STRINGA );
    CU_ASSERT_NOT_EQUAL_FATAL( messages, NULL );

    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str1" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str2" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str3" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str4" ) );

    CU_ASSERT_TRUE( sendFrame( &hcpCtx, moduleId, messages ) );
    
    CU_ASSERT_TRUE( recvFrame( &hcpCtx, &outMod, &outMessages, 5 ) );
    CU_ASSERT_EQUAL( outMod, moduleId );

    CU_ASSERT_EQUAL( rList_getNumElements( outMessages ), rList_getNumElements( messages ) );
    CU_ASSERT_TRUE( rList_isEqual( messages, outMessages ) );
    
    rList_free( messages );
    rList_free( outMessages );

    // Cleanup cloud connectivity
    CryptoLib_symFreeContext( hcpCtx.session.symRecvCtx );
    CryptoLib_symFreeContext( hcpCtx.session.symSendCtx );

    NetLib_TcpDisconnect( hcpCtx.cloudConnection );
    
}

int
    main
    (
        int argc,
        char* argv[]
    )
{
    int ret = 1;

    CU_pSuite suite = NULL;

    UNREFERENCED_PARAMETER( argc );
    UNREFERENCED_PARAMETER( argv );

    rpal_initialize( NULL, 1 );

    CU_initialize_registry();

    if( NULL != ( suite = CU_add_suite( "cryptoLib", NULL, NULL ) ) )
    {
        if( NULL == CU_add_test( suite, "create_cloud", test_create_dummy_cloud ) || 
            NULL == CU_add_test( suite, "exchange_frames", test_frames ) ||
            NULL == CU_add_test( suite, "destroy_cloud", test_destroy_dummy_cloud ) ||
            NULL == CU_add_test( suite, "memoryLeaks", test_memoryLeaks ) )
        {
            ret = 0;
        }
    }

    CU_basic_run_tests();

    CU_cleanup_registry();

    rpal_Context_deinitialize();

    return ret;
}

