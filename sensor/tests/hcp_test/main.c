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
rEvent g_serverStop = NULL;
rEvent g_isClean = NULL;

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
    if( 0 != ( serverSock = NetLib_TcpListen( "localhost", g_server_port ) ) )
    {
        while( !rEvent_wait( g_serverStop, 0 ) )
        {
            if( 0 != ( clientSock = NetLib_TcpAccept( serverSock, g_serverStop, 0 ) ) )
            {
                hcpCtx.session.symSendCtx = CryptoLib_symEncInitContext( g_key, g_iv );
                hcpCtx.session.symRecvCtx = CryptoLib_symDecInitContext( g_key, g_iv );
                hcpCtx.cloudConnection = clientSock;

                while( recvFrame( &hcpCtx, &moduleId, &messages, 2 ) )  // Tested function
                {
                    sendFrame( &hcpCtx, moduleId, messages, TRUE );   // Tested function
                    rList_free( messages );
                }

                NetLib_TcpDisconnect( clientSock );

                CryptoLib_symFreeContext( hcpCtx.session.symSendCtx );
                CryptoLib_symFreeContext( hcpCtx.session.symRecvCtx );
            }
        }

        NetLib_TcpDisconnect( serverSock );
    }

    rEvent_set( g_isClean );
    
    return 0;
}

RBOOL
    getConnectionToServer
    (
        rpHCPContext* hcpCtx
    )
{
    RBOOL isConnected = FALSE;

    hcpCtx->cloudConnection = NetLib_TcpConnect( "localhost", g_server_port );
    CU_ASSERT_NOT_EQUAL_FATAL( hcpCtx->cloudConnection, 0 );

    hcpCtx->session.symRecvCtx = CryptoLib_symDecInitContext( g_key, g_iv );
    hcpCtx->session.symSendCtx = CryptoLib_symEncInitContext( g_key, g_iv );

    CU_ASSERT_NOT_EQUAL_FATAL( hcpCtx->session.symRecvCtx, NULL );
    CU_ASSERT_NOT_EQUAL_FATAL( hcpCtx->session.symSendCtx, NULL );

    isConnected = TRUE;

    return isConnected;
}

RVOID
    closeConnectionToServer
    (
        rpHCPContext* hcpCtx
    )
{
    CryptoLib_symFreeContext( hcpCtx->session.symRecvCtx );
    CryptoLib_symFreeContext( hcpCtx->session.symSendCtx );

    NetLib_TcpDisconnect( hcpCtx->cloudConnection );
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
    rThread hThread = NULL;

    g_isClean = rEvent_create( TRUE );
    CU_ASSERT_NOT_EQUAL_FATAL( g_isClean, NULL );
    g_serverStop = rEvent_create( TRUE );
    CU_ASSERT_NOT_EQUAL( g_serverStop, NULL );
    CU_ASSERT_TRUE_FATAL( CryptoLib_init() );

    // Setup cloud connectivity
    CU_ASSERT_TRUE_FATAL( CryptoLib_genRandomBytes( g_key, sizeof( g_key ) ) );
    CU_ASSERT_TRUE_FATAL( CryptoLib_genRandomBytes( g_iv, sizeof( g_iv ) ) );

    hThread = rpal_thread_new( threadServer, NULL );
    rpal_thread_free( hThread );
    rpal_thread_sleep( 2000 );
}

void test_destroy_dummy_cloud( void )
{
    rEvent_set( g_serverStop );
    CryptoLib_deinit();
    rEvent_wait( g_isClean, RINFINITE );
    rEvent_free( g_isClean );
    g_isClean = NULL;
    rEvent_free( g_serverStop );
    g_serverStop = NULL;
}

void test_frames( void )
{
    RpHcp_ModuleId moduleId = 1;
    RpHcp_ModuleId outMod = 0;
    rList messages = NULL;
    rList outMessages = NULL;
    RPU8 garbage = NULL;
    RU32 garbageMaxSize = 1024;
    RU32 garbageSize = 0;
    RU32 garbageLoops = 100;
    rBlob blob = NULL;
    
    // Create and test frames
    messages = rList_new( 1, RPCM_STRINGA );
    CU_ASSERT_NOT_EQUAL_FATAL( messages, NULL );

    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str1" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str2" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str3" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str4" ) );

    blob = wrapFrame( moduleId, messages, TRUE );
    CU_ASSERT_NOT_EQUAL_FATAL( blob, NULL );

    CU_ASSERT( unwrapFrame( blob, &outMod, &outMessages ) );
    rpal_blob_free( blob );
    CU_ASSERT_EQUAL( outMod, moduleId );
    CU_ASSERT_NOT_EQUAL_FATAL( outMessages, NULL );

    CU_ASSERT_EQUAL( rList_getNumElements( outMessages ), rList_getNumElements( messages ) );
    CU_ASSERT_TRUE( rList_isEqual( messages, outMessages ) );

    rList_free( messages );
    rList_free( outMessages );
    
    // Fuzz the unwrapping function.
    for( garbageLoops = garbageLoops; 0 != garbageLoops; garbageLoops-- )
    {
        garbageSize = ( rpal_rand() % garbageMaxSize ) + 1;
        garbage = rpal_memory_alloc( garbageSize );
        CU_ASSERT_NOT_EQUAL_FATAL( garbage, NULL );
        CU_ASSERT_TRUE( CryptoLib_genRandomBytes( garbage, garbageSize ) );
        
        blob = rpal_blob_createFromBuffer( garbage, garbageSize );
        CU_ASSERT_NOT_EQUAL_FATAL( blob, NULL );

        CU_ASSERT_FALSE( unwrapFrame( blob, &outMod, &outMessages ) );

        rpal_blob_free( blob );
    }
}

void test_exchange_frames( void )
{
    rpHCPContext hcpCtx = { 0 };
    RpHcp_ModuleId moduleId = 1;
    RpHcp_ModuleId outMod = 0;
    rList messages = NULL;
    rList outMessages = NULL;
    RU8 garbage[ 1024 ] = { 0 };
    RU32 garbageSize = 0;
    RU32 tmpFrameSize = 0;
    RU32 garbageLoops = 100;
    
    // Connect to the fake server
    getConnectionToServer( &hcpCtx );

    // Create and test frames
    messages = rList_new( 1, RPCM_STRINGA );
    CU_ASSERT_NOT_EQUAL_FATAL( messages, NULL );

    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str1" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str2" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str3" ) );
    CU_ASSERT_TRUE_FATAL( rList_addSTRINGA( messages, "str4" ) );

    CU_ASSERT_TRUE( sendFrame( &hcpCtx, moduleId, messages, TRUE ) );
    
    CU_ASSERT_TRUE( recvFrame( &hcpCtx, &outMod, &outMessages, 5 ) );
    CU_ASSERT_EQUAL( outMod, moduleId );

    CU_ASSERT_EQUAL( rList_getNumElements( outMessages ), rList_getNumElements( messages ) );
    CU_ASSERT_TRUE( rList_isEqual( messages, outMessages ) );
    
    rList_free( messages );
    rList_free( outMessages );

    closeConnectionToServer( &hcpCtx );

    // Send over garbage and check we don't crash or get anything back
    for( garbageLoops = garbageLoops; 0 != garbageLoops; garbageLoops-- )
    {
        getConnectionToServer( &hcpCtx );

        garbageSize = rpal_rand() % sizeof( garbage );
        CU_ASSERT_TRUE( CryptoLib_genRandomBytes( garbage, garbageSize ) );
        CU_ASSERT_TRUE( NetLib_TcpSend( hcpCtx.cloudConnection, garbage, garbageSize, NULL ) );
        CU_ASSERT_FALSE( NetLib_TcpReceive( hcpCtx.cloudConnection, &tmpFrameSize, sizeof( tmpFrameSize ), NULL, 2 ) );

        closeConnectionToServer( &hcpCtx );
    }
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

    if( NULL != ( suite = CU_add_suite( "hcp", NULL, NULL ) ) )
    {
        if( NULL == CU_add_test( suite, "create_cloud", test_create_dummy_cloud ) ||
            NULL == CU_add_test( suite, "frames", test_frames ) ||
            NULL == CU_add_test( suite, "exchange_frames", test_exchange_frames ) ||
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

