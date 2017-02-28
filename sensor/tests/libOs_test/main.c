#include <rpal/rpal.h>
#include <libOs/libOs.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <Basic.h>

#define RPAL_FILE_ID      86


#ifdef RPAL_PLATFORM_WINDOWS
static RBOOL 
    SetPrivilege
    (
        HANDLE hToken, 
        LPCTSTR lpszPrivilege, 
        BOOL bEnablePrivilege
    )
{
    LUID luid;
    RBOOL bRet = FALSE;

    if( LookupPrivilegeValue( NULL, lpszPrivilege, &luid ) )
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if( AdjustTokenPrivileges( hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL ) )
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet = ( GetLastError() == ERROR_SUCCESS );
        }
    }
    return bRet;
}


static RBOOL
	Get_Privilege
	(
		RPCHAR privName
	)
{
	RBOOL isSuccess = FALSE;

	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;

	hProcess = GetCurrentProcess();

	if( NULL != hProcess )
	{
		if( OpenProcessToken( hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken ) )
		{
			if( SetPrivilege( hToken, privName, TRUE ) )
			{
				isSuccess = TRUE;
			}
			
			CloseHandle( hToken );
		}
	}

	return isSuccess;
}
#endif


void 
	parseSignature
	( 
	    rSequence signature  
	)
{
	RPNCHAR strBuffer = NULL;
	RPNCHAR wStrBuffer = NULL;
	RU32   signatureStatus = 0;
	RU32   byteBufferSize = 0;
	RU8*   byteBuffer = NULL;

	CU_ASSERT_TRUE( rSequence_getSTRINGN( signature, RP_TAGS_FILE_PATH, &wStrBuffer ) );
	CU_ASSERT_TRUE( rSequence_getRU32( signature, RP_TAGS_CERT_CHAIN_STATUS, &signatureStatus ) );
	if( rSequence_getSTRINGN( signature, RP_TAGS_CERT_ISSUER, &strBuffer ) )
	{
		CU_ASSERT_TRUE( 0 < rpal_string_strsize( strBuffer ) );
	}
		
	if( rSequence_getSTRINGN( signature, RP_TAGS_CERT_SUBJECT, &strBuffer ) )
	{
		CU_ASSERT_TRUE( 0 < rpal_string_strsize( strBuffer ) );
	}
	
	if( rSequence_getBUFFER( signature, RP_TAGS_CERT_BUFFER, &byteBuffer, &byteBufferSize ) )
	{
		CU_ASSERT_TRUE( 0 < byteBufferSize );
		CU_ASSERT_PTR_NOT_EQUAL_FATAL( byteBuffer, NULL );
	}
}


void
	test_signCheck
	(
	    void
	)
{
    rList filePaths = NULL;
	RPWCHAR filePath = NULL;
	rSequence fileSignature = NULL;
	RU32 operationFlags = OSLIB_SIGNCHECK_NO_NETWORK | OSLIB_SIGNCHECK_CHAIN_VERIFICATION | OSLIB_SIGNCHECK_INCLUDE_RAW_CERT;
	RBOOL isSigned = FALSE;
	RBOOL isVerified_local = FALSE;
	RBOOL isVerified_global = FALSE;

	filePaths = rList_new( RP_TAGS_FILE_PATH, RPCM_STRINGW );
	CU_ASSERT_PTR_NOT_EQUAL_FATAL( filePaths, NULL );

#ifdef RPAL_PLATFORM_WINDOWS
	// Windows signed file
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\system32\\Taskmgr.exe" ) );
	rList_addSTRINGW( filePaths, _WCH( "C:\\Program Files\\Internet Explorer\\iexplore.exe" ) );

	// Catalogs files
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\explorer.exe" ) );
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\system32\\calc.exe" ) );
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\system32\\cmd.exe" ) );
#endif

    while( rList_getSTRINGW( filePaths, RP_TAGS_FILE_PATH, &filePath ) )
	{
		if( libOs_getSignature( filePath, &fileSignature, operationFlags, &isSigned, &isVerified_local, &isVerified_global ) )
		{
			CU_ASSERT_PTR_NOT_EQUAL_FATAL( fileSignature, NULL );

			if ( isSigned )
			{
				parseSignature( fileSignature );
			}

			rSequence_free( fileSignature );
			fileSignature = NULL;
		}
	}
    rList_free( filePaths );
}


void
    test_services
    (
        void
    )
{
    rList svcs = NULL;
    rSequence svc = NULL;
    RPNCHAR svcName = NULL;

    svcs = libOs_getServices( TRUE );

    CU_ASSERT_PTR_NOT_EQUAL_FATAL( svcs, NULL );

    CU_ASSERT_TRUE( rList_getSEQUENCE( svcs, RP_TAGS_SVC, &svc ) );

    CU_ASSERT_TRUE( rSequence_getSTRINGN( svc, RP_TAGS_SVC_NAME, &svcName ) );

    CU_ASSERT_PTR_NOT_EQUAL( svcName, NULL );

    CU_ASSERT_NOT_EQUAL( rpal_string_strlen( svcName ), 0 );

    rSequence_free( svcs );
}

int
    main
    (
        int argc,
        char* argv[]
    )
{
    int ret = -1;
    
    CU_pSuite suite = NULL;
    CU_ErrorCode error = 0;

#ifdef RPAL_PLATFORM_WINDOWS
    RCHAR strSeDebug[] = "SeDebugPrivilege";
    Get_Privilege( strSeDebug );
#endif
    UNREFERENCED_PARAMETER( argc );
    UNREFERENCED_PARAMETER( argv );

    if( rpal_initialize( NULL, 1 ) )
    {
        if( CUE_SUCCESS == ( error = CU_initialize_registry() ) )
        {
            if( NULL != ( suite = CU_add_suite( "libOs", NULL, NULL ) ) )
            {
                if( NULL == CU_add_test( suite, "signCheck", test_signCheck ) ||
                    NULL == CU_add_test( suite, "services", test_services ) )
                {
                    rpal_debug_error( "%s", CU_get_error_msg() );
                }
                else
                {
                    CU_basic_run_tests();
                    ret = CU_get_number_of_failures();
                }
            }

            CU_cleanup_registry();
        }
        else
        {
            rpal_debug_error( "could not init cunit: %d", error );
        }

        rpal_Context_deinitialize();
    }
    else
    {
        printf( "error initializing rpal" );
    }

    return ret;
}

