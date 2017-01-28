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

#include <rpal/rpal.h>
#include <rpHostCommonPlatformLib/rpHostCommonPlatformLib.h>

#ifdef RPAL_PLATFORM_LINUX
#include <signal.h>
#elif defined( RPAL_PLATFORM_MACOSX )
#include <mach-o/dyld.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif


#ifdef RPAL_PLATFORM_DEBUG
#ifndef HCP_EXE_ENABLE_MANUAL_LOAD
#define HCP_EXE_ENABLE_MANUAL_LOAD
#endif
#endif

static rEvent g_timeToQuit = NULL;



#ifdef RPAL_PLATFORM_WINDOWS
BOOL
    ctrlHandler
    (
        DWORD type
    )
{
    BOOL isHandled = FALSE;

    static RU32 isHasBeenSignaled = 0;
    
    UNREFERENCED_PARAMETER( type );

    if( 0 == rInterlocked_set32( &isHasBeenSignaled, 1 ) )
    {
        // We handle all events the same way, cleanly exit
    
        rpal_debug_info( "terminating rpHCP." );
        rpHostCommonPlatformLib_stop();
    
        rEvent_set( g_timeToQuit );
    
        isHandled = TRUE;
    }

    return isHandled;
}

RBOOL
    isLaunchedInteractively
    (

    )
{
    RBOOL isInteractive = FALSE;
    HANDLE stdHandle = NULL;
    CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };

    if( INVALID_HANDLE_VALUE != ( stdHandle = GetStdHandle( STD_OUTPUT_HANDLE ) ) &&
        GetConsoleScreenBufferInfo( stdHandle, &csbi ) &&
        0 == csbi.dwCursorPosition.X && 
        0 == csbi.dwCursorPosition.Y )
    {
        isInteractive = TRUE;
    }

    return isInteractive;
}

#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
void
    ctrlHandler
    (
        int sigNum
    )
{
    static RU32 isHasBeenSignaled = 0;
    
    if( 0 == rInterlocked_set32( &isHasBeenSignaled, 1 ) )
    {
        rpal_debug_info( "terminating rpHCP." );
        rpHostCommonPlatformLib_stop();
        rEvent_set( g_timeToQuit );
    }
}
#endif

#ifdef RPAL_PLATFORM_WINDOWS


#define _SERVICE_NAME _WCH( "rphcpsvc" )
#define _SERVICE_NAMEW _WCH( "rphcpsvc" )
static SERVICE_STATUS g_svc_status = { 0 };
static SERVICE_STATUS_HANDLE g_svc_status_handle = NULL;
static RPNCHAR g_svc_primary = NULL;
static RPNCHAR g_svc_secondary = NULL;
static RPNCHAR g_svc_mod = NULL;
static RU32 g_svc_mod_id = 0;

static
RU32
    installService
    (

    )
{
    HMODULE hModule = NULL;
    RWCHAR curPath[ RPAL_MAX_PATH ] = { 0 };
    RWCHAR destPath[] = _WCH( "%SYSTEMROOT%\\system32\\rphcp.exe" );
    RWCHAR svcPath[] = _WCH( "\"%SYSTEMROOT%\\system32\\rphcp.exe\" -w" );
    SC_HANDLE hScm = NULL;
    SC_HANDLE hSvc = NULL;
    RWCHAR svcName[] = { _SERVICE_NAMEW };
    RWCHAR svcDisplay[] = { _WCH( "rp_HCP_Svc" ) };

    rpal_debug_info( "installing service" );

    hModule = GetModuleHandleW( NULL );
    if( NULL != hModule )
    {
        if( ARRAY_N_ELEM( curPath ) > GetModuleFileNameW( hModule, curPath, ARRAY_N_ELEM( curPath ) ) )
        {
            if( rpal_file_copy( curPath, destPath ) )
            {
                if( NULL != ( hScm = OpenSCManagerA( NULL, NULL, SC_MANAGER_CREATE_SERVICE ) ) )
                {
                    if( NULL != ( hSvc = CreateServiceW( hScm,
                                                         svcName,
                                                         svcDisplay,
                                                         SERVICE_ALL_ACCESS,
                                                         SERVICE_WIN32_OWN_PROCESS,
                                                         SERVICE_AUTO_START,
                                                         SERVICE_ERROR_NORMAL,
                                                         svcPath,
                                                         NULL,
                                                         NULL,
                                                         NULL,
                                                         NULL,
                                                         _WCH( "" ) ) ) )
                    {
                        if( StartService( hSvc, 0, NULL ) )
                        {
                            // Emitting as error level to make sure it's displayed in release.
                            rpal_debug_error( "service installer!" );
                            return 0;
                        }
                        else
                        {
                            rpal_debug_error( "could not start service: %d", GetLastError() );
                        }

                        CloseServiceHandle( hSvc );
                    }
                    else
                    {
                        rpal_debug_error( "could not create service in SCM: %d", GetLastError() );
                    }

                    CloseServiceHandle( hScm );
                }
                else
                {
                    rpal_debug_error( "could not open SCM: %d", GetLastError() );
                }
            }
            else
            {
                rpal_debug_error( "could not move executable to service location: %d", GetLastError() );
            }
        }
        else
        {
            rpal_debug_error( "could not get current executable path: %d", GetLastError() );
        }

        CloseHandle( hModule );
    }
    else
    {
        rpal_debug_error( "could not get current executable handle: %d", GetLastError() );
    }
    
    return GetLastError();
}

static
RU32
    uninstallService
    (

    )
{
    RWCHAR destPath[] = _WCH( "%SYSTEMROOT%\\system32\\rphcp.exe" );
    SC_HANDLE hScm = NULL;
    SC_HANDLE hSvc = NULL;
    RWCHAR svcName[] = { _SERVICE_NAMEW };
    SERVICE_STATUS svcStatus = { 0 };
    RU32 nRetries = 10;

    rpal_debug_info( "uninstalling service" );

    if( NULL != ( hScm = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS ) ) )
    {
        if( NULL != ( hSvc = OpenServiceW( hScm, svcName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE ) ) )
        {
            if( ControlService( hSvc, SERVICE_CONTROL_STOP, &svcStatus ) )
            {
                while( SERVICE_STOPPED != svcStatus.dwCurrentState &&
                       0 != nRetries )
                {
                    rpal_debug_error( "waiting for service to stop..." );
                    rpal_thread_sleep( 1000 );

                    if( !QueryServiceStatus( hSvc, &svcStatus ) )
                    {
                        break;
                    }

                    nRetries--;
                }

                if( 0 == nRetries )
                {
                    rpal_debug_error( "timed out waiting for service to stop, moving on..." );
                }
                else
                {
                    rpal_debug_info( "service stopped" );
                }
            }
            else
            {
                rpal_debug_error( "could not stop service: %d", GetLastError() );
            }

            if( DeleteService( hSvc ) )
            {
                rpal_debug_info( "service deleted" );
            }
            else
            {
                rpal_debug_error( "could not delete service: %d", GetLastError() );
            }

            CloseServiceHandle( hSvc );
        }
        else
        {
            rpal_debug_error( "could not open service: %d", GetLastError() );
        }

        CloseServiceHandle( hScm );
    }
    else
    {
        rpal_debug_error( "could not open SCM: %d", GetLastError() );
    }

    rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );

    if( rpal_file_delete( destPath, FALSE ) )
    {
        rpal_debug_info( "service executable deleted" );
    }
    else
    {
        rpal_debug_error( "could not delete service executable: %d", GetLastError() );
    }

    return GetLastError();
}

static
VOID WINAPI 
    SvcCtrlHandler
    (
        DWORD fdwControl
    )
{
    switch( fdwControl )
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:

            if( g_svc_status.dwCurrentState != SERVICE_RUNNING )
                break;

            /*
            * Perform tasks necessary to stop the service here
            */

            g_svc_status.dwControlsAccepted = 0;
            g_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
            g_svc_status.dwWin32ExitCode = 0;
            g_svc_status.dwCheckPoint = 2;

            SetServiceStatus( g_svc_status_handle, &g_svc_status );

            rpal_debug_info( "terminating rpHCP." );
            rpHostCommonPlatformLib_stop();

            rEvent_set( g_timeToQuit );

            break;

        default:
            break;
    }
}

static
VOID WINAPI 
    ServiceMain
    (
        DWORD  dwArgc,
        RPCHAR lpszArgv
    )
{
    RU32 memUsed = 0;
    RWCHAR svcName[] = { _SERVICE_NAME };

    UNREFERENCED_PARAMETER( dwArgc );
    UNREFERENCED_PARAMETER( lpszArgv );


    if( NULL == ( g_svc_status_handle = RegisterServiceCtrlHandlerW( svcName, SvcCtrlHandler ) ) )
    {
        return;
    }

    rpal_memory_zero( &g_svc_status, sizeof( g_svc_status ) );
    g_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwControlsAccepted = 0;
    g_svc_status.dwCurrentState = SERVICE_START_PENDING;
    g_svc_status.dwWin32ExitCode = 0;
    g_svc_status.dwServiceSpecificExitCode = 0;
    g_svc_status.dwCheckPoint = 0;
    SetServiceStatus( g_svc_status_handle, &g_svc_status );

    if( NULL == ( g_timeToQuit = rEvent_create( TRUE ) ) )
    {
        g_svc_status.dwControlsAccepted = 0;
        g_svc_status.dwCurrentState = SERVICE_STOPPED;
        g_svc_status.dwWin32ExitCode = GetLastError();
        g_svc_status.dwCheckPoint = 1;
        SetServiceStatus( g_svc_status_handle, &g_svc_status );
        return;
    }

    rpal_debug_info( "initialising rpHCP." );
    if( !rpHostCommonPlatformLib_launch( g_svc_primary, g_svc_secondary ) )
    {
        rpal_debug_warning( "error launching hcp." );
    }

    if( NULL != g_svc_mod )
    {
#ifdef HCP_EXE_ENABLE_MANUAL_LOAD
        rpHostCommonPlatformLib_load( g_svc_mod, g_svc_mod_id );
#endif
        rpal_memory_free( g_svc_mod );
    }

    g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svc_status.dwCurrentState = SERVICE_RUNNING;
    g_svc_status.dwWin32ExitCode = 0;
    g_svc_status.dwCheckPoint = 1;
    SetServiceStatus( g_svc_status_handle, &g_svc_status );

    rpal_debug_info( "...running, waiting to exit..." );
    rEvent_wait( g_timeToQuit, RINFINITE );
    rEvent_free( g_timeToQuit );

    if( rpal_memory_isValid( g_svc_mod ) )
    {
        rpal_memory_free( g_svc_mod );
    }

    rpal_debug_info( "...exiting..." );
    rpal_Context_cleanup();

    memUsed = rpal_memory_totalUsed();
    if( 0 != memUsed )
    {
        rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
        //rpal_memory_findMemory();
#ifdef RPAL_FEATURE_MEMORY_ACCOUNTING
        rpal_memory_printDetailedUsage();
#endif
    }

    g_svc_status.dwControlsAccepted = 0;
    g_svc_status.dwCurrentState = SERVICE_STOPPED;
    g_svc_status.dwWin32ExitCode = 0;
    g_svc_status.dwCheckPoint = 3;
    SetServiceStatus( g_svc_status_handle, &g_svc_status );
}

#elif defined( RPAL_PLATFORM_MACOSX )

#define _SERVICE_DESC_FILE  _NC("/Library/LaunchDaemons/com.refractionpoint.rphcp.plist")
#define _SERVICE_NAME       _NC("com.refractionpoint.rphcp")
#define _SERVICE_DIR        _NC("/usr/local/bin/")
#define _SERVICE_FILE       _NC("/usr/local/bin/rphcp")
#define _SERVICE_LOAD       _NC("launchctl load ") _SERVICE_DESC_FILE
#define _SERVICE_START      _NC("launchctl start ") _SERVICE_NAME
#define _SERVICE_UNLOAD     _NC("launchctl unload ") _SERVICE_DESC_FILE
#define _SERVICE_DESC       _NC("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
<plist version=\"1.0\">\
    <dict>\
        <key>Label</key>\
        <string>com.refractionpoint.rphcp</string>\
        <key>ProgramArguments</key>\
        <array>\
            <string>/usr/local/bin/rphcp</string>\
        </array>\
        <key>KeepAlive</key>\
        <true/>\
    </dict>\
</plist>\
")

static
RU32
    installService
    (

    )
{
    RU32 res = (RU32)-1;

    RNCHAR currentPath[ RPAL_MAX_PATH ] = {0};
    RU32 currentPathSize = sizeof( currentPath );
    RNCHAR svcDir[] = { _SERVICE_DIR };
    RNCHAR svcPath[] = { _SERVICE_FILE };
    RNCHAR svcDescPath[] = { _SERVICE_DESC_FILE };
    RNCHAR svcDesc[] = { _SERVICE_DESC };
    RBOOL isOnDisk = FALSE;
    RNCHAR svcLoad[] = { _SERVICE_LOAD };
    RNCHAR svcStart[] = { _SERVICE_START };

    if( 0 == _NSGetExecutablePath( currentPath, &currentPathSize ) )
    {
        if( rDir_create( svcDir ) )
        {
            chmod( svcDir, S_IRWXU );
        }

        if( rpal_file_copy( currentPath, svcPath ) )
        {
            if( 0 != chmod( svcPath, S_IRWXU ) )
            {
                rpal_debug_warning( "could not set restricted permissions on executable" );
            }

            if( rpal_file_write( svcDescPath, svcDesc, rpal_string_strlen( svcDesc ), TRUE ) )
            {
                if( 0 != chmod( svcDescPath, S_IRWXU ) )
                {
                    rpal_debug_warning( "could not set restricted permissions on service descriptor" );
                }

                isOnDisk = TRUE;
            }
            else
            {
                rpal_debug_error( "could not write service descriptor" );
            }
        }
        else
        {
            rpal_debug_error( "could not copy executable to service location" );
        }
    }
    else
    {
        rpal_debug_error( "could not get current executable path" );
    }

    if( isOnDisk )
    {
        if( 0 != system( svcLoad ) )
        {
            rpal_debug_warning( "failed to load service, already exists?" );
        }

        if( 0 != system( svcStart ) )
        {
            rpal_debug_warning( "failed to start service, already running?" );
        }
        else
        {
            rpal_debug_info( "successfully installed" );
            res = 0;
        }
    }

    return res;
}

static
RU32
    uninstallService
    (

    )
{
    RU32 res = (RU32)-1;

    RNCHAR svcUnload[] = { _SERVICE_UNLOAD };
    RNCHAR svcPath[] = { _SERVICE_FILE };

    if( 0 != system( svcUnload ) )
    {
        rpal_debug_warning( "failed to unload service, already unloaded?" );
    }

    if( !rpal_file_delete( svcPath, FALSE ) )
    {
        rpal_debug_warning( "failed to delete file from disk, not present?" );
    }
    else
    {
        rpal_debug_info( "uninstalled successfully" );
        res = 0;
    }

    return res;
}

#endif


RPAL_NATIVE_MAIN
{
    RNCHAR argFlag = 0;
    RPNCHAR argVal = NULL;
    RPNCHAR primary = NULL;
    RPNCHAR secondary = NULL;
    RPNCHAR tmpMod = NULL;
    RU32 tmpModId = 0;
    RU32 memUsed = 0;
    RBOOL asService = FALSE;
    RBOOL isArgumentsSpecified = FALSE;

    rpal_opt switches[] = { { _NC( 'h' ), _NC( "help" ), FALSE },
                            { _NC( 'p' ), _NC( "primary" ), TRUE },
                            { _NC( 's' ), _NC( "secondary" ), TRUE },
                            { _NC( 'm' ), _NC( "manual" ), TRUE },
                            { _NC( 'n' ), _NC( "moduleId" ), TRUE }
#ifdef RPAL_PLATFORM_WINDOWS
                            ,
                            { _NC( 'i' ), _NC( "install" ), FALSE },
                            { _NC( 'r' ), _NC( "uninstall" ), FALSE },
                            { _NC( 'w' ), _NC( "service" ), FALSE }
#elif defined( RPAL_PLATFORM_MACOSX )
                            ,
                            { _NC( 'i' ), _NC( "install" ), FALSE },
                            { _NC( 'r' ), _NC( "uninstall" ), FALSE }
#endif
                          };

    if( rpal_initialize( NULL, 0 ) )
    {
        while( (RNCHAR)-1 != ( argFlag = rpal_getopt( argc, argv, switches, &argVal ) ) )
        {
            switch( argFlag )
            {
                case _NC( 'p' ):
                    primary = argVal;
                    rpal_debug_info( "Setting primary URL: %s.", primary );
                    isArgumentsSpecified = TRUE;
                    break;
                case _NC( 's' ):
                    secondary = argVal;
                    rpal_debug_info( "Setting secondary URL: %s.", secondary );
                    isArgumentsSpecified = TRUE;
                    break;
                case _NC( 'm' ):
                    tmpMod = rpal_string_strdup( argVal );
                    rpal_debug_info( "Manually loading module: %s.", argVal );
                    isArgumentsSpecified = TRUE;
                    break;
                case _NC( 'n' ):
                    if( rpal_string_stoi( argVal, &tmpModId ) )
                    {
                        rpal_debug_info( "Manually loaded module id is: %d", tmpModId );
                    }
                    else
                    {
                        rpal_debug_warning( "Module id provided is invalid." );
                    }
                    isArgumentsSpecified = TRUE;
                    break;
#ifdef RPAL_PLATFORM_WINDOWS
                case _NC( 'i' ):
                    return installService();
                    break;
                case _NC( 'r' ):
                    return uninstallService();
                    break;
                case _NC( 'w' ):
                    asService = TRUE;
                    isArgumentsSpecified = TRUE;
                    break;
#elif defined( RPAL_PLATFORM_MACOSX )
                case _NC( 'i' ):
                    return installService();
                    break;
                case _NC( 'r' ):
                    return uninstallService();
                    break;
#endif
                case _NC( 'h' ):
                default:
#ifdef RPAL_PLATFORM_DEBUG
                    printf( "Usage: %s [ -p primaryHomeUrl ] [ -s secondaryHomeUrl ] [ -m moduleToLoad ] [ -h ].\n", argv[ 0 ] );
                    printf( "-p: primary Url used to communicate home.\n" );
                    printf( "-s: secondary Url used to communicate home if the primary failed.\n" );
                    printf( "-m: module to be loaded manually, only available in debug builds.\n" );
                    printf( "-n: the module id of the module being manually loaded.\n" );
#ifdef RPAL_PLATFORM_WINDOWS
                    printf( "-i: install executable as a service.\n" );
                    printf( "-r: uninstall executable as a service.\n" );
                    printf( "-w: executable is running as a Windows service.\n" );
#elif defined( RPAL_PLATFORM_MACOSX )
                    printf( "-i: install executable as a service.\n" );
                    printf( "-r: uninstall executable as a service.\n" );
#endif
                    printf( "-h: this help.\n" );
                    return 0;
#endif
                    break;
            }
        }

#ifdef RPAL_PLATFORM_WINDOWS
        if( asService )
        {
            RWCHAR svcName[] = { _SERVICE_NAME };
            SERVICE_TABLE_ENTRYW DispatchTable[] =
            {
                { NULL, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
                { NULL, NULL }
            };

            DispatchTable[ 0 ].lpServiceName = svcName;

            g_svc_primary = primary;
            g_svc_secondary = secondary;
            g_svc_mod = tmpMod;
            g_svc_mod_id = tmpModId;
            if( !StartServiceCtrlDispatcherW( DispatchTable ) )
            {
                return GetLastError();
            }
            else
            {
                return 0;
            }
        }

        if( !isArgumentsSpecified &&
            isLaunchedInteractively() )
        {
            // If launched via a double-click, we assume it's an installation.
            rpal_debug_info( "Launched interactively, installing." );
            return installService();
        }
#endif

        rpal_debug_info( "initialising rpHCP." );
        if( !rpHostCommonPlatformLib_launch( primary, secondary ) )
        {
            rpal_debug_warning( "error launching hcp." );
        }

        if( NULL == ( g_timeToQuit = rEvent_create( TRUE ) ) )
        {
            rpal_debug_error( "error creating quit event." );
            return -1;
        }

#ifdef RPAL_PLATFORM_WINDOWS
        if( !SetConsoleCtrlHandler( (PHANDLER_ROUTINE)ctrlHandler, TRUE ) )
        {
            rpal_debug_error( "error registering control handler function." );
            return -1;
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( SIG_ERR == signal( SIGINT, ctrlHandler ) )
        {
            rpal_debug_error( "error setting signal handler" );
            return -1;
        }
#endif

        if( NULL != tmpMod )
        {
#ifdef HCP_EXE_ENABLE_MANUAL_LOAD
            rpHostCommonPlatformLib_load( tmpMod, tmpModId );
#endif
            rpal_memory_free( tmpMod );
        }

        rpal_debug_info( "...running, waiting to exit..." );
        rEvent_wait( g_timeToQuit, RINFINITE );
        rEvent_free( g_timeToQuit );
        
        rpal_debug_info( "...exiting..." );
        rpal_Context_cleanup();

        memUsed = rpal_memory_totalUsed();
        if( 0 != memUsed )
        {
            rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
            //rpal_memory_findMemory();
#ifdef RPAL_FEATURE_MEMORY_ACCOUNTING
            rpal_memory_printDetailedUsage();
#endif
        }
        
        rpal_Context_deinitialize();
    }

    return 0;
}
