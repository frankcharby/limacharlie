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


#define RPAL_FILE_ID                  97

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

RPRIVATE HbsState* g_hbsStateRef = NULL;

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_14_events[] = { 0 };

RBOOL
    collector_14_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );
    UNREFERENCED_PARAMETER( hbsState );

    return isSuccess;
}

RBOOL
    collector_14_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( config );

    return isSuccess;
}

//=============================================================================
//  Collector Testing
//=============================================================================
HBS_TEST_SUITE( 14 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}