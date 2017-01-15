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
#include "helpers.h"
#include <kernelAcquisitionLib/common.h>

#pragma warning(disable:4127)       // constant expressions

#define _NUM_BUFFERED_CONNECTIONS 200

typedef struct
{
    RPWCHAR slName;
    RPWCHAR coName;
    RPWCHAR flName;
    FWPS_CALLOUT_CLASSIFY_FN co;
    GUID guid;
    GUID slGuid;
    RBOOL slActive;
    GUID coGuid;
    RBOOL coActive;
    GUID flGuid;
    RBOOL flActive;
} LayerInfo;

RVOID
    coAuthConnect
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    );

RVOID
    coAuthRecvAccept
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    );

static LayerInfo g_layerAuthConnect4 = {
    _WCH( "slAuthConnect4" ),
    _WCH( "coAuthConnect4" ),
    _WCH( "flAuthConnect4" ),
    coAuthConnect
};

static LayerInfo g_layerAuthConnect6 = {
    _WCH( "slAuthConnect6" ),
    _WCH( "coAuthConnect6" ),
    _WCH( "flAuthConnect6" ),
    coAuthConnect
};

static LayerInfo g_layerAuthRecvAccept4 = {
    _WCH( "slAuthRecvAccept4" ),
    _WCH( "coAuthRecvAccept4" ),
    _WCH( "flAuthRecvAccept4" ),
    coAuthRecvAccept
};

static LayerInfo g_layerAuthRecvAccept6 = {
    _WCH( "slAuthRecvAccept6" ),
    _WCH( "coAuthRecvAccept6" ),
    _WCH( "flAuthRecvAccept6" ),
    coAuthRecvAccept
};

static LayerInfo* g_layers[] = { &g_layerAuthConnect4,
                                 &g_layerAuthConnect6,
                                 &g_layerAuthRecvAccept4,
                                 &g_layerAuthRecvAccept6 };

static HANDLE g_stateChangeHandle = NULL;
static HANDLE g_engineHandle = NULL;

static KSPIN_LOCK g_collector_4_mutex = { 0 };
static KernelAcqNetwork g_connections[ _NUM_BUFFERED_CONNECTIONS ] = { 0 };
static RU32 g_nextConnection = 0;

RBOOL
    task_get_new_network
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    RU32 toCopy = 0;

    UNREFERENCED_PARAMETER( pArgs );
    UNREFERENCED_PARAMETER( argsSize );

    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

        toCopy = ( *resultSize ) / sizeof( g_connections[ 0 ] );

        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextConnection ? g_nextConnection : toCopy );

            *resultSize = toCopy * sizeof( g_connections[ 0 ] );
            memcpy( pResult, g_connections, *resultSize );

            g_nextConnection -= toCopy;
            memmove( g_connections, g_connections + toCopy, g_nextConnection );
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}

static NTSTATUS
    getIpTuple
    (
        RU16 layerId,
        const FWPS_INCOMING_VALUES* fixedVals,
        KernelAcqNetwork* netEntry
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    switch( layerId )
    {
        case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
            netEntry->isIncoming = FALSE;
            netEntry->srcIp.isV6 = FALSE;
            netEntry->dstIp.isV6 = FALSE;
            netEntry->srcIp.value.v4 = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS ].value.uint32;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v4 = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS ].value.uint32;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
            netEntry->isIncoming = FALSE;
            netEntry->srcIp.isV6 = TRUE;
            netEntry->dstIp.isV6 = TRUE;
            netEntry->srcIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS ].value.byteArray16;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS ].value.byteArray16;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
            netEntry->isIncoming = TRUE;
            netEntry->srcIp.isV6 = FALSE;
            netEntry->dstIp.isV6 = FALSE;
            netEntry->dstIp.value.v4 = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS ].value.uint32;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT ].value.uint16;
            netEntry->srcIp.value.v4 = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS ].value.uint32;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
            netEntry->isIncoming = TRUE;
            netEntry->srcIp.isV6 = TRUE;
            netEntry->dstIp.isV6 = TRUE;
            netEntry->dstIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS ].value.byteArray16;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT ].value.uint16;
            netEntry->srcIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS ].value.byteArray16;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL ].value.uint8;
            break;

        default:
            rpal_debug_kernel( "Unknown layer protocol family: 0x%08X", layerId );
            status = STATUS_INTERNAL_ERROR;
    }

    return TRUE;
}

RVOID
    coAuthConnect
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( classifyCtx );
    UNREFERENCED_PARAMETER( flt );
    UNREFERENCED_PARAMETER( flowCtx );

    if( IS_FLAG_ENABLED( result->rights, FWPS_RIGHT_ACTION_WRITE ) )
    {
        result->actionType = FWP_ACTION_CONTINUE;
    }

    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

    if( getIpTuple( fixVals->layerId, fixVals, &g_connections[ g_nextConnection ] ) )
    {
        if( FWPS_IS_METADATA_FIELD_PRESENT( metaVals, FWPS_METADATA_FIELD_PROCESS_ID ) )
        {
            g_connections[ g_nextConnection ].pid = (RU32)metaVals->processId;
        }

        g_connections[ g_nextConnection ].ts = rpal_time_getLocal();
        g_nextConnection++;
        if( g_nextConnection == _NUM_BUFFERED_CONNECTIONS )
        {
            g_nextConnection = 0;
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to get tuple: 0x%08X", status );
        status = STATUS_INTERNAL_ERROR;
        RtlZeroMemory( &g_connections[ g_nextConnection ], sizeof( g_connections[ g_nextConnection ] ) );
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}

RVOID
    coAuthRecvAccept
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( classifyCtx );
    UNREFERENCED_PARAMETER( flt );
    UNREFERENCED_PARAMETER( flowCtx );

    if( IS_FLAG_ENABLED( result->rights, FWPS_RIGHT_ACTION_WRITE ) )
    {
        result->actionType = FWP_ACTION_CONTINUE;
    }

    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

    if( getIpTuple( fixVals->layerId, fixVals, &g_connections[ g_nextConnection ] ) )
    {
        if( FWPS_IS_METADATA_FIELD_PRESENT( metaVals, FWPS_METADATA_FIELD_PROCESS_ID ) )
        {
            g_connections[ g_nextConnection ].pid = (RU32)metaVals->processId;
        }

        g_connections[ g_nextConnection ].ts = rpal_time_getLocal();
        g_nextConnection++;
        if( g_nextConnection == _NUM_BUFFERED_CONNECTIONS )
        {
            g_nextConnection = 0;
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to get tuple: 0x%08X", status );
        status = STATUS_INTERNAL_ERROR;
        RtlZeroMemory( &g_connections[ g_nextConnection ], sizeof( g_connections[ g_nextConnection ] ) );
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}

static NTSTATUS
    calloutNotify
    (
        FWPS_CALLOUT_NOTIFY_TYPE type,
        const GUID* filterKey,
        const FWPS_FILTER* filter
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( type );
    UNREFERENCED_PARAMETER( filterKey );
    UNREFERENCED_PARAMETER( filter );

    return status;
}

static RVOID
    unregisterCallouts
    (

    )
{
    RU32 i = 0;
    
    for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
    {
        if( g_layers[ i ]->coActive )
        {
            FwpsCalloutUnregisterByKey( &g_layers[ i ]->coGuid );
            g_layers[ i ]->coActive = FALSE;
        }
    }
}

static RVOID
    deactivateLayers
    (

    )
{
    NTSTATUS status = STATUS_SUCCESS;
    RU32 i = 0;

    if( NULL == g_engineHandle ) return;

    if( NT_SUCCESS( status = FwpmTransactionBegin( g_engineHandle, 0 ) ) )
    {
        for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
        {
            if( g_layers[ i ]->flActive )
            {
                if( !NT_SUCCESS( status = FwpmFilterDeleteByKey( g_engineHandle, &g_layers[ i ]->flGuid ) ) )
                {
                    rpal_debug_kernel( "Failed to delete filter by key: 0x%08X", status );
                    FwpmTransactionAbort( g_engineHandle );
                    break;
                }
                g_layers[ i ]->flActive = FALSE;
            }

            if( g_layers[ i ]->slActive )
            {
                if( !NT_SUCCESS( status = FwpmSubLayerDeleteByKey( g_engineHandle, &g_layers[ i ]->slGuid ) ) )
                {
                    rpal_debug_kernel( "Failed to delete sublayer sby key: 0x%08X", status );
                    FwpmTransactionAbort( g_engineHandle );
                    break;
                }
                g_layers[ i ]->slActive = FALSE;
            }
        }

        if( !NT_SUCCESS( status = FwpmTransactionCommit( g_engineHandle ) ) )
        {
            rpal_debug_kernel( "Failed to commit transaction: 0x%08X", status );
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to start transaction: 0x%08X", status );
    }

    unregisterCallouts();

    if( NULL != g_engineHandle )
    {
        FwpmEngineClose0( g_engineHandle );
        g_engineHandle = NULL;
    }
}

static NTSTATUS
    activateLayers
    (
        PDEVICE_OBJECT deviceObject
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    RU32 i = 0;
    
    if( NULL != g_engineHandle ) return status;

    if( !NT_SUCCESS( status = FwpmEngineOpen( NULL, 
                                              RPC_C_AUTHN_DEFAULT, 
                                              NULL, 
                                              NULL, 
                                              &g_engineHandle ) ) )
    {
        return status;
    }

    if( !NT_SUCCESS( status = FwpmTransactionBegin( g_engineHandle, 0 ) ) )
    {
        rpal_debug_kernel( "Failed to start transaction: 0x%08X", status );
        return status;
    }

    for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
    {
        FWPS_CALLOUT callout = { 0 };
        callout.calloutKey = g_layers[ i ]->coGuid;
        callout.classifyFn = g_layers[ i ]->co;
        callout.notifyFn = calloutNotify;
        callout.flowDeleteFn = NULL;

        if( !NT_SUCCESS( status = FwpsCalloutRegister( deviceObject, &callout, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to register callout %d: 0x%08X", i, status );
            break;
        }

        g_layers[ i ]->coActive = TRUE;
    }

    if( !NT_SUCCESS( status ) )
    {
        unregisterCallouts();
        FwpmTransactionAbort( g_engineHandle );
        FwpmEngineClose( g_engineHandle );
        g_engineHandle = NULL;
        return status;
    }

    for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
    {
        FWPM_SUBLAYER sublayer = { 0 };
        FWPM_CALLOUT callout = { 0 };
        FWPM_FILTER filter = { 0 };

        sublayer.subLayerKey = g_layers[ i ]->slGuid;
        sublayer.displayData.name = g_layers[ i ]->slName;

        callout.calloutKey = g_layers[ i ]->coGuid;
        callout.displayData.name = g_layers[ i ]->coName;
        callout.applicableLayer = g_layers[ i ]->guid;

        filter.flags = FWPM_FILTER_FLAG_NONE;
        filter.filterKey = g_layers[ i ]->flGuid;
        filter.layerKey = g_layers[ i ]->guid;
        filter.displayData.name = g_layers[ i ]->flName;
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.calloutKey = g_layers[ i ]->coGuid;
        filter.subLayerKey = g_layers[ i ]->slGuid;
        filter.weight.type = FWP_EMPTY;

        if( !NT_SUCCESS( status = FwpmSubLayerAdd( g_engineHandle, &sublayer, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to add sublayer: 0x%08X", status );
            break;
        }

        g_layers[ i ]->slActive = TRUE;

        if( !NT_SUCCESS( status = FwpmCalloutAdd( g_engineHandle, &callout, NULL, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to add callout: 0x%08X", status );
            break;
        }

        if( !NT_SUCCESS( status = FwpmFilterAdd( g_engineHandle, &filter, NULL, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to add filter: 0x%08X", status );
            break;
        }

        g_layers[ i ]->flActive = TRUE;
    }

    if( !NT_SUCCESS( status ) )
    {
        unregisterCallouts();
        FwpmTransactionAbort( g_engineHandle );
        FwpmEngineClose( g_engineHandle );
        g_engineHandle = NULL;
        return status;
    }

    if( !NT_SUCCESS( status = FwpmTransactionCommit( g_engineHandle ) ) )
    {
        rpal_debug_kernel( "Failed to commit transaction: 0x%08X", status );
        return status;
    }

    return status;
}


RVOID
    stateChangeCallback
    (
        RPVOID ctx,
        FWPM_SERVICE_STATE newState
    )
{
    PDEVICE_OBJECT deviceObject = (PDEVICE_OBJECT)ctx;

    switch( newState )
    {
        case FWPM_SERVICE_STOP_PENDING:
            KeEnterGuardedRegion();
            deactivateLayers();
            KeLeaveGuardedRegion();
            break;
        case FWPM_SERVICE_RUNNING:
            KeEnterGuardedRegion();
            activateLayers( deviceObject );
            KeLeaveGuardedRegion();
            break;
        default:
            break;
    }
}

static NTSTATUS
    installWfp
    (
        PDEVICE_OBJECT deviceObject
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    do
    {
        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect4.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect4.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect4.flGuid ) ) )
        {
            g_layerAuthConnect4.guid = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authConnect4 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect6.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect6.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect6.flGuid ) ) )
        {
            g_layerAuthConnect6.guid = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authConnect6 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept4.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept4.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept4.flGuid ) ) )
        {
            g_layerAuthRecvAccept4.guid = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authRecvAccept4 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept6.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept6.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept6.flGuid ) ) )
        {
            g_layerAuthRecvAccept6.guid = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authRecvAccept4 GUIDs: 0x%08X", status );
            break;
        }

        if( !NT_SUCCESS( status = FwpmBfeStateSubscribeChanges( deviceObject,
                                                                stateChangeCallback,
                                                                (RPVOID)deviceObject,
                                                                &g_stateChangeHandle ) ) )
        {
            rpal_debug_kernel( "Failed to subscribe to changes: 0x%08X", status );
            g_stateChangeHandle = NULL;
            break;
        }

        if( FWPM_SERVICE_RUNNING == FwpmBfeStateGet() )
        {
            KeEnterGuardedRegion();
            status = activateLayers( deviceObject );
            KeLeaveGuardedRegion();
        }
        else
        {
            rpal_debug_kernel( "Engine not running" );
        }
    } while( FALSE );

    return status;
}

static RVOID
    uninstallWfp
    (

    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if( NULL != g_stateChangeHandle )
    {
        if( !NT_SUCCESS( status = FwpmBfeStateUnsubscribeChanges( g_stateChangeHandle ) ) )
        {
            rpal_debug_kernel( "Failed to unsubscribe to changes: 0x%08X", status );
        }
        g_stateChangeHandle = NULL;
    }

    KeEnterGuardedRegion();
    deactivateLayers();
    KeLeaveGuardedRegion();
}

RBOOL
    collector_4_initialize
    (
        PDRIVER_OBJECT driverObject,
        PDEVICE_OBJECT deviceObject
    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( driverObject );

    KeInitializeSpinLock( &g_collector_4_mutex );

    status = installWfp( deviceObject );

    if( NT_SUCCESS( status ) )
    {
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Failed to initialize: 0x%08X", status );
    }

    return isSuccess;
}

RBOOL
    collector_4_deinitialize
    (

    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    uninstallWfp();

    if( NT_SUCCESS( status ) )
    {
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Failed to deinitialize: 0x%08X", status );
    }

    return isSuccess;
}
