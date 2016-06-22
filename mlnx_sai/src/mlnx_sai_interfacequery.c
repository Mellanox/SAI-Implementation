/*
 *  Copyright (C) 2014. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "sai_windows.h"

#include "sai.h"
#include "mlnx_sai.h"

service_method_table_t g_mlnx_services;
static bool            g_initialized = false;

/*
 * Routine Description:
 *     Adapter module initialization call. This is NOT for SDK initialization.
 *
 * Arguments:
 *     [in] flags - reserved for future use, must be zero
 *     [in] services - methods table with services provided by adapter host
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_api_initialize(_In_ uint64_t flags, _In_ const service_method_table_t* services)
{
    if (g_initialized) {
        fprintf(stderr, "SAI API initialize already called before, can't re-initialize\n");
        return SAI_STATUS_FAILURE;
    }

    if ((NULL == services) || (NULL == services->profile_get_next_value) || (NULL == services->profile_get_value)) {
        fprintf(stderr, "Invalid services handle passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memcpy(&g_mlnx_services, services, sizeof(g_mlnx_services));

    if (0 != flags) {
        fprintf(stderr, "Invalid flags passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    g_initialized = true;

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Retrieve a pointer to the C-style method table for desired SAI
 *     functionality as specified by the given sai_api_id.
 *
 * Arguments:
 *     [in] sai_api_id - SAI api ID
 *     [out] api_method_table - Caller allocated method table
 *           The table must remain valid until the sai_api_uninitialize() is called
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_api_query(_In_ sai_api_t sai_api_id, _Out_ void** api_method_table)
{
    if (NULL == api_method_table) {
        fprintf(stderr, "NULL method table passed to SAI API initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (!g_initialized) {
        fprintf(stderr, "SAI API not initialized before calling API query\n");

        return SAI_STATUS_UNINITIALIZED;
    }

    switch (sai_api_id) {
    case SAI_API_SWITCH:
        *(const sai_switch_api_t**)api_method_table = &mlnx_switch_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_PORT:
        *(const sai_port_api_t**)api_method_table = &mlnx_port_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_FDB:
        *(const sai_fdb_api_t**)api_method_table = &mlnx_fdb_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VLAN:
        *(const sai_vlan_api_t**)api_method_table = &mlnx_vlan_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VIRTUAL_ROUTER:
        *(const sai_virtual_router_api_t**)api_method_table = &mlnx_router_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ROUTE:
        *(const sai_route_api_t**)api_method_table = &mlnx_route_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEXT_HOP:
        *(const sai_next_hop_api_t**)api_method_table = &mlnx_next_hop_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEXT_HOP_GROUP:
        *(const sai_next_hop_group_api_t**)api_method_table = &mlnx_next_hop_group_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ROUTER_INTERFACE:
        *(const sai_router_interface_api_t**)api_method_table = &mlnx_router_interface_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEIGHBOR:
        *(const sai_neighbor_api_t**)api_method_table = &mlnx_neighbor_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ACL:
        *(const sai_acl_api_t**)api_method_table = &mlnx_acl_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_HOST_INTERFACE:
        *(const sai_hostif_api_t**)api_method_table = &mlnx_host_interface_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_QOS_MAPS:
        *(const sai_qos_map_api_t**)api_method_table = &mlnx_qos_maps_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_WRED:
        *(const sai_wred_api_t**)api_method_table = &mlnx_wred_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_QUEUE:
        *(const sai_queue_api_t**)api_method_table = &mlnx_queue_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SCHEDULER:
        *(const sai_scheduler_api_t**)api_method_table = &mlnx_scheduler_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_POLICER:
        *(const sai_policer_api_t**)api_method_table = &mlnx_policer_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_MIRROR:
        *(const sai_mirror_api_t**)api_method_table = &mlnx_mirror_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SAMPLEPACKET:
        *(const sai_samplepacket_api_t**)api_method_table = &mlnx_samplepacket_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_STP:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    case SAI_API_LAG:
        *(const sai_lag_api_t**)api_method_table = &mlnx_lag_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SCHEDULER_GROUP:
        *(const sai_scheduler_group_api_t**)api_method_table = &mlnx_scheduler_group_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_BUFFERS:
        *(const sai_buffer_api_t**)api_method_table = &mlnx_buffer_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_HASH:
        *(const sai_hash_api_t**)api_method_table = &mlnx_hash_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_UDF:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    case SAI_API_TUNNEL:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    default:
        fprintf(stderr, "Invalid API type %d\n", sai_api_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
}

/*
 * Routine Description:
 *   Uninitialization of the adapter module. SAI functionalities, retrieved via
 *   sai_api_query() cannot be used after this call.
 *
 * Arguments:
 *   None
 *
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
sai_status_t sai_api_uninitialize(void)
{
    memset(&g_mlnx_services, 0, sizeof(g_mlnx_services));
    g_initialized = false;

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Set log level for sai api module. The default log level is SAI_LOG_WARN.
 *
 * Arguments:
 *     [in] sai_api_id - SAI api ID
 *     [in] log_level - log level
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_log_set(_In_ sai_api_t sai_api_id, _In_ sai_log_level_t log_level)
{
    sx_log_severity_t severity;

    switch (log_level) {
    case SAI_LOG_DEBUG:
        severity = SX_VERBOSITY_LEVEL_DEBUG;
        break;

    case SAI_LOG_INFO:
        severity = SX_VERBOSITY_LEVEL_INFO;
        break;

    case SAI_LOG_NOTICE:
        severity = SX_VERBOSITY_LEVEL_NOTICE;
        break;

    case SAI_LOG_WARN:
        severity = SX_VERBOSITY_LEVEL_WARNING;
        break;

    case SAI_LOG_ERROR:
        severity = SX_VERBOSITY_LEVEL_ERROR;
        break;

    case SAI_LOG_CRITICAL:
        severity = SX_VERBOSITY_LEVEL_ERROR;
        break;

    default:
        fprintf(stderr, "Invalid log level %d\n", log_level);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO : map the utils module */

    switch (sai_api_id) {
    case SAI_API_SWITCH:
        mlnx_switch_log_set(severity);
        return mlnx_utils_log_set(severity);

    case SAI_API_PORT:
        return mlnx_port_log_set(severity);

    case SAI_API_FDB:
        return mlnx_fdb_log_set(severity);

    case SAI_API_VLAN:
        return mlnx_vlan_log_set(severity);

    case SAI_API_VIRTUAL_ROUTER:
        return mlnx_router_log_set(severity);

    case SAI_API_ROUTE:
        return mlnx_route_log_set(severity);

    case SAI_API_NEXT_HOP:
        return mlnx_nexthop_log_set(severity);

    case SAI_API_NEXT_HOP_GROUP:
        return mlnx_nexthop_group_log_set(severity);

    case SAI_API_ROUTER_INTERFACE:
        return mlnx_rif_log_set(severity);

    case SAI_API_NEIGHBOR:
        return mlnx_neighbor_log_set(severity);

    case SAI_API_ACL:
        return mlnx_acl_log_set(severity);

    case SAI_API_HOST_INTERFACE:
        return mlnx_host_interface_log_set(severity);

    case SAI_API_QOS_MAPS:
        return mlnx_qos_map_log_set(severity);

    case SAI_API_WRED:
        return mlnx_wred_log_set(severity);

    case SAI_API_QUEUE:
        return mlnx_queue_log_set(severity);

    case SAI_API_SCHEDULER:
        return mlnx_scheduler_log_set(severity);

    case SAI_API_POLICER:
        return mlnx_policer_log_set(severity);

    case SAI_API_MIRROR:
        return mlnx_mirror_log_set(severity);

    case SAI_API_SAMPLEPACKET:
        return mlnx_samplepacket_log_set(severity);

    case SAI_API_STP:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    case SAI_API_LAG:
        return mlnx_lag_log_set(severity);

    case SAI_API_SCHEDULER_GROUP:
        return mlnx_scheduler_group_log_set(severity);

    case SAI_API_BUFFERS:
        return mlnx_sai_buffer_log_set(severity);

    case SAI_API_HASH:
        return mlnx_hash_log_set(severity);

    case SAI_API_UDF:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    case SAI_API_TUNNEL:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    default:
        fprintf(stderr, "Invalid API type %d\n", sai_api_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
}

/*
 * Routine Description:
 *     Query sai object type.
 *
 * Arguments:
 *     [in] sai_object_id_t
 *
 * Return Values:
 *    Return SAI_OBJECT_TYPE_NULL when sai_object_id is not valid.
 *    Otherwise, return a valid sai object type SAI_OBJECT_TYPE_XXX
 */
sai_object_type_t sai_object_type_query(_In_ sai_object_id_t sai_object_id)
{
    sai_object_type_t type = ((mlnx_object_id_t*)&sai_object_id)->object_type;

    if SAI_TYPE_CHECK_RANGE(type) {
        return type;
    } else {
        fprintf(stderr, "Unknown type %d", type);
        return SAI_OBJECT_TYPE_NULL;
    }
}
