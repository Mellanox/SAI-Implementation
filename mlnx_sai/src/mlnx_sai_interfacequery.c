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

service_method_table_t g_services;
bool                   g_initialized = false;

/*
 * Routine Description:
 *     API initialization call
 *
 * Arguments:
 *     [in] flags - reserved for future use
 *
 * Return Values
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_api_initialize(_In_ uint64_t flags, _In_ service_method_table_t* services)
{
    if ((NULL == services) || (NULL == services->profile_get_next_value) || (NULL == services->profile_get_value)) {
        fprintf(stderr, "Invalid services handle passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memcpy(&g_services, services, sizeof(g_services));

    if (0 != flags) {
        fprintf(stderr, "Invalid flags passed to SAI API initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    g_initialized = true;

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Retrieve a group of SAI APIs
 *     Interfaces are C-style method tables and are queried by corresponding id.
 *
 * Arguments:
 *     [in] sai_interface_id - SAI interface ID
 *     [out] interface_method_table - Caller allocated method table
 *           The table must remain valid until the sai_api_shutdown() is called
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
    case SAI_API_ROUTE:
        *(const sai_route_api_t**)api_method_table = &route_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VR:
        *(const sai_vr_api_t**)api_method_table = &router_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SWITCH:
        *(const sai_switch_api_t**)api_method_table = &switch_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_PORT:
        *(const sai_port_api_t**)api_method_table = &port_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_FDB:
        *(const sai_fdb_api_t**)api_method_table = &fdb_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VLAN:
        *(const sai_vlan_api_t**)api_method_table = &vlan_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEXT_HOP:
        *(const sai_next_hop_api_t**)api_method_table = &next_hop_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ROUTER_INTERFACE:
        *(const sai_router_interface_api_t**)api_method_table = &router_interface_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEIGHBOR:
        *(const sai_neighbor_api_t**)api_method_table = &neighbor_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_QOS:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    case SAI_API_ACL:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    default:
        fprintf(stderr, "Invalid API type %d\n", sai_api_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
}

/*
 * Routine Description:
 *   API shutdown call
 *   SAI interfaces, retrieved via sai_api_query() cannot be used after this call
 *
 * Arguments:
 *   None
 *
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
sai_status_t sai_api_unitialize(void)
{
    memset(&g_services, 0, sizeof(g_services));
    g_initialized = false;

    return SAI_STATUS_SUCCESS;
}
