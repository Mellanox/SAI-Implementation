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

#undef  __MODULE__
#define __MODULE__ SAI_SWITCH

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;
sx_api_handle_t           gh_sdk = 0;
sai_switch_notification_t g_notification_callbacks;

/*
 * Routine Description:
 *   Full switch initialization.
 *   Getting switch ready for operation
 *   All previous settings and configuration must be deleted
 *
 * Arguments:
 *   [in] profile_id - Handle for the switch profile.
 *   [in] switch_hardware_id - Switch hardware ID to open
 *   [in] port_map - sai port to physical port mapping
 *   [in] number_of_ports - number of sai ports
 *   [in] sdk_path - Switch sdk library path
 *   [in/opt] firmware_path_name - Vendor specific name of the firmware file to load
 *   [in] switch_notifications - switch notification table
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
sai_status_t mlnx_initialize_switch(_In_ sai_switch_profile_id_t                           profile_id,
                                    _In_reads_z_(SAI_MAX_HARDWARE_ID_LEN) char           * switch_hardware_id,
                                    _In_ sai_port_mapping_t                              * port_map,
                                    _In_ int                                               number_of_ports,
                                    _In_reads_z_(SAI_MAX_SDK_PATH_NAME_LEN) char         * sdk_path,
                                    _In_reads_opt_z_(SAI_MAX_FIRMWARE_PATH_NAME_LEN) char* firmware_path_name,
                                    _In_ sai_switch_notification_t                       * switch_notifications)
{
    sx_router_general_param_t   general_param;
    sx_router_resources_param_t resources_param;
    sx_status_t                 status;

    UNUSED_PARAM(profile_id);

    if (NULL == switch_hardware_id) {
        fprintf(stderr, "NULL switch hardware ID passed to SAI switch initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == sdk_path) {
        fprintf(stderr, "NULL sdk path passed to SAI switch initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == port_map) {
        fprintf(stderr, "NULL port map passed to SAI switch initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (0 == number_of_ports) {
        fprintf(stderr, "No ports passed to SAI switch initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == switch_notifications) {
        fprintf(stderr, "NULL switch notifications passed to SAI switch initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    memcpy(&g_notification_callbacks, switch_notifications, sizeof(g_notification_callbacks));

    /* TODO : launch SDK, burn FW */

    /* TODO : query the profile */

    /* Open an handle */
    if (SX_STATUS_SUCCESS != (status = sx_api_open(NULL, &gh_sdk))) {
        fprintf(stderr, "Can't open connection to SDK\n");
        return sdk_to_sai(status);
    }

    /* init router model, T1 config */
    /* TODO : in the future, get some/all of these params dynamically from the profile */
    resources_param.min_ipv4_uc_route_entries = 6000;
    resources_param.min_ipv6_uc_route_entries = 0;
    resources_param.min_ipv4_mc_route_entries = 0;
    resources_param.min_ipv6_mc_route_entries = 0;
    resources_param.max_virtual_routers_num = 1;
    resources_param.max_vlan_router_interfaces = 16;
    resources_param.max_port_router_interfaces = 64;
    resources_param.max_router_interfaces = 80;
    resources_param.min_ipv4_neighbor_entries = 64;
    resources_param.min_ipv6_neighbor_entries = 0;

    general_param.ipv4_enable = 1;
    general_param.ipv6_enable = 0;
    general_param.ipv4_mc_enable = 0;
    general_param.ipv6_mc_enable = 0;
    general_param.rpf_enable = 0;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_init_set(gh_sdk, &general_param, &resources_param))) {
        SX_LOG_ERR("Router init failed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Release all resources associated with currently opened switch
 *
 * Arguments:
 *   [in] warm_restart_hint - hint that indicates controlled warm restart.
 *                            Since warm restart can be caused by crash
 *                            (therefore there are no guarantees for this call),
 *                            this hint is really a performance optimization.
 *
 * Return Values:
 *   None
 */
void mlnx_shutdown_switch(_In_ bool warm_restart_hint)
{
    sx_status_t status;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_router_deinit_set(gh_sdk))) {
        SX_LOG_ERR("Router deinit failed.\n");
    }

#ifndef _WIN32
    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }
#endif

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));

    SX_LOG_EXIT();
}

/*
 * Routine Description:
 *   SDK connect. This API connects library to the initialized SDK.
 *   After the call the capability attributes should be ready for retrieval
 *   via sai_get_switch_attribute().
 *
 * Arguments:
 *   [in] profile_id - Handle for the switch profile.
 *   [in] switch_hardware_id - Switch hardware ID to open
 *   [in] switch_notifications - switch notification table
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
sai_status_t mlnx_connect_switch(_In_ sai_switch_profile_id_t                profile_id,
                                 _In_reads_z_(SAI_MAX_HARDWARE_ID_LEN) char* switch_hardware_id,
                                 _In_ sai_switch_notification_t            * switch_notifications)
{
    sx_status_t status;

    UNUSED_PARAM(profile_id);

    if (NULL == switch_hardware_id) {
        fprintf(stderr, "NULL switch hardware ID passed to SAI switch connect\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == switch_notifications) {
        fprintf(stderr, "NULL switch notifications passed to SAI switch connect\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    memcpy(&g_notification_callbacks, switch_notifications, sizeof(g_notification_callbacks));

    /* Open an handle if not done already on init for init agent */
    if (0 == gh_sdk) {
        if (SX_STATUS_SUCCESS != (status = sx_api_open(NULL, &gh_sdk))) {
            fprintf(stderr, "Can't open connection to SDK\n");
            return sdk_to_sai(status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Disconnect this SAI library from the SDK.
 *
 * Arguments:
 *   None
 * Return Values:
 *   None
 */
void mlnx_disconnect_switch(void)
{
#ifndef _WIN32
    sx_status_t status;

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));
#endif
}

/*
 * Routine Description:
 *    Set switch attribute value
 *
 * Arguments:
 *    [in] attribute - switch attribute
 *    [in] value - switch attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_switch_attribute(_In_ sai_switch_attr_t attribute, _In_ uint64_t value)
{
    sx_router_ecmp_hash_params_t ecmp;
    sx_status_t                  status;

    SX_LOG_ENTER();

    switch (attribute) {
    case SAI_SWITCH_ATTR_HW_SEQUENCE_ID:
        break;

    case SAI_SWITCH_ATTR_ADMIN_STATE:
        break;

    case SAI_SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE:
        break;

    case SAI_SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE:
        break;

    case SAI_SWITCH_ATTR_DEFAULT_PORT_VLAN_ID:
        break;

    case SAI_SWITCH_ATTR_MAX_LEARNED_ADDRESSES:
        break;

    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_ACTION:
        break;

    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_ACTION:
        break;

    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_ACTION:
        break;

    case SAI_SWITCH_ATTR_ECMP_HASH_TYPE:
    case SAI_SWITCH_ATTR_ECMP_HASH_FIELDS:
    case SAI_SWITCH_ATTR_ECMP_HASH_SEED:
        /* TODO : get only works after first configuration. need to implement set per attrib, without get, instead of set all that requires get */
        if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_get(gh_sdk, &ecmp))) {
            SX_LOG_ERR("Failed to get ECMP hash params - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SAI_SWITCH_ATTR_ECMP_HASH_TYPE == attribute) {
            /* TODO : add implementation */
            /* ecmp.ecmp_hash_type = */
        } else if (SAI_SWITCH_ATTR_ECMP_HASH_FIELDS == attribute) {
            ecmp.ecmp_hash = 0;
            if (value & SAI_SWITCH_ECMP_HASH_SRC_IP) {
                ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_SRC_IP;
            }
            if (value & SAI_SWITCH_ECMP_HASH_DST_IP) {
                ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_DST_IP;
            }
            if (value & SAI_SWITCH_ECMP_HASH_L4_SRC_PORT) {
                ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_TCP_UDP_SRC_PORT;
            }
            if (value & SAI_SWITCH_ECMP_HASH_L4_DST_PORT) {
                ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_TCP_UDP_DST_PORT;
            }
        } else if (SAI_SWITCH_ATTR_ECMP_HASH_SEED == attribute) {
            ecmp.seed = (uint32_t)value;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_set(gh_sdk, &ecmp))) {
            SX_LOG_ERR("Failed to set ECMP hash params - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    default:
        SX_LOG_ERR("Invalid switch attribute %d.\n", attribute);
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *    Get switch attribute value
 *
 * Arguments:
 *    [in] attribute - switch attribute
 *    [out] value - switch attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_switch_attribute(_In_ sai_switch_attr_t attribute, _Out_ uint64_t* value)
{
    sx_status_t                  status;
    sx_router_ecmp_hash_params_t ecmp;

    SX_LOG_ENTER();

    if (NULL == value) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attribute) {
    case SAI_SWITCH_ATTR_PORT_NUMBER:
        *value = SWITCH_PORT_NUM;
        return SAI_STATUS_SUCCESS;

    case SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS:
        *value = SWITCH_MAX_VR;
        return SAI_STATUS_SUCCESS;

    case SAI_SWITCH_ATTR_ON_LINK_ROUTE_SUPPORTED:
        break;

    case SAI_SWITCH_ATTR_OPER_STATUS:
        break;

    case SAI_SWITCH_ATTR_HW_SEQUENCE_ID:
        break;

    case SAI_SWITCH_ATTR_ADMIN_STATE:
        break;

    case SAI_SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE:
        break;

    case SAI_SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE:
        break;

    case SAI_SWITCH_ATTR_DEFAULT_PORT_VLAN_ID:
        break;

    case SAI_SWITCH_ATTR_MAX_LEARNED_ADDRESSES:
        break;

    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_ACTION:
        break;

    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_ACTION:
        break;

    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_ACTION:
        break;

    case SAI_SWITCH_ATTR_ECMP_HASH_SEED:
        if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_get(gh_sdk, &ecmp))) {
            SX_LOG_ERR("Failed to get ECMP hash params - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = ecmp.seed;
        return SAI_STATUS_SUCCESS;

    case SAI_SWITCH_ATTR_ECMP_HASH_TYPE:
        if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_get(gh_sdk, &ecmp))) {
            SX_LOG_ERR("Failed to get ECMP hash params - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        /* TODO : add implementation */
        break;

    case SAI_SWITCH_ATTR_ECMP_HASH_FIELDS:
        if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_get(gh_sdk, &ecmp))) {
            SX_LOG_ERR("Failed to get ECMP hash params - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = 0;
        if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_SRC_IP) {
            *value |= SAI_SWITCH_ECMP_HASH_SRC_IP;
        }
        if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_DST_IP) {
            *value |= SAI_SWITCH_ECMP_HASH_DST_IP;
        }
        if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_TCP_UDP_SRC_PORT) {
            *value |= SAI_SWITCH_ECMP_HASH_L4_SRC_PORT;
        }
        if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_TCP_UDP_DST_PORT) {
            *value |= SAI_SWITCH_ECMP_HASH_L4_DST_PORT;
        }

        return SAI_STATUS_SUCCESS;

    default:
        SX_LOG_ERR("Invalid switch attribute %d.\n", attribute);
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *   Enable/disable switch statistics counters.
 *
 * Arguments:
 *    [in] number_of_counters - number of counters.
 *    [in] counter_id_array - array of counter ids ot query.
 *    [out] stats_array - array of resulting counter values.
 *
 * Return Values:
 *    S_OK        on success
 *    Failure status code on error
 */
sai_status_t mlx_sai_ctl_switch_stats(_In_ uint32_t counter_set_id, _In_ bool enable)
{
    UNUSED_PARAM(counter_set_id);
    UNUSED_PARAM(enable);

    SX_LOG_ENTER();

    /* TODO : fill */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *   Get switch statistics counters.
 *
 * Arguments:
 *    [in] counter_ids - specifies the array of counter ids
 *    [in] number_of_counters - number of counters in the array
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    S_OK        on success
 *    Failure status code on error
 */
sai_status_t mlnx_sai_get_switch_stats(_In_ sai_switch_stat_counter_t* counter_ids,
                                       _In_ uint32_t                   number_of_counters,
                                       _Out_ uint64_t                * counters)
{
    UNUSED_PARAM(counter_ids);
    UNUSED_PARAM(number_of_counters);

    SX_LOG_ENTER();

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO : fill */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

const sai_switch_api_t switch_api = {
    mlnx_initialize_switch,
    mlnx_shutdown_switch,
    mlnx_connect_switch,
    mlnx_disconnect_switch,
    mlnx_set_switch_attribute,
    mlnx_get_switch_attribute,
    mlx_sai_ctl_switch_stats,
    mlnx_sai_get_switch_stats
};
