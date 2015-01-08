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
#define __MODULE__ SAI_PORT

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *   Set port attribute value.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] attribute - port attribute.
 *    [in] value - port attribute value.
 *
 * Return Values:
 *    S_OK        on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_port_attribute(_In_ sai_port_id_t port_id, _In_ sai_port_attr_t attribute, _In_ uint64_t value)
{
    sx_status_t               status;
    sx_vlan_frame_types_t     frame_types;
    sx_mstp_inst_port_state_t stp_state;

    SX_LOG_ENTER();

    switch (attribute) {
    case SAI_PORT_ATTR_ADMIN_STATE:
        if (SX_STATUS_SUCCESS != (status = sx_api_port_state_set(gh_sdk, port_id,
                                                                 value ? SX_PORT_ADMIN_STATUS_UP :
                                                                 SX_PORT_ADMIN_STATUS_DOWN))) {
            SX_LOG_ERR("Failed to set port state - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_DEFAULT_VLAN:
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD, port_id, (sx_vid_t)value))) {
            SX_LOG_ERR("Failed to set port pvid - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_DEFAULT_VLAN_PRIORITY:
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_cos_port_default_prio_set(gh_sdk, port_id, (sx_cos_priority_t)value))) {
            SX_LOG_ERR("Failed to set port default prio - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_INGRESS_FILTERING:
        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_ingr_filter_set(gh_sdk, port_id,
                                                                            value ? SX_INGR_FILTER_ENABLE :
                                                                            SX_INGR_FILTER_DISABLE))) {
            SX_LOG_ERR("Failed to set port ingress filter - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_DROP_UNTAGGED:
    case SAI_PORT_ATTR_DROP_TAGGED:
        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_accptd_frm_types_get(gh_sdk, port_id, &frame_types))) {
            SX_LOG_ERR("Failed to get port accepted frame types - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SAI_PORT_ATTR_DROP_UNTAGGED == attribute) {
            frame_types.allow_untagged = !value;
        } else if (SAI_PORT_ATTR_DROP_TAGGED == attribute) {
            frame_types.allow_tagged = !value;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_accptd_frm_types_set(gh_sdk, port_id, &frame_types))) {
            SX_LOG_ERR("Failed to set port accepted frame types - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_INTERNAL_LOOPBACK:
        if (SX_STATUS_SUCCESS != (status = sx_api_port_phys_loopback_set(gh_sdk, port_id,
                                                                         value ? SX_PORT_PHYS_LOOPBACK_ENABLE_INTERNAL
                                                                         : SX_PORT_PHYS_LOOPBACK_DISABLE))) {
            SX_LOG_ERR("Failed to set port physical loopback - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_FDB_LEARNING:
        if (SX_STATUS_SUCCESS != (status = sx_api_fdb_port_learn_mode_set(gh_sdk, port_id,
                                                                          value ? SX_FDB_LEARN_MODE_AUTO_LEARN :
                                                                          SX_FDB_LEARN_MODE_DONT_LEARN))) {
            SX_LOG_ERR("Failed to set port learning mode - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_MTU:
        if (SX_STATUS_SUCCESS != (status = sx_api_port_mtu_set(gh_sdk, port_id, (sx_port_mtu_t)value))) {
            SX_LOG_ERR("Failed to set port mtu - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_STP_STATE:
        switch (value) {
        case SAI_PORT_STP_STATE_DISCARDING:
            stp_state = SX_MSTP_INST_PORT_STATE_DISCARDING;
            break;

        case SAI_PORT_STP_STATE_LEARNING:
            stp_state = SX_MSTP_INST_PORT_STATE_LEARNING;
            break;

        case SAI_PORT_STP_STATE_FORWARDING:
            stp_state = SX_MSTP_INST_PORT_STATE_FORWARDING;
            break;

        /* TODO : translate these states */
        case SAI_PORT_STP_STATE_DISABLED:
        case SAI_PORT_STP_STATE_LISTENING:
        case SAI_PORT_STP_STATE_BLOCKING:
        default:
            SX_LOG_ERR("Invalid stp state %" PRIu64 "\n", value);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_rstp_port_state_set(gh_sdk, port_id, stp_state))) {
            SX_LOG_ERR("Failed to set port stp state - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_STP_MODE:
    case SAI_PORT_ATTR_UPDATE_DSCP:
    case SAI_PORT_ATTR_SFLOW:
    case SAI_PORT_ATTR_FLOOD_STORM_CONTROL:
    case SAI_PORT_ATTR_BOADCAST_STORM_CONTROL:
    case SAI_PORT_ATTR_MULTICAST_STORM_CONTROL:
    case SAI_PORT_ATTR_GLOBOL_FLOW_CONTROL:
    case SAI_PORT_ATTR_MAX_LEARNED_ADDRESSES:

    default:
        SX_LOG_ERR("Invalid port attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }
}

/*
 * Routine Description:
 *   Get port attribute value.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] attribute - port attribute.
 *    [out] value - port attribute value.
 *
 * Return Values:
 *    S_OK        on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_port_attribute(_In_ sai_port_id_t port_id, _In_ sai_port_attr_t attribute, _Out_ uint64_t* value)
{
    sx_status_t                status;
    sx_port_mode_t             port_mode;
    sx_port_speed_capability_t speed_cap;
    sx_port_oper_speed_t       speed_oper;
    sx_port_oper_state_t       state_oper;
    sx_port_admin_state_t      state_admin;
    sx_port_module_state_t     state_module;
    sx_vid_t                   pvid;
    sx_port_phys_loopback_t    loopback;
    sx_cos_priority_t          prio;
    sx_ingr_filter_mode_t      mode;
    sx_vlan_frame_types_t      frame_types;
    sx_fdb_learn_mode_t        learn_mode;
    sx_port_mtu_t              max_mtu;
    sx_port_mtu_t              oper_mtu;
    sx_mstp_inst_port_state_t  stp_state;

    SX_LOG_ENTER();

    if (NULL == value) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attribute) {
    case SAI_PORT_ATTR_TYPE:
        if (SX_STATUS_SUCCESS != (status = sx_api_port_mode_get(gh_sdk, port_id, &port_mode))) {
            SX_LOG_ERR("Failed to get port mode - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        switch (port_mode) {
        case SX_PORT_MODE_EXTERNAL:
            *value = SAI_PORT_TYPE_LOGICAL;
            break;

        case SX_PORT_MODE_CPU:
            *value = SAI_PORT_TYPE_CPU;
            break;
        /* TODO : add case for LAG */

        default:
            SX_LOG_ERR("Unexpected port mode %d\n", port_mode);
            return SAI_STATUS_FAILURE;
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_SPEED:
        if (SX_STATUS_SUCCESS != (status = sx_api_port_speed_get(gh_sdk, port_id, &speed_cap, &speed_oper))) {
            SX_LOG_ERR("Failed to get port speed - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (speed_cap.mode_56GB_KX4 || speed_cap.mode_56GB_KR4) {
            *value = PORT_SPEED_56;
        } else if (speed_cap.mode_40GB_KR4 || speed_cap.mode_40GB_CR4) {
            *value = PORT_SPEED_40;
        } else if (speed_cap.mode_20GB_KR2) {
            *value = PORT_SPEED_20;
        } else if (speed_cap.mode_10GB_KR || speed_cap.mode_10GB_KX4 || speed_cap.mode_10GB_CX4_XAUI) {
            *value = PORT_SPEED_10;
        } else if (speed_cap.mode_1GB_CX_SGMII || speed_cap.mode_1GB_KX) {
            *value = PORT_SPEED_1;
        } else {
            SX_LOG_ERR("Unexpected port speed\n");
            *value = 0;
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_OPER_STATUS:
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_port_state_get(gh_sdk, port_id, &state_oper, &state_admin, &state_module))) {
            SX_LOG_ERR("Failed to get port state - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        switch (state_oper) {
        case SX_PORT_OPER_STATUS_UP:
            *value = SAI_PORT_OPER_STATUS_UP;
            break;

        case SX_PORT_OPER_STATUS_DOWN:
        case SX_PORT_OPER_STATUS_DOWN_BY_FAIL:
            *value = SAI_PORT_OPER_STATUS_DOWN;
            break;

        default:
            *value = SAI_PORT_OPER_STATUS_UNKNOWN;
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_ADMIN_STATE:
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_port_state_get(gh_sdk, port_id, &state_oper, &state_admin, &state_module))) {
            SX_LOG_ERR("Failed to get port state - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        switch (state_admin) {
        case SX_PORT_ADMIN_STATUS_UP:
            *value = 1;
            break;

        case SX_PORT_ADMIN_STATUS_DOWN:
            *value = 0;
            break;

        default:
            SX_LOG_ERR("Unexpected port admin state %d\n", state_admin);
            return SAI_STATUS_FAILURE;
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_DEFAULT_VLAN:
        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_pvid_get(gh_sdk, port_id, &pvid))) {
            SX_LOG_ERR("Failed to get port pvid - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = pvid;
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_DEFAULT_VLAN_PRIORITY:
        if (SX_STATUS_SUCCESS != (status = sx_api_cos_port_default_prio_get(gh_sdk, port_id, &prio))) {
            SX_LOG_ERR("Failed to get port default prio - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = prio;
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_INGRESS_FILTERING:
        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_ingr_filter_get(gh_sdk, port_id, &mode))) {
            SX_LOG_ERR("Failed to get port ingress filter - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = mode;
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_DROP_UNTAGGED:
        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_accptd_frm_types_get(gh_sdk, port_id, &frame_types))) {
            SX_LOG_ERR("Failed to get port accepted frame types - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = !(frame_types.allow_untagged);
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_DROP_TAGGED:
        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_accptd_frm_types_get(gh_sdk, port_id, &frame_types))) {
            SX_LOG_ERR("Failed to get port accepted frame types - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = !(frame_types.allow_tagged);
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_INTERNAL_LOOPBACK:
        if (SX_STATUS_SUCCESS != (status = sx_api_port_phys_loopback_get(gh_sdk, port_id, &loopback))) {
            SX_LOG_ERR("Failed to get port physical loopback - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        /* is internal loopback enabled bool */
        *value =
            ((loopback == SX_PORT_PHYS_LOOPBACK_ENABLE_INTERNAL) || (loopback == SX_PORT_PHYS_LOOPBACK_ENABLE_BOTH));
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_FDB_LEARNING:
        if (SX_STATUS_SUCCESS != (status = sx_api_fdb_port_learn_mode_get(gh_sdk, port_id, &learn_mode))) {
            SX_LOG_ERR("Failed to get port learning mode - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = !(SX_FDB_LEARN_MODE_DONT_LEARN == learn_mode);
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_MTU:
        if (SX_STATUS_SUCCESS != (status = sx_api_port_mtu_get(gh_sdk, port_id, &max_mtu, &oper_mtu))) {
            SX_LOG_ERR("Failed to get port mtu - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = oper_mtu;
        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_STP_STATE:
        if (SX_STATUS_SUCCESS != (status = sx_api_rstp_port_state_get(gh_sdk, port_id, &stp_state))) {
            SX_LOG_ERR("Failed to get port stp state - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        switch (stp_state) {
        case SX_MSTP_INST_PORT_STATE_DISCARDING:
            *value = SAI_PORT_STP_STATE_DISCARDING;
            break;

        case SX_MSTP_INST_PORT_STATE_LEARNING:
            *value = SAI_PORT_STP_STATE_LEARNING;
            break;

        case SX_MSTP_INST_PORT_STATE_FORWARDING:
            *value = SAI_PORT_STP_STATE_FORWARDING;
            break;

        default:
            SX_LOG_ERR("Unexpected stp state %d\n", stp_state);
            return SAI_STATUS_FAILURE;
        }

        return SAI_STATUS_SUCCESS;

    case SAI_PORT_ATTR_STP_MODE:
    case SAI_PORT_ATTR_UPDATE_DSCP:
    case SAI_PORT_ATTR_SFLOW:
    case SAI_PORT_ATTR_FLOOD_STORM_CONTROL:
    case SAI_PORT_ATTR_BOADCAST_STORM_CONTROL:
    case SAI_PORT_ATTR_MULTICAST_STORM_CONTROL:
    case SAI_PORT_ATTR_GLOBOL_FLOW_CONTROL:
    case SAI_PORT_ATTR_MAX_LEARNED_ADDRESSES:

    default:
        SX_LOG_ERR("Invalid port attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }
}

/*
 * Routine Description:
 *   Enable/disable port statistics counters
 *
 * Arguments:
 *   [in] port_id - port id
 *   [in] number_of_counters - number of counters
 *   [out] stats_array - array of resulting counter values
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_ctl_port_stats(_In_ sai_port_id_t port_id, _In_ uint32_t port_counter_set_id, _In_ bool enable)
{
    UNUSED_PARAM(port_id);
    UNUSED_PARAM(port_counter_set_id);
    UNUSED_PARAM(enable);

    SX_LOG_ENTER();

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *   Get port statistics counters
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] counter_ids - specifies the array of counter ids
 *    [in] number_of_counters - number of counters in the array
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_port_stat_counters(_In_ sai_port_id_t            port_id,
                                         _In_ sai_port_stat_counter_t *counter_ids,
                                         _In_ uint32_t                 number_of_counters,
                                         _Out_ uint64_t              * counters)
{
    UNUSED_PARAM(port_id);
    UNUSED_PARAM(counter_ids);
    UNUSED_PARAM(number_of_counters);
    UNUSED_PARAM(counters);

    SX_LOG_ENTER();

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

const sai_port_api_t port_api = {
    mlnx_set_port_attribute,
    mlnx_get_port_attribute,
    mlnx_ctl_port_stats,
    mlnx_get_port_stat_counters
};
