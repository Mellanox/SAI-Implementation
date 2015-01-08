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
#define __MODULE__ SAI_VLAN

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *    Set VLAN attribute Value
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] attribute - VLAN attribute
 *    [in] value - VLAN attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_vlan_attribute(_In_ sai_vlan_id_t vlan_id, _In_ sai_vlan_attr_t attribute, _In_ uint64_t value)
{
    UNREFERENCED_PARAMETER(vlan_id);
    UNREFERENCED_PARAMETER(value);

    SX_LOG_ENTER();

    switch (attribute) {
    /* TODO : implement */
    case SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES:
    default:
        SX_LOG_ERR("Invalid vlan attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }
}


/*
 * Routine Description:
 *    Get VLAN attribute Value
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] attribute - VLAN attribute
 *    [out] value - VLAN attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_vlan_attribute(_In_ sai_vlan_id_t vlan_id, _In_ sai_vlan_attr_t attribute, _Out_ uint64_t* value)
{
    UNREFERENCED_PARAMETER(vlan_id);

    SX_LOG_ENTER();

    if (NULL == value) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attribute) {
    /* TODO : implement */
    case SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES:
    default:
        SX_LOG_ERR("Invalid vlan attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }
}


/*
 * Routine Description:
 *    Delete VLAN configuration (delete all VLANs).
 *
 * Arguments:
 *    None
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_all_vlans(void)
{
    SX_LOG_ENTER();

    /* no need to call SDK */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Create a VLAN
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_create_vlan(_In_ sai_vlan_id_t vlan_id)
{
    UNREFERENCED_PARAMETER(vlan_id);

    SX_LOG_ENTER();

    /* no need to call SDK */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Delete a VLAN
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_vlan(_In_ sai_vlan_id_t vlan_id)
{
    UNREFERENCED_PARAMETER(vlan_id);

    SX_LOG_ENTER();

    /* no need to call SDK */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t do_vlan_port_list(_In_ sai_vlan_id_t    vlan_id,
                               _In_ uint32_t         port_count,
                               _In_ sai_vlan_port_t* port_list,
                               _In_ sx_access_cmd_t  cmd)
{
    sx_status_t      status;
    sx_vlan_ports_t *vlan_port_list;
    uint32_t         i;

    SX_LOG_ENTER();

    if (NULL == port_list) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    vlan_port_list = (sx_vlan_ports_t*)malloc(sizeof(sx_vlan_ports_t) * port_count);
    if (NULL == vlan_port_list) {
        SX_LOG_ERR("Can't allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    for (i = 0; i < port_count; i++) {
        vlan_port_list[i].log_port = port_list[i].port_id;

        switch (port_list[i].tagging_mode) {
        case SAI_VLAN_PORT_UNTAGGED:
            vlan_port_list[i].is_untagged = SX_UNTAGGED_MEMBER;
            break;

        case SAI_VLAN_PORT_TAGGED:
            vlan_port_list[i].is_untagged = SX_TAGGED_MEMBER;
            break;

        /* TODO : how to map */
        case SAI_VLAN_PORT_PRIORITY_TAGGED:
            break;

        default:
            free(vlan_port_list);
            SX_LOG_ERR("Invalid tagging mode %d\n", port_list[i].tagging_mode);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_vlan_ports_set(gh_sdk, cmd, DEFAULT_ETH_SWID, vlan_id, vlan_port_list, port_count))) {
        SX_LOG_ERR("Failed to set vlan ports %s.\n", SX_STATUS_MSG(status));
        free(vlan_port_list);
        return sdk_to_sai(status);
    }

    free(vlan_port_list);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Add Port to VLAN
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] port_id - port id
 *    [in] is_tagged - TRUE if only tagged packets are allowed
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_add_ports_to_vlan(_In_ sai_vlan_id_t    vlan_id,
                                    _In_ uint32_t         port_count,
                                    _In_ sai_vlan_port_t* port_list)
{
    SX_LOG_ENTER();
    return do_vlan_port_list(vlan_id, port_count, port_list, SX_ACCESS_CMD_ADD);
}


/*
 * Routine Description:
 *    Remove Port from VLAN
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] port_id - port id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_remove_ports_from_vlan(_In_ sai_vlan_id_t    vlan_id,
                                         _In_ uint32_t         port_count,
                                         _In_ sai_vlan_port_t* port_list)
{
    SX_LOG_ENTER();
    return do_vlan_port_list(vlan_id, port_count, port_list, SX_ACCESS_CMD_DELETE);
}

/*
 * Routine Description:
 *     Enable/Disable vlan statistics counters
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] number_of_counters - number of counters
 *    [out] stats_array - array of resulting counter values
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_ctl_vlan_stat_counters(_In_ sai_vlan_id_t vlan_id, _In_ uint32_t counter_set_id, _In_ bool enable)
{
    UNREFERENCED_PARAMETER(vlan_id);
    UNREFERENCED_PARAMETER(counter_set_id);
    UNREFERENCED_PARAMETER(enable);

    SX_LOG_ENTER();

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *     Get vlan statistics counters
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] counter_ids - specifies the array of counter ids
 *    [in] number_of_counters - number of counters in the array
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_vlan_stat_counters(_In_ sai_vlan_id_t            vlan_id,
                                         _In_ sai_vlan_stat_counter_t *counter_ids,
                                         _In_ uint32_t                 number_of_counters,
                                         _Out_ uint64_t              * stats_array)
{
    UNREFERENCED_PARAMETER(vlan_id);
    UNREFERENCED_PARAMETER(counter_ids);
    UNREFERENCED_PARAMETER(number_of_counters);

    SX_LOG_ENTER();

    if (NULL == stats_array) {
        SX_LOG_ERR("NULL stats array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_vlan_api_t vlan_api = {
    mlnx_create_vlan,
    mlnx_delete_vlan,
    mlnx_set_vlan_attribute,
    mlnx_get_vlan_attribute,
    mlnx_add_ports_to_vlan,
    mlnx_remove_ports_from_vlan,
    mlnx_delete_all_vlans,
    mlnx_ctl_vlan_stat_counters,
    mlnx_get_vlan_stat_counters
};
