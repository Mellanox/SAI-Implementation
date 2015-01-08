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
#define __MODULE__ SAI_FDB

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *    Set FDB attribute value
 *
 * Arguments:
 *    [in] attribute - FDB attribute
 *    [in] value - FDB attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_fdb_attribute(_In_ sai_fdb_attr_t attribute, _In_ uint64_t value)
{
    sx_status_t status;

    SX_LOG_ENTER();

    switch (attribute) {
    case SAI_FDB_ATTR_AGING_TIME:
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_fdb_age_time_set(gh_sdk, DEFAULT_ETH_SWID, (sx_fdb_age_time_t)value))) {
            SX_LOG_ERR("Failed to set fdb age time - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_FDB_ATTR_TABLE_SIZE:
        break;

    default:
        SX_LOG_ERR("Invalid fdb attribute %d.\n", attribute);
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}


/*
 * Routine Description:
 *    Get FDB attribute value
 *
 * Arguments:
 *    [in] attribute - FDB attribute
 *    [out] value - FDB attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_fdb_attribute(_In_ sai_fdb_attr_t attribute, _Out_ uint64_t* value)
{
    sx_status_t       status;
    sx_fdb_age_time_t age_time;

    SX_LOG_ENTER();

    if (NULL == value) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attribute) {
    case SAI_FDB_ATTR_AGING_TIME:
        if (SX_STATUS_SUCCESS != (status = sx_api_fdb_age_time_get(gh_sdk, DEFAULT_ETH_SWID, &age_time))) {
            SX_LOG_ERR("Failed to get fdb age time - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = age_time;
        return SAI_STATUS_SUCCESS;

    case SAI_FDB_ATTR_TABLE_SIZE:
        break;

    default:
        SX_LOG_ERR("Invalid fdb attribute %d.\n", attribute);
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}


/*
 * Routine Description:
 *    Delete MAC table
 *
 * Arguments:
 *    None
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_flush_all_fdb_entries(void)
{
    sx_status_t status;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_all_set(gh_sdk, DEFAULT_ETH_SWID))) {
        SX_LOG_ERR("Failed to flush all fdb entries - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Flush all FDB entries by port
 *
 * Arguments:
 *    [in] port_id - port id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_flush_all_fdb_entries_by_port(_In_ sai_port_id_t port_id)
{
    sx_status_t status;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_port_set(gh_sdk, port_id))) {
        SX_LOG_ERR("Failed to flush port fdb entries - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Flush all FDB entries by vlan
 *
 * Arguments:
 *    [in] vlan_id - vlan id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_flush_all_fdb_entries_by_vlan(_In_ sai_vlan_id_t vlan_id)
{
    sx_status_t status;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_fid_set(gh_sdk, DEFAULT_ETH_SWID, vlan_id))) {
        SX_LOG_ERR("Failed to flush vlan fdb entries - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Flush all FDB entries from table by port and VLAN id
 *
 * Arguments:
 *    [in] mac_address - MAC address
 *    [in] vlan_id - VLAN id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_flush_all_fdb_entries_by_port_vlan(_In_ sai_port_id_t port_id, _In_ sai_vlan_id_t vlan_id)
{
    sx_status_t status;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_port_fid_set(gh_sdk, port_id, vlan_id))) {
        SX_LOG_ERR("Failed to flush port vlan fdb entries - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t do_fdb_entries(_In_ uint32_t fdb_count, _In_ sai_fdb_entry_t* fdb_entries, _In_ sx_access_cmd_t cmd)
{
    sx_fdb_uc_mac_addr_params_t *entries;
    uint32_t                     i, count = fdb_count;
    sx_status_t                  status;

    SX_LOG_ENTER();

    if (NULL == fdb_entries) {
        SX_LOG_ERR("NULL fdb entries param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    entries = (sx_fdb_uc_mac_addr_params_t*)malloc(sizeof(sx_fdb_uc_mac_addr_params_t) * count);
    if (NULL == entries) {
        SX_LOG_ERR("Can't allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    for (i = 0; i < count; i++) {
        switch (fdb_entries[i].action) {
        case SAI_FDB_ENTRY_PACKET_ACTION_FORWARD:
            entries[i].action = SX_FDB_ACTION_FORWARD;
            break;

        case SAI_FDB_ENTRY_PACKET_ACTION_TRAP:
            entries[i].action = SX_FDB_ACTION_TRAP;
            break;

        case SAI_FDB_ENTRY_PACKET_ACTION_LOG:
            entries[i].action = SX_FDB_ACTION_MIRROR_TO_CPU;
            break;

        case SAI_FDB_ENTRY_PACKET_ACTION_DROP:
            entries[i].action = SX_FDB_ACTION_DISCARD;
            break;

        default:
            free(entries);
            SX_LOG_ERR("Invalid fdb action %d\n", fdb_entries[i].action);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        switch (fdb_entries[i].entry_type) {
        case SAI_FDB_ENTRY_DYNAMIC:
            entries[i].entry_type = SX_FDB_UC_AGEABLE;
            break;

        case SAI_FDB_ENTRY_STATIC:
            entries[i].entry_type = SX_FDB_UC_STATIC;
            break;

        case SAI_FDB_ENTRY_UNSPECIFIED:
        default:
            free(entries);
            SX_LOG_ERR("Invalid fdb entry type %d\n", fdb_entries[i].entry_type);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        entries[i].fid_vid = fdb_entries[i].vlan_id;
        entries[i].log_port = fdb_entries[i].port_id;
        memcpy(&entries[i].mac_addr, fdb_entries[i].mac_address, sizeof(entries[i].mac_addr));
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_mac_addr_set(gh_sdk, cmd, DEFAULT_ETH_SWID, entries, &count))) {
        SX_LOG_ERR("Failed to set %d fdb entries %s.\n", count, SX_STATUS_MSG(status));
        for (i = 0; i < count; i++) {
            SX_LOG_ERR("%d : [%0x%0x%0x%0x%0x%0x], vlan %d\n",
                       i,
                       entries[i].mac_addr.ether_addr_octet[0],
                       entries[i].mac_addr.ether_addr_octet[1],
                       entries[i].mac_addr.ether_addr_octet[2],
                       entries[i].mac_addr.ether_addr_octet[3],
                       entries[i].mac_addr.ether_addr_octet[4],
                       entries[i].mac_addr.ether_addr_octet[5],
                       entries[i].fid_vid);
        }
        free(entries);
        return sdk_to_sai(status);
    }

    free(entries);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Add FDB entries
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] mac_address - MAC address
 *    [in] vlan_id - VLAN id
 *    [in] entry_type - FDB entry type
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_create_fdb_entries(_In_ uint32_t fdb_count, _In_ sai_fdb_entry_t* fdb_entries)
{
    SX_LOG_ENTER();
    return do_fdb_entries(fdb_count, fdb_entries, SX_ACCESS_CMD_ADD);
}

/*
 * Routine Description:
 *     Flush FDB entries
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] mac_address - MAC address
 *    [in] vlan_id - VLAN id
 *    [in] entry_type - FDB entry type
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_flush_fdb_entries(_In_ uint32_t fdb_count, _In_ sai_fdb_entry_t* fdb_entries)
{
    SX_LOG_ENTER();
    return do_fdb_entries(fdb_count, fdb_entries, SX_ACCESS_CMD_DELETE);
}

const sai_fdb_api_t fdb_api = {
    mlnx_create_fdb_entries,
    mlnx_flush_fdb_entries,
    mlnx_flush_all_fdb_entries,
    mlnx_flush_all_fdb_entries_by_port,
    mlnx_flush_all_fdb_entries_by_vlan,
    mlnx_flush_all_fdb_entries_by_port_vlan,
    mlnx_set_fdb_attribute,
    mlnx_get_fdb_attribute
};
