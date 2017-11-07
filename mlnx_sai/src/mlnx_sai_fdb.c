/*
 *  Copyright (C) 2017. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
#include "assert.h"

#undef  __MODULE__
#define __MODULE__ SAI_FDB

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_fdb_type_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static sai_status_t mlnx_fdb_port_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static sai_status_t mlnx_fdb_action_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_fdb_endpoint_ip_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg);
static sai_status_t mlnx_fdb_type_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_fdb_port_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_fdb_action_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_fdb_endpoint_ip_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static const sai_vendor_attribute_entry_t fdb_vendor_attribs[] = {
    { SAI_FDB_ENTRY_ATTR_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_fdb_type_get, NULL,
      mlnx_fdb_type_set, NULL },
    { SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_fdb_port_get, NULL,
      mlnx_fdb_port_set, NULL },
    { SAI_FDB_ENTRY_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_fdb_action_get, NULL,
      mlnx_fdb_action_set, NULL },
    { SAI_FDB_ENTRY_ATTR_ENDPOINT_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_fdb_endpoint_ip_get, NULL,
      mlnx_fdb_endpoint_ip_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static sai_status_t mlnx_add_or_del_mac(sx_fdb_uc_mac_addr_params_t *mac_entry, sx_access_cmd_t cmd)
{
    uint32_t            entries_count = 1;
    const char         *cmd_name      = cmd == SX_ACCESS_CMD_ADD ? "add" : "del";
    sx_status_t         status;
    mlnx_bridge_port_t *port;

    SX_LOG_ENTER();

    status = sx_api_fdb_uc_mac_addr_set(gh_sdk, cmd, DEFAULT_ETH_SWID, mac_entry, &entries_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to %s %d fdb entries %s.\n", cmd_name, entries_count, SX_STATUS_MSG(status));
        SX_LOG_ERR("[%02x:%02x:%02x:%02x:%02x:%02x], vlan %d, log port 0x%x, entry type %u, action %u, dest type %u\n",
                   mac_entry->mac_addr.ether_addr_octet[0],
                   mac_entry->mac_addr.ether_addr_octet[1],
                   mac_entry->mac_addr.ether_addr_octet[2],
                   mac_entry->mac_addr.ether_addr_octet[3],
                   mac_entry->mac_addr.ether_addr_octet[4],
                   mac_entry->mac_addr.ether_addr_octet[5],
                   mac_entry->fid_vid,
                   mac_entry->log_port,
                   mac_entry->entry_type,
                   mac_entry->action,
                   mac_entry->dest_type);
        return sdk_to_sai(status);
    }

    /* Check if this entry is CPU port related */
    if (SX_FDB_IS_PORT_REDUNDANT(mac_entry->entry_type, mac_entry->action)) {
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }
    if (mac_entry->entry_type == SX_FDB_UC_AGEABLE) {
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }
    if (mlnx_log_port_is_cpu(mac_entry->log_port)) {
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    sai_db_write_lock();

    if (mac_entry->log_port == g_sai_db_ptr->sx_nve_log_port) {
        sai_db_unlock();
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_bridge_port_by_log(mac_entry->log_port, &port);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_ERR("Failed to get port using log port 0x%x\n", mac_entry->log_port);
        SX_LOG_EXIT();
        return status;
    }
    if (cmd == SX_ACCESS_CMD_ADD) {
        port->fdbs++;
    } else if (port->fdbs) {
        port->fdbs--;
    }
    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_add_mac(sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    return mlnx_add_or_del_mac(mac_entry, SX_ACCESS_CMD_ADD);
}

static sai_status_t mlnx_del_mac(sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    return mlnx_add_or_del_mac(mac_entry, SX_ACCESS_CMD_DELETE);
}

static sai_status_t mlnx_fdb_entry_to_sdk(const sai_fdb_entry_t *fdb_entry, sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    sai_status_t status;

    if (fdb_entry->bridge_type == SAI_FDB_ENTRY_BRIDGE_TYPE_1Q) {
        mac_entry->fid_vid = fdb_entry->vlan_id;
    } else if (fdb_entry->bridge_type == SAI_FDB_ENTRY_BRIDGE_TYPE_1D) {
        status = mlnx_bridge_oid_to_id(fdb_entry->bridge_id, (sx_bridge_id_t*)&mac_entry->fid_vid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to fill fid_vid with bridge id\n");
            return status;
        }
    } else {
        SX_LOG_ERR("Invalid fdb entry bridge type %u\n", fdb_entry->bridge_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memcpy(&mac_entry->mac_addr, fdb_entry->mac_address, sizeof(mac_entry->mac_addr));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_get_mac(const sai_fdb_entry_t *fdb_entry, sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    uint32_t                    entries_count = 1;
    sx_fdb_uc_mac_addr_params_t mac_key;
    sx_fdb_uc_key_filter_t      filter;
    sx_status_t                 status;

    SX_LOG_ENTER();

    status = mlnx_fdb_entry_to_sdk(fdb_entry, &mac_key);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai_fdb_entry_t to SDK params\n");
        return status;
    }

    memset(&filter, 0, sizeof(filter));

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_fdb_uc_mac_addr_get(gh_sdk, DEFAULT_ETH_SWID, SX_ACCESS_CMD_GET, SX_FDB_UC_ALL, &mac_key, &filter,
                                        mac_entry, &entries_count))) {
        SX_LOG_ERR("Failed to get %d fdb entries %s.\n", entries_count, SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_get_n_delete_mac(const sai_fdb_entry_t *fdb_entry, sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    sai_status_t status;

    SX_LOG_ENTER();

    status = mlnx_get_mac(fdb_entry, mac_entry);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to get mac\n");
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_del_mac(mac_entry);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_translate_sai_action_to_sdk(sai_int32_t                  action,
                                              sx_fdb_uc_mac_addr_params_t *mac_entry,
                                              uint32_t                     param_index)
{
    switch (action) {
    case SAI_PACKET_ACTION_FORWARD:
        mac_entry->action = SX_FDB_ACTION_FORWARD;
        break;

    case SAI_PACKET_ACTION_TRAP:
        mac_entry->action = SX_FDB_ACTION_TRAP;
        break;

    case SAI_PACKET_ACTION_LOG:
        mac_entry->action = SX_FDB_ACTION_MIRROR_TO_CPU;
        break;

    case SAI_PACKET_ACTION_DROP:
        mac_entry->action = SX_FDB_ACTION_DISCARD;
        break;

    default:
        SX_LOG_ERR("Invalid fdb action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_translate_sai_type_to_sdk(sai_int32_t                  type,
                                                   sx_fdb_uc_mac_addr_params_t *mac_entry,
                                                   uint32_t                     param_index)
{
    switch (type) {
    case SAI_FDB_ENTRY_TYPE_DYNAMIC:
        mac_entry->entry_type = SX_FDB_UC_AGEABLE;
        break;

    case SAI_FDB_ENTRY_TYPE_STATIC:
        mac_entry->entry_type = SX_FDB_UC_STATIC;
        break;

    default:
        SX_LOG_ERR("Invalid fdb entry type %d\n", type);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

static void fdb_key_to_str(_In_ const sai_fdb_entry_t* fdb_entry, _Out_ char *key_str)
{
    snprintf(key_str, MAX_KEY_STR_LEN, "fdb entry mac [%02x:%02x:%02x:%02x:%02x:%02x] vlan %u bridge %lx",
             fdb_entry->mac_address[0],
             fdb_entry->mac_address[1],
             fdb_entry->mac_address[2],
             fdb_entry->mac_address[3],
             fdb_entry->mac_address[4],
             fdb_entry->mac_address[5],
             fdb_entry->vlan_id,
             fdb_entry->bridge_id);
}

/*
 * Routine Description:
 *    Create FDB entry
 *
 * Arguments:
 *    [in] fdb_entry - fdb entry
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_fdb_entry(_In_ const sai_fdb_entry_t* fdb_entry,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status, ip_status;
    const sai_attribute_value_t *type, *action, *port, *ip_addr;
    sai_packet_action_t          packet_action;
    uint32_t                     type_index, action_index, port_index, ip_index;
    sx_fdb_uc_mac_addr_params_t  check_entry;
    sx_fdb_uc_mac_addr_params_t  mac_entry;
    sx_tunnel_id_t               sx_tunnel_id;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    sx_port_log_id_t             port_id;
    mlnx_bridge_port_t          *bridge_port;

    SX_LOG_ENTER();

    if (NULL == fdb_entry) {
        SX_LOG_ERR("NULL fdb entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_FDB_ENTRY, fdb_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    fdb_key_to_str(fdb_entry, key_str);
    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_FDB_ENTRY, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create FDB entry %s\n", key_str);
    SX_LOG_NTC("Attribs %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_FDB_ENTRY_ATTR_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_translate_sai_type_to_sdk(type->s32, &mac_entry, type_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_FDB_ENTRY_ATTR_PACKET_ACTION, &action, &action_index);
    if (SAI_ERR(status)) {
        packet_action = SAI_PACKET_ACTION_FORWARD;
    } else {
        packet_action = action->s32;
    }

    status = mlnx_translate_sai_action_to_sdk(packet_action, &mac_entry, action_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    ip_status = find_attrib_in_list(attr_count, attr_list, SAI_FDB_ENTRY_ATTR_ENDPOINT_IP, &ip_addr, &ip_index);

    status = find_attrib_in_list(attr_count, attr_list, SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, &port, &port_index);
    if (SAI_ERR(status) || (SAI_NULL_OBJECT_ID == port->oid)) {
        if (false == SX_FDB_IS_PORT_REDUNDANT(mac_entry.entry_type, mac_entry.action)) {
            SX_LOG_NTC("Failed to create FDB Entry - action (%d) needs a port id attribute\n", packet_action);
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }

        if (SAI_PACKET_ACTION_TRAP != packet_action) {
            packet_action = SAI_PACKET_ACTION_DROP;
        }

        /* log port is redundant */
        port_id = 0;
    } else if (SAI_ERR(ip_status)) {
        status = mlnx_bridge_port_sai_to_log_port(port->oid, &port_id);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        sai_db_read_lock();
        status = mlnx_bridge_port_by_oid(port->oid, &bridge_port);
        if (SAI_ERR(status)) {
            sai_db_unlock();
            SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 "\n", port->oid);
            goto out;
        }
        if (bridge_port->port_type != SAI_BRIDGE_PORT_TYPE_TUNNEL) {
            SX_LOG_ERR("Invalid bridge port type %d, SAI_BRIDGE_PORT_TYPE_TUNNEL is only supported when endpoint ip is passed\n",
                       bridge_port->port_type);
            sai_db_unlock();
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        sx_tunnel_id = g_sai_db_ptr->tunnel_db[bridge_port->tunnel_id].sx_tunnel_id;
        sai_db_unlock();
        mac_entry.dest_type = SX_FDB_UC_MAC_ADDR_DEST_TYPE_NEXT_HOP;
        mac_entry.dest.next_hop.next_hop_key.type = SX_NEXT_HOP_TYPE_TUNNEL_ENCAP;
        mac_entry.dest.next_hop.next_hop_key.next_hop_key_entry.ip_tunnel.tunnel_id = sx_tunnel_id;
        status = mlnx_translate_sai_ip_address_to_sdk(&ip_addr->ipaddr,
                                                      &mac_entry.dest.next_hop.next_hop_key.next_hop_key_entry.ip_tunnel.underlay_dip);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Error translating sai ip to sdk ip\n");
            goto out;
        }
    }

    if (!SAI_ERR(mlnx_get_mac(fdb_entry, &check_entry))) {
        status = SAI_STATUS_SUCCESS;
        goto out;
    }

    status = mlnx_fdb_entry_to_sdk(fdb_entry, &mac_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai_fdb_entry_t to SDK params\n");
        return status;
    }

    mac_entry.log_port = port_id;

    status = mlnx_add_mac(&mac_entry);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Remove FDB entry
 *
 * Arguments:
 *    [in] fdb_entry - fdb entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_fdb_entry(_In_ const sai_fdb_entry_t* fdb_entry)
{
    sx_fdb_uc_mac_addr_params_t mac_entry;
    sai_status_t                status;
    char                        key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == fdb_entry) {
        SX_LOG_ERR("NULL fdb entry param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    fdb_key_to_str(fdb_entry, key_str);
    SX_LOG_NTC("Remove FDB entry %s\n", key_str);

    status = mlnx_get_n_delete_mac(fdb_entry, &mac_entry);
    if (SAI_ERR(status)) {
        goto out;
    }
out:
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Set fdb entry attribute value
 *
 * Arguments:
 *    [in] fdb_entry - fdb entry
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_fdb_entry_attribute(_In_ const sai_fdb_entry_t* fdb_entry,
                                                 _In_ const sai_attribute_t *attr)
{
    sai_object_key_t key;
    char             key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == fdb_entry) {
        SX_LOG_ERR("NULL fdb entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memcpy(&key.key.fdb_entry, fdb_entry, sizeof(*fdb_entry));

    fdb_key_to_str(fdb_entry, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_FDB_ENTRY, fdb_vendor_attribs, attr);
}

/* Set FDB entry type [sai_fdb_entry_type_t] */
static sai_status_t mlnx_fdb_type_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t                status;
    sx_fdb_uc_mac_addr_params_t old_mac_entry, new_mac_entry;
    const sai_fdb_entry_t      *fdb_entry = &key->key.fdb_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_mac(fdb_entry, &old_mac_entry))) {
        return status;
    }

    if ((SAI_FDB_ENTRY_TYPE_DYNAMIC == value->s32) && (SX_FDB_ACTION_FORWARD != old_mac_entry.action)) {
        SX_LOG_ERR("Failed to update FDB Entry Type - Dynamic entries can only have Forward action\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    new_mac_entry = old_mac_entry;

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_type_to_sdk(value->s32, &new_mac_entry, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_del_mac(&old_mac_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_add_mac(&new_mac_entry))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* FDB entry port id [sai_object_id_t] (MANDATORY_ON_CREATE|CREATE_AND_SET)
 * The port id here can refer to a generic port object such as SAI port object id,
 * SAI LAG object id and etc. on. */
static sai_status_t mlnx_fdb_port_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t                status;
    sx_fdb_uc_mac_addr_params_t old_mac_entry, new_mac_entry;
    const sai_fdb_entry_t      *fdb_entry = &key->key.fdb_entry;
    sx_port_log_id_t            port_id;

    SX_LOG_ENTER();

    status = mlnx_get_mac(fdb_entry, &old_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    new_mac_entry = old_mac_entry;

    if (SAI_NULL_OBJECT_ID == value->oid) {
        if (SX_FDB_ACTION_TRAP != old_mac_entry.action) {
            new_mac_entry.action = SX_FDB_ACTION_DISCARD;
        }

        new_mac_entry.log_port = 0;
    } else {
        status = mlnx_bridge_port_sai_to_log_port(value->oid, &port_id);
        if (SAI_ERR(status)) {
            return status;
        }

        mlnx_fdb_route_action_fetch(SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry, &new_mac_entry);

        new_mac_entry.log_port = port_id;
    }

    status = mlnx_del_mac(&old_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_add_mac(&new_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Set FDB entry packet action [sai_packet_action_t] */
static sai_status_t mlnx_fdb_action_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t                status;
    sx_fdb_uc_mac_addr_params_t old_mac_entry, new_mac_entry;
    const sai_fdb_entry_t      *fdb_entry = &key->key.fdb_entry;

    SX_LOG_ENTER();

    status = mlnx_get_mac(fdb_entry, &old_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    new_mac_entry = old_mac_entry;

    if ((SX_FDB_IS_PORT_REDUNDANT(old_mac_entry.entry_type, old_mac_entry.action)) &&
        ((SAI_PACKET_ACTION_FORWARD == value->s32) || (SAI_PACKET_ACTION_LOG == value->s32))) {
        status = mlnx_fdb_route_action_save(SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry, value->s32);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = mlnx_translate_sai_action_to_sdk(value->s32, &new_mac_entry, 0);
        if (SAI_ERR(status)) {
            return status;
        }

        mlnx_fdb_route_action_clear(SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry);
    }

    status = mlnx_del_mac(&old_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_add_mac(&new_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Set FDB entry endpoint ip [sai_ip_address_t] */
static sai_status_t mlnx_fdb_endpoint_ip_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t                status;
    sx_fdb_uc_mac_addr_params_t old_mac_entry, new_mac_entry;
    const sai_fdb_entry_t      *fdb_entry = &key->key.fdb_entry;

    SX_LOG_ENTER();

    status = mlnx_get_mac(fdb_entry, &old_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    new_mac_entry = old_mac_entry;

    status = mlnx_translate_sai_ip_address_to_sdk(&value->ipaddr,
                                                  &new_mac_entry.dest.next_hop.next_hop_key.next_hop_key_entry.ip_tunnel.underlay_dip);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_del_mac(&old_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_add_mac(&new_mac_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Get fdb entry attribute value
 *
 * Arguments:
 *    [in] fdb_entry - fdb entry
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_fdb_entry_attribute(_In_ const sai_fdb_entry_t* fdb_entry,
                                                 _In_ uint32_t               attr_count,
                                                 _Inout_ sai_attribute_t    *attr_list)
{
    sai_object_key_t key;
    char             key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == fdb_entry) {
        SX_LOG_ERR("NULL fdb entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memcpy(&key.key.fdb_entry, fdb_entry, sizeof(*fdb_entry));

    fdb_key_to_str(fdb_entry, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_FDB_ENTRY, fdb_vendor_attribs, attr_count, attr_list);
}

static sai_status_t fill_fdb_cache(mlnx_fdb_cache_t *fdb_cache, const sai_fdb_entry_t *fdb_entry)
{
    sai_status_t                status;
    sx_fdb_uc_mac_addr_params_t mac_entry;

    if (fdb_cache->fdb_cache_set) {
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_mac(fdb_entry, &mac_entry))) {
        return status;
    }

    fdb_cache->fdb_cache_set = true;
    fdb_cache->action        = mac_entry.action;
    fdb_cache->entry_type    = mac_entry.entry_type;
    fdb_cache->log_port      = mac_entry.log_port;
    memcpy(&fdb_cache->endpoint_ip,
           &mac_entry.dest.next_hop.next_hop_key.next_hop_key_entry.ip_tunnel.underlay_dip,
           sizeof(fdb_cache->endpoint_ip));

    return SAI_STATUS_SUCCESS;
}

/* Get FDB entry type [sai_fdb_entry_type_t] */
static sai_status_t mlnx_fdb_type_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_status_t           status;
    const sai_fdb_entry_t *fdb_entry = &key->key.fdb_entry;
    mlnx_fdb_cache_t      *fdb_cache = &(cache->fdb_cache);

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = fill_fdb_cache(fdb_cache, fdb_entry))) {
        return status;
    }

    switch (fdb_cache->entry_type) {
    case SX_FDB_UC_STATIC:
        value->s32 = SAI_FDB_ENTRY_TYPE_STATIC;
        break;

    case SX_FDB_UC_REMOTE:
    case SX_FDB_UC_AGEABLE:
        value->s32 = SAI_FDB_ENTRY_TYPE_DYNAMIC;
        break;

    default:
        SX_LOG_ERR("Unexpected entry type %d\n", fdb_cache->entry_type);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* FDB entry port id [sai_object_id_t] (MANDATORY_ON_CREATE|CREATE_AND_SET)
 * The port id here can refer to a generic port object such as SAI port object id,
 * SAI LAG object id and etc. on.
 * Port 0 is returned for entries with action = drop or action = trap
 * Since port is irrelevant for these actions, even if actual port is set
 * In case the action is changed from drop/trap to forward/log, need to also set port
 */
static sai_status_t mlnx_fdb_port_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_status_t           status;
    const sai_fdb_entry_t *fdb_entry = &key->key.fdb_entry;
    mlnx_fdb_cache_t      *fdb_cache = &(cache->fdb_cache);

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = fill_fdb_cache(fdb_cache, fdb_entry))) {
        return status;
    }

    if (SX_FDB_ACTION_DISCARD == fdb_cache->action) {
        value->oid = SAI_NULL_OBJECT_ID;
    } else {
        status = mlnx_log_port_to_sai_bridge_port(fdb_cache->log_port, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get FDB entry packet action [sai_packet_action_t] */
static sai_status_t mlnx_fdb_action_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t           status;
    const sai_fdb_entry_t *fdb_entry = &key->key.fdb_entry;
    mlnx_fdb_cache_t      *fdb_cache = &(cache->fdb_cache);

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = fill_fdb_cache(fdb_cache, fdb_entry))) {
        return status;
    }

    switch (fdb_cache->action) {
    case SX_FDB_ACTION_FORWARD:
        value->s32 = SAI_PACKET_ACTION_FORWARD;
        break;

    case SX_FDB_ACTION_TRAP:
        value->s32 = SAI_PACKET_ACTION_TRAP;
        break;

    case SX_FDB_ACTION_MIRROR_TO_CPU:
        value->s32 = SAI_PACKET_ACTION_LOG;
        break;

    case SX_FDB_ACTION_DISCARD:
        value->s32 = SAI_PACKET_ACTION_DROP;
        break;

    case SX_FDB_ACTION_FORWARD_TO_ROUTER:
    default:
        SX_LOG_ERR("Unexpected fdb action %d\n", fdb_cache->action);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get FDB entry endpoint ip [sai_ip_address_t] */
static sai_status_t mlnx_fdb_endpoint_ip_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t           status;
    const sai_fdb_entry_t *fdb_entry = &key->key.fdb_entry;
    mlnx_fdb_cache_t      *fdb_cache = &(cache->fdb_cache);

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = fill_fdb_cache(fdb_cache, fdb_entry))) {
        return status;
    }

    status = mlnx_translate_sdk_ip_address_to_sai(&fdb_cache->endpoint_ip,
                                                  &value->ipaddr);

    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove all FDB entries by attribute set in sai_fdb_flush_attr
 *
 * Arguments:
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_flush_fdb_entries(_In_ sai_object_id_t        switch_id,
                                           _In_ uint32_t               attr_count,
                                           _In_ const sai_attribute_t *attr_list)
{
    sx_status_t                  status;
    const sai_attribute_value_t *port, *vlan, *type;
    uint32_t                     port_index, vlan_index, type_index;
    bool                         port_found = false, vlan_found = false;
    sx_port_log_id_t             port_id;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_FDB_FLUSH_ATTR_BRIDGE_PORT_ID,
                                 &port, &port_index))) {
        port_found = true;

        status = mlnx_bridge_port_sai_to_log_port(port->oid, &port_id);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_FDB_FLUSH_ATTR_VLAN_ID,
                                 &vlan, &vlan_index))) {
        vlan_found = true;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_FDB_FLUSH_ATTR_ENTRY_TYPE,
                                 &type, &type_index))) {
        if (SAI_FDB_FLUSH_ENTRY_TYPE_DYNAMIC != type->s32) {
            SX_LOG_ERR("Flush of static FDB entries is not implemented, got %d.\n", type->s32);
            return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + type_index;
        }
    }

    /* Mellanox implementation flushes only dynamic entries. Static entries should be deleted with entry remove */
    if ((!port_found) && (!vlan_found)) {
        if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_all_set(gh_sdk, DEFAULT_ETH_SWID))) {
            SX_LOG_ERR("Failed to flush all fdb entries - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    } else if ((port_found) && (vlan_found)) {
        if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_port_fid_set(gh_sdk, port_id, vlan->u16))) {
            SX_LOG_ERR("Failed to flush port vlan fdb entries - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    } else if (port_found) {
        if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_port_set(gh_sdk, port_id))) {
            SX_LOG_ERR("Failed to flush port fdb entries - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    } else if (vlan_found) {
        if (SX_STATUS_SUCCESS != (status = sx_api_fdb_uc_flush_fid_set(gh_sdk, DEFAULT_ETH_SWID, vlan->u16))) {
            SX_LOG_ERR("Failed to flush vlan fdb entries - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

bool mlnx_fdb_is_flood_disabled()
{
    return ((g_sai_db_ptr->flood_action_uc == SAI_PACKET_ACTION_DROP) ||
            (g_sai_db_ptr->flood_action_bc == SAI_PACKET_ACTION_DROP));
}

sai_status_t mlnx_fdb_port_event_handle(mlnx_bridge_port_t *port, uint16_t vid, sai_port_event_t event)
{
    bool add;

    add = (event == SAI_PORT_EVENT_ADD);

    return mlnx_fdb_flood_control_set(vid, &port->logical, 1, add);
}

sai_status_t mlnx_fdb_flood_control_set(_In_ sx_vid_t                vlan_id,
                                        _In_ const sx_port_log_id_t *sx_ports,
                                        _In_ uint32_t                ports_count,
                                        _In_ bool                    add)
{
    sx_status_t     sx_status;
    sx_access_cmd_t flood_cmd;

    assert(sx_ports);

    flood_cmd = add ? SX_ACCESS_CMD_ADD_PORTS : SX_ACCESS_CMD_DELETE_PORTS;

    if (g_sai_db_ptr->flood_action_uc == SAI_PACKET_ACTION_DROP) {
        sx_status = sx_api_fdb_flood_control_set(gh_sdk, flood_cmd, DEFAULT_ETH_SWID, vlan_id,
                                                 SX_FLOOD_CONTROL_TYPE_UNICAST_E, ports_count, sx_ports);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to update FDB ucast flood list - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    if (g_sai_db_ptr->flood_action_bc == SAI_PACKET_ACTION_DROP) {
        sx_status = sx_api_fdb_flood_control_set(gh_sdk, flood_cmd, DEFAULT_ETH_SWID, vlan_id,
                                                 SX_FLOOD_CONTROL_TYPE_BROADCAST_E, ports_count, sx_ports);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to update FDB bcast flood list - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_fdb_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_fdb_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_fdb_api_t mlnx_fdb_api = {
    mlnx_create_fdb_entry,
    mlnx_remove_fdb_entry,
    mlnx_set_fdb_entry_attribute,
    mlnx_get_fdb_entry_attribute,
    mlnx_flush_fdb_entries
};
