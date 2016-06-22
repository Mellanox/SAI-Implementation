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
static const sai_attribute_entry_t        fdb_attribs[] = {
    { SAI_FDB_ENTRY_ATTR_TYPE, true, true, true, true,
      "FDB entry type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_FDB_ENTRY_ATTR_PORT_ID, true, true, true, true,
      "FDB entry port id", SAI_ATTR_VAL_TYPE_OID},
    { SAI_FDB_ENTRY_ATTR_PACKET_ACTION, true, true, true, true,
      "FDB entry packet action", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t fdb_vendor_attribs[] = {
    { SAI_FDB_ENTRY_ATTR_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_fdb_type_get, NULL,
      mlnx_fdb_type_set, NULL },
    { SAI_FDB_ENTRY_ATTR_PORT_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_fdb_port_get, NULL,
      mlnx_fdb_port_set, NULL },
    { SAI_FDB_ENTRY_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_fdb_action_get, NULL,
      mlnx_fdb_action_set, NULL }
};
static sai_status_t mlnx_add_mac(sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    sx_status_t status;
    uint32_t    entries_count = 1;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_fdb_uc_mac_addr_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, mac_entry, &entries_count))) {
        SX_LOG_ERR("Failed to add %d fdb entries %s.\n", entries_count, SX_STATUS_MSG(status));
        SX_LOG_ERR("[%02x:%02x:%02x:%02x:%02x:%02x], vlan %d\n",
                   mac_entry->mac_addr.ether_addr_octet[0],
                   mac_entry->mac_addr.ether_addr_octet[1],
                   mac_entry->mac_addr.ether_addr_octet[2],
                   mac_entry->mac_addr.ether_addr_octet[3],
                   mac_entry->mac_addr.ether_addr_octet[4],
                   mac_entry->mac_addr.ether_addr_octet[5],
                   mac_entry->fid_vid);
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_delete_mac(sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    sx_status_t status;
    uint32_t    entries_count = 1;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_fdb_uc_mac_addr_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, mac_entry, &entries_count))) {
        SX_LOG_ERR("Failed to delete %d fdb entries %s.\n", entries_count, SX_STATUS_MSG(status));
        SX_LOG_ERR("[%02x:%02x:%02x:%02x:%02x:%02x], vlan %d\n",
                   mac_entry->mac_addr.ether_addr_octet[0],
                   mac_entry->mac_addr.ether_addr_octet[1],
                   mac_entry->mac_addr.ether_addr_octet[2],
                   mac_entry->mac_addr.ether_addr_octet[3],
                   mac_entry->mac_addr.ether_addr_octet[4],
                   mac_entry->mac_addr.ether_addr_octet[5],
                   mac_entry->fid_vid);
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_get_mac(const sai_fdb_entry_t *fdb_entry, sx_fdb_uc_mac_addr_params_t *mac_entry)
{
    sx_status_t                 status;
    uint32_t                    entries_count = 1;
    sx_fdb_uc_mac_addr_params_t mac_key;
    sx_fdb_uc_key_filter_t      filter;

    SX_LOG_ENTER();

    mac_key.fid_vid = fdb_entry->vlan_id;
    memcpy(&mac_key.mac_addr, fdb_entry->mac_address, sizeof(mac_key.mac_addr));
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
        return status;
    }

    status = mlnx_delete_mac(mac_entry);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_translate_sai_action_to_sdk(sai_int32_t                  action,
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
    case SAI_FDB_ENTRY_DYNAMIC:
        mac_entry->entry_type = SX_FDB_UC_AGEABLE;
        break;

    case SAI_FDB_ENTRY_STATIC:
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
    snprintf(key_str, MAX_KEY_STR_LEN, "fdb entry mac [%02x:%02x:%02x:%02x:%02x:%02x] vlan %u",
             fdb_entry->mac_address[0],
             fdb_entry->mac_address[1],
             fdb_entry->mac_address[2],
             fdb_entry->mac_address[3],
             fdb_entry->mac_address[4],
             fdb_entry->mac_address[5],
             fdb_entry->vlan_id);
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
    sai_status_t                 status;
    const sai_attribute_value_t *type, *action, *port;
    uint32_t                     type_index, action_index, port_index;
    sx_fdb_uc_mac_addr_params_t  mac_entry;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    sx_port_log_id_t             port_id;

    SX_LOG_ENTER();

    if (NULL == fdb_entry) {
        SX_LOG_ERR("NULL fdb entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, fdb_attribs, fdb_vendor_attribs, SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    fdb_key_to_str(fdb_entry, key_str);
    sai_attr_list_to_str(attr_count, attr_list, fdb_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create FDB entry %s\n", key_str);
    SX_LOG_NTC("Attribs %s\n", list_str);

    assert(SAI_STATUS_SUCCESS == find_attrib_in_list(attr_count,
                                                     attr_list,
                                                     SAI_FDB_ENTRY_ATTR_TYPE,
                                                     &type,
                                                     &type_index));
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_FDB_ENTRY_ATTR_PACKET_ACTION, &action, &action_index));
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_FDB_ENTRY_ATTR_PORT_ID, &port, &port_index));

    if (SAI_OBJECT_TYPE_LAG == sai_object_type_query(port->oid)) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(port->oid, SAI_OBJECT_TYPE_LAG, &port_id, NULL))) {
            return status;
        }
    } else {
        if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(port->oid, SAI_OBJECT_TYPE_PORT, &port_id, NULL))) {
            return status;
        }
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_action_to_sdk(action->s32, &mac_entry, action_index))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_type_to_sdk(type->s32, &mac_entry, type_index))) {
        return status;
    }

    mac_entry.fid_vid  = fdb_entry->vlan_id;
    mac_entry.log_port = port_id;
    memcpy(&mac_entry.mac_addr, fdb_entry->mac_address, sizeof(mac_entry.mac_addr));

    if (SAI_STATUS_SUCCESS != (status = mlnx_add_mac(&mac_entry))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
        return SAI_STATUS_INVALID_PARAMETER;
    }

    fdb_key_to_str(fdb_entry, key_str);
    SX_LOG_NTC("Remove FDB entry %s\n", key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_n_delete_mac(fdb_entry, &mac_entry))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    const sai_object_key_t key = {.fdb_entry = fdb_entry };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == fdb_entry) {
        SX_LOG_ERR("NULL fdb entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    fdb_key_to_str(fdb_entry, key_str);
    return sai_set_attribute(&key, key_str, fdb_attribs, fdb_vendor_attribs, attr);
}

/* Set FDB entry type [sai_fdb_entry_type_t] */
static sai_status_t mlnx_fdb_type_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t                status;
    sx_fdb_uc_mac_addr_params_t mac_entry;
    const sai_fdb_entry_t      *fdb_entry = key->fdb_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_n_delete_mac(fdb_entry, &mac_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_type_to_sdk(value->s32, &mac_entry, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_add_mac(&mac_entry))) {
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
    sx_fdb_uc_mac_addr_params_t mac_entry;
    const sai_fdb_entry_t      *fdb_entry = key->fdb_entry;
    sx_port_log_id_t            port_id;

    SX_LOG_ENTER();

    if (SAI_OBJECT_TYPE_LAG == sai_object_type_query(value->oid)) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(value->oid, SAI_OBJECT_TYPE_LAG, &port_id, NULL))) {
            return status;
        }
    } else {
        if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(value->oid, SAI_OBJECT_TYPE_PORT, &port_id, NULL))) {
            return status;
        }
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_n_delete_mac(fdb_entry, &mac_entry))) {
        return status;
    }

    mac_entry.log_port = port_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_add_mac(&mac_entry))) {
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
    sx_fdb_uc_mac_addr_params_t mac_entry;
    const sai_fdb_entry_t      *fdb_entry = key->fdb_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_n_delete_mac(fdb_entry, &mac_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_action_to_sdk(value->s32, &mac_entry, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_add_mac(&mac_entry))) {
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
    const sai_object_key_t key = { .fdb_entry = fdb_entry };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == fdb_entry) {
        SX_LOG_ERR("NULL fdb entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    fdb_key_to_str(fdb_entry, key_str);
    return sai_get_attributes(&key, key_str, fdb_attribs, fdb_vendor_attribs, attr_count, attr_list);
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
    const sai_fdb_entry_t *fdb_entry = key->fdb_entry;
    mlnx_fdb_cache_t      *fdb_cache = &(cache->fdb_cache);

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = fill_fdb_cache(fdb_cache, fdb_entry))) {
        return status;
    }

    switch (fdb_cache->entry_type) {
    case SX_FDB_UC_STATIC:
        value->s32 = SAI_FDB_ENTRY_STATIC;
        break;

    case SX_FDB_UC_REMOTE:
    case SX_FDB_UC_AGEABLE:
        value->s32 = SAI_FDB_ENTRY_DYNAMIC;
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
    const sai_fdb_entry_t *fdb_entry = key->fdb_entry;
    mlnx_fdb_cache_t      *fdb_cache = &(cache->fdb_cache);

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = fill_fdb_cache(fdb_cache, fdb_entry))) {
        return status;
    }

    if (SX_PORT_TYPE_LAG == SX_PORT_TYPE_ID_GET(fdb_cache->log_port)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, fdb_cache->log_port, NULL, &value->oid))) {
            return status;
        }
    } else {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, fdb_cache->log_port, NULL, &value->oid))) {
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
    const sai_fdb_entry_t *fdb_entry = key->fdb_entry;
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
static sai_status_t mlnx_flush_fdb_entries(_In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list)
{
    sx_status_t                  status;
    const sai_attribute_value_t *port, *vlan, *type;
    uint32_t                     port_index, vlan_index, type_index;
    bool                         port_found = false, vlan_found = false;
    sx_port_log_id_t             port_id;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_FDB_FLUSH_ATTR_PORT_ID,
                                 &port, &port_index))) {
        port_found = true;
        if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(port->oid, SAI_OBJECT_TYPE_PORT, &port_id, NULL))) {
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
        if (SAI_FDB_FLUSH_ENTRY_DYNAMIC != type->s32) {
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
