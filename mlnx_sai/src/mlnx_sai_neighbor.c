/*
 *  Copyright (C) 2017-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#define __MODULE__ SAI_NEIGHBOR

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_neighbor_mac_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_neighbor_action_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_neighbor_no_host_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_neighbor_mac_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
static sai_status_t mlnx_neighbor_action_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg);
static sai_status_t mlnx_neighbor_no_host_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_neighbor_trap_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_neighbor_trap_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static sai_status_t mlnx_get_neighbor(const sai_neighbor_entry_t* neighbor_entry, sx_neigh_get_entry_t *neigh_entry);

static const sai_vendor_attribute_entry_t neighbor_vendor_attribs[] = {
    { SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_neighbor_mac_get, NULL,
      mlnx_neighbor_mac_set, NULL },
    { SAI_NEIGHBOR_ENTRY_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_neighbor_action_get, NULL,
      mlnx_neighbor_action_set, NULL },
    { SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_neighbor_no_host_get, NULL,
      mlnx_neighbor_no_host_set, NULL },
    { SAI_NEIGHBOR_ENTRY_ATTR_USER_TRAP_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_neighbor_trap_get, NULL,
      mlnx_neighbor_trap_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        neighbor_enum_info[] = {
    [SAI_NEIGHBOR_ENTRY_ATTR_PACKET_ACTION] = ATTR_ENUM_VALUES_LIST(
        SAI_PACKET_ACTION_FORWARD,
        SAI_PACKET_ACTION_TRAP,
        SAI_PACKET_ACTION_LOG,
        SAI_PACKET_ACTION_DROP
        )
};
static size_t neighbor_entry_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    int written_chars = 0;

    sai_ipaddr_to_str(key->key.neighbor_entry.ip_address, max_len, str, &written_chars);
    written_chars +=
        snprintf(str + written_chars, max_len - written_chars, "RIF:0x%lX", key->key.neighbor_entry.rif_id);
    return written_chars;
}
const mlnx_obj_type_attrs_info_t mlnx_neighbor_obj_type_info =
{ neighbor_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(neighbor_enum_info), OBJ_STAT_CAP_INFO_EMPTY(),
  neighbor_entry_info_print};

static sai_status_t mlnx_translate_sai_neighbor_entry_to_sdk(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                                             _Out_ sx_ip_addr_t              *ip_addr_p)
{
    return mlnx_translate_sai_ip_address_to_sdk(&neighbor_entry->ip_address, ip_addr_p);
}

/*
 * Routine Description:
 *    Create neighbor entry
 *
 * Arguments:
 *    [in] neighbor_entry - neighbor entry
 *    [in] attr_count - number of attributes
 *    [in] attrs - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP address expected in Network Byte Order.
 */
static sai_status_t mlnx_create_neighbor_entry(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                               _In_ uint32_t                    attr_count,
                                               _In_ const sai_attribute_t      *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    const sai_attribute_value_t *mac, *action, *no_host, *trap;
    uint32_t                     mac_index, action_index, no_host_index, trap_index;
    sx_ip_addr_t                 ipaddr;
    sx_neigh_data_t              neigh_data;
    sx_router_interface_t        rif;
    int32_t                      packet_action;

    SX_LOG_ENTER();

    if (NULL == neighbor_entry) {
        SX_LOG_ERR("NULL neighbor entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_on_create_without_oid(attr_count, attr_list, SAI_OBJECT_TYPE_NEIGHBOR_ENTRY);
    if (SAI_ERR(status)) {
        return status;
    }

    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_NEIGHBOR_ENTRY);

    memset(&neigh_data, 0, sizeof(neigh_data));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_rif_oid_to_sdk_rif_id(neighbor_entry->rif_id, &rif))) {
        SX_LOG_ERR("Fail to get sdk rif id from rif oid %" PRIx64 "\n", neighbor_entry->rif_id);
        SX_LOG_EXIT();
        return status;
    }

    memset(&ipaddr, 0, sizeof(ipaddr));
    neigh_data.action = SX_ROUTER_ACTION_FORWARD;

    status = find_attrib_in_list(attr_count, attr_list, SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, &mac, &mac_index);
    assert(SAI_STATUS_SUCCESS == status);
    memcpy(&neigh_data.mac_addr, mac->mac, sizeof(neigh_data.mac_addr));

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_NEIGHBOR_ENTRY_ATTR_PACKET_ACTION, &action,
                                 &action_index))) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sai_router_action_to_sdk(action->s32, &neigh_data.action, action_index))) {
            return status;
        }
        packet_action = action->s32;
    } else {
        packet_action = SAI_PACKET_ACTION_FORWARD;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, &no_host,
                                 &no_host_index))) {
        neigh_data.is_software_only = no_host->booldata;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_NEIGHBOR_ENTRY_ATTR_USER_TRAP_ID, &trap, &trap_index);
    if (SAI_ERR(status) && (status != SAI_STATUS_ITEM_NOT_FOUND)) {
        SX_LOG_ERR("Failed to find attribute\n");
        return status;
    }

    if (is_action_trap(packet_action) && (SAI_ERR(status) || (trap->oid == SAI_NULL_OBJECT_ID))) {
        SX_LOG_ERR("Trap action requires a user defined trap\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if ((!is_action_trap(packet_action)) && SAI_OK(status)) {
        SX_LOG_ERR("Invalid attribute trap id for non-trap packet action\n");
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + trap_index;
    }

    sai_db_write_lock();

    if (is_action_trap(packet_action)) {
        status = mlnx_get_user_defined_trap_prio(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, trap->oid,
                                                 &neigh_data.trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get trap priority\n");
            goto out;
        }

        status = mlnx_trap_refcount_increase(trap->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to increase trap refcount\n");
            goto out;
        }
    }

    status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sai neighbor entry to sdk\n");
        goto out;
    }

    sx_status = sx_api_router_neigh_set(get_sdk_handle(), SX_ACCESS_CMD_ADD, rif, &ipaddr, &neigh_data);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create neighbor entry - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = sdk_to_sai(sx_status);

    MLNX_LOG_KEY_CREATED(SX_LOG_NOTICE, neighbor_entry, SAI_OBJECT_TYPE_NEIGHBOR_ENTRY);

out:
    sai_db_unlock();
    SX_LOG_EXIT();

    return status;
}

static sai_status_t mlnx_remove_neighbor_trap(const sai_neighbor_entry_t *neighbor_entry)
{
    sai_packet_action_t  packet_action;
    sx_neigh_get_entry_t neigh_get_entry;
    sai_status_t         status;

    assert(neighbor_entry);

    status = mlnx_get_neighbor(neighbor_entry, &neigh_get_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get neighbor\n");
        return status;
    }

    status = mlnx_translate_sdk_router_action_to_sai(neigh_get_entry.neigh_data.action, &packet_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SDK router action to SAI\n");
        return status;
    }

    if (is_action_trap(packet_action)) {
        mlnx_trap_refcount_decrease_by_prio(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY,
                                            neigh_get_entry.neigh_data.trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrease trap refcount by prio %d\n", neigh_get_entry.neigh_data.trap_attr.prio);
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove neighbor entry
 *
 * Arguments:
 *    [in] neighbor_entry - neighbor entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP address expected in Network Byte Order.
 */
static sai_status_t mlnx_remove_neighbor_entry(_In_ const sai_neighbor_entry_t* neighbor_entry)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    sx_ip_addr_t          ipaddr;
    sx_neigh_data_t       neigh_data;
    sx_router_interface_t rif;

    SX_LOG_ENTER();

    if (NULL == neighbor_entry) {
        SX_LOG_ERR("NULL neighbor entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    MLNX_LOG_KEY_REMOVE(SX_LOG_NOTICE, neighbor_entry, SAI_OBJECT_TYPE_NEIGHBOR_ENTRY);

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&neigh_data, 0, sizeof(neigh_data));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_rif_oid_to_sdk_rif_id(neighbor_entry->rif_id, &rif))) {
        SX_LOG_ERR("Fail to get sdk rif id from rif oid %" PRIx64 "\n", neighbor_entry->rif_id);
        SX_LOG_EXIT();
        return status;
    }

    sai_db_write_lock();

    status = mlnx_remove_neighbor_trap(neighbor_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unbind trap from neighbor\n");
        goto out;
    }

    sx_status = sx_api_router_neigh_set(get_sdk_handle(), SX_ACCESS_CMD_DELETE, rif, &ipaddr, &neigh_data);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove neighbor entry - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Set neighbor attribute value
 *
 * Arguments:
 *    [in] neighbor_entry - neighbor entry
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_neighbor_attribute(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                                _In_ const sai_attribute_t      *attr)
{
    sai_object_key_t key;

    if (!neighbor_entry) {
        SX_LOG_ERR("Entry is NULL.\n");
        return SAI_STATUS_FAILURE;
    }

    memcpy(&key.key.neighbor_entry, neighbor_entry, sizeof(*neighbor_entry));
    return sai_set_attribute(&key, SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, attr);
}

/*
 * Routine Description:
 *    Get neighbor attribute value
 *
 * Arguments:
 *    [in] neighbor_entry - neighbor entry
 *    [in] attr_count - number of attributes
 *    [inout] attrs - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_neighbor_attribute(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                                _In_ uint32_t                    attr_count,
                                                _Inout_ sai_attribute_t         *attr_list)
{
    sai_object_key_t key;

    if (!neighbor_entry) {
        SX_LOG_ERR("Entry is NULL.\n");
        return SAI_STATUS_FAILURE;
    }

    memcpy(&key.key.neighbor_entry, neighbor_entry, sizeof(*neighbor_entry));
    return sai_get_attributes(&key, SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, attr_count, attr_list);
}

static sai_status_t mlnx_get_neighbor(const sai_neighbor_entry_t* neighbor_entry, sx_neigh_get_entry_t *neigh_entry)
{
    sx_status_t           status;
    uint32_t              entries_count = 1;
    sx_ip_addr_t          ipaddr;
    sx_neigh_filter_t     filter;
    sx_router_interface_t sx_rif;

    SX_LOG_ENTER();

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&filter, 0, sizeof(filter));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_rif_oid_to_sdk_rif_id(neighbor_entry->rif_id, &sx_rif))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_neigh_get(get_sdk_handle(), SX_ACCESS_CMD_GET, sx_rif, &ipaddr, &filter,
                                     neigh_entry,
                                     &entries_count))) {
        SX_LOG_ERR("Failed to get %d neighbor entries %s.\n", entries_count, SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Destination mac address for the neighbor [sai_mac_t] */
static sai_status_t mlnx_neighbor_mac_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_neighbor(neighbor_entry, &neigh_entry))) {
        return status;
    }

    memcpy(value->mac, &neigh_entry.neigh_data.mac_addr, sizeof(value->mac));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* L3 forwarding action for this neighbor [sai_packet_action_t] */
static sai_status_t mlnx_neighbor_action_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;
    sai_packet_action_t         packet_action;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_neighbor(neighbor_entry, &neigh_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sdk_router_action_to_sai(neigh_entry.neigh_data.action, &packet_action))) {
        return status;
    }

    value->s32 = packet_action;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Neighbor not to be programmed as a host route entry in ASIC and to be only
 * used to setup next-hop purpose. Typical use-case is to set this true
 * for neighbor with IPv6 link-local addresses. [bool] */
static sai_status_t mlnx_neighbor_no_host_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_neighbor(neighbor_entry, &neigh_entry))) {
        return status;
    }

    value->booldata = neigh_entry.neigh_data.is_software_only;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_modify_neighbor_entry(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                               _In_ const sx_neigh_data_t      *new_neigh_data)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    sx_ip_addr_t          ipaddr;
    sx_neigh_data_t       neigh_data;
    sx_router_interface_t sx_rif;

    SX_LOG_ENTER();

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&neigh_data, 0, sizeof(neigh_data));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_rif_oid_to_sdk_rif_id(neighbor_entry->rif_id, &sx_rif))) {
        return status;
    }

    /* To modify a neighbor, we delete and read it with new data */
    sx_status = sx_api_router_neigh_set(get_sdk_handle(), SX_ACCESS_CMD_DELETE, sx_rif, &ipaddr, &neigh_data);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove neighbor entry - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_router_neigh_set(get_sdk_handle(), SX_ACCESS_CMD_ADD, sx_rif, &ipaddr, new_neigh_data);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create neighbor entry - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Destination mac address for the neighbor [sai_mac_t] */
static sai_status_t mlnx_neighbor_mac_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_neighbor(neighbor_entry, &neigh_entry))) {
        return status;
    }

    memcpy(&neigh_entry.neigh_data.mac_addr, value->mac, sizeof(neigh_entry.neigh_data.mac_addr));

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_neighbor_entry(neighbor_entry, &neigh_entry.neigh_data))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* L3 forwarding action for this neighbor [sai_packet_action_t] */

/*
 * Note:
 * Different packet action will be set depending on the action and whether trap id bound to the neighbor
 * If new action is TRAP or LOG, but current action is DROP or FORWARD. action will be changed to an action that does
 * not require trap id
 * current action DROP new action TRAP or LOG - result action DROP
 * current action FORWARD new action TRAP - result action DROP
 * current action FORWARD new action LOG - result action FORWARD
 */
static sai_status_t mlnx_neighbor_action_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;
    sai_packet_action_t         current_sai_action, action_to_configure;
    bool                        is_action_present;

    SX_LOG_ENTER();

    status = mlnx_get_neighbor(neighbor_entry, &neigh_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get neighbor data\n");
        return status;
    }

    status = mlnx_translate_sdk_router_action_to_sai(neigh_entry.neigh_data.action, &current_sai_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sdk action %d to sai\n", neigh_entry.neigh_data.action);
        return status;
    }

    if (is_action_trap(value->s32) && (!is_action_trap(current_sai_action))) {
        status = mlnx_translate_action_to_no_trap(value->s32, &action_to_configure, &is_action_present);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate action %d to non-trap action\n", value->s32);
            return status;
        }
    } else {
        action_to_configure = value->s32;
    }

    if (current_sai_action == action_to_configure) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_translate_sai_router_action_to_sdk(action_to_configure, &neigh_entry.neigh_data.action, 0);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SAI action %d to SDK\n", action_to_configure);
        return status;
    }

    status = mlnx_modify_neighbor_entry(neighbor_entry, &neigh_entry.neigh_data);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to modify neighbor sx\n");
        return status;
    }

    sai_db_write_lock();

    if (is_action_trap(current_sai_action) && (!is_action_trap(action_to_configure))) {
        status = mlnx_trap_refcount_decrease_by_prio(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY,
                                                     neigh_entry.neigh_data.trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrease trap refcount by prio %d\n", neigh_entry.neigh_data.trap_attr.prio);
            goto out;
        }
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_neighbor_trap_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;
    sai_packet_action_t         packet_action;

    status = mlnx_get_neighbor(neighbor_entry, &neigh_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get neighbor data\n");
        return status;
    }

    status = mlnx_translate_sdk_router_action_to_sai(neigh_entry.neigh_data.action, &packet_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SDK router action %d to SAI\n", neigh_entry.neigh_data.action);
        return status;
    }

    sai_db_read_lock();
    if (is_action_trap(packet_action)) {
        status = mlnx_get_user_defined_trap_by_prio(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY,
                                                    neigh_entry.neigh_data.trap_attr.prio,
                                                    &value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup trap oid by trap prio %d\n", neigh_entry.neigh_data.trap_attr.prio);
            goto out;
        }
    } else {
        value->oid = SAI_NULL_OBJECT_ID;
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/*
 * Trap set may change the action that is configured in the neighbor in following cases
 * > If current action is DROP and trap id provided is not SAI_NULL_OBJECT_ID TRAP packet action will be configured
 * > If current action is FORWARD and trap id provided is not SAI_NULL_OBJECT_ID LOG packet action will be configured
 * > If current action is LOG and trap id provided is SAI_NULL_OBJECT_ID FORWARD packet action will be configured
 * > If current action is TRAP and trap id provided is SAI_NULL_OBJECT_ID DROP packet action will be configured
 *
 * In other cases neighbor packet action will remain the same
 */
static sai_status_t mlnx_neighbor_trap_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;
    sai_packet_action_t         current_action, action_to_configure;
    sai_object_id_t             current_trap = SAI_NULL_OBJECT_ID;
    bool                        is_action_present;

    SX_LOG_ENTER();

    status = mlnx_get_neighbor(neighbor_entry, &neigh_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get neighbor data\n");
        return status;
    }

    status = mlnx_translate_sdk_router_action_to_sai(neigh_entry.neigh_data.action, &current_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sdk action %d to sai\n", neigh_entry.neigh_data.action);
        return status;
    }

    sai_db_write_lock();

    if (value->oid != SAI_NULL_OBJECT_ID) {
        if (!mlnx_is_hostif_user_defined_trap_valid_for_set(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, value->oid)) {
            SX_LOG_ERR("Invalid trap id 0x%" PRIx64 "\n", value->oid);
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
    }

    if (is_action_trap(current_action)) {
        status = mlnx_get_user_defined_trap_by_prio(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY,
                                                    neigh_entry.neigh_data.trap_attr.prio, &current_trap);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get current trap id by prio %d\n", neigh_entry.neigh_data.trap_attr.prio);
            goto out;
        }
    }

    if (current_trap == value->oid) {
        goto out;
    }

    if ((value->oid != SAI_NULL_OBJECT_ID) && (!is_action_trap(current_action))) {
        status = mlnx_translate_action_to_trap(true, current_action, &action_to_configure);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate current action %d to trap action\n", current_action);
            goto out;
        }
    } else if ((value->oid == SAI_NULL_OBJECT_ID) && is_action_trap(current_action)) {
        status = mlnx_translate_action_to_no_trap(current_action, &action_to_configure, &is_action_present);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate current action %d to non-trap action\n", current_action);
            goto out;
        }
    } else {
        action_to_configure = current_action;
    }

    if (value->oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_get_user_defined_trap_prio(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, value->oid,
                                                 &neigh_entry.neigh_data.trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get current trap id by prio %d\n", neigh_entry.neigh_data.trap_attr.prio);
            goto out;
        }
    }

    status = mlnx_translate_sai_router_action_to_sdk(action_to_configure, &neigh_entry.neigh_data.action, 0);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SAI action %d to SDK\n", action_to_configure);
        goto out;
    }

    status = mlnx_modify_neighbor_entry(neighbor_entry, &neigh_entry.neigh_data);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to modify neighbor\n");
        goto out;
    }

    if (current_trap != SAI_NULL_OBJECT_ID) {
        status = mlnx_trap_refcount_decrease(current_trap);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrease previous trap 0x%" PRIx64 " refcount\n", current_trap);
            goto out;
        }
    }

    if (value->oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_trap_refcount_increase(value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to increase new trap 0x%" PRIx64 " refcount\n", value->oid);
            goto out;
        }
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/* Neighbor not to be programmed as a host route entry in ASIC and to be only
 * used to setup next-hop purpose. Typical use-case is to set this true
 * for neighbor with IPv6 link-local addresses. [bool] */
static sai_status_t mlnx_neighbor_no_host_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_neighbor(neighbor_entry, &neigh_entry))) {
        return status;
    }

    neigh_entry.neigh_data.is_software_only = value->booldata;

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_neighbor_entry(neighbor_entry, &neigh_entry.neigh_data))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove all neighbor entries
 *
 * Arguments:
 *    None
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_all_neighbor_entries(_In_ sai_object_id_t switch_id)
{
    sai_status_t    sx_status;
    sx_ip_addr_t    ipaddr;
    sx_neigh_data_t neigh_data;

    SX_LOG_ENTER();

    SX_LOG_NTC("Remove all neighbor entries\n");

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&neigh_data, 0, sizeof(neigh_data));

    ipaddr.version = SX_IP_VERSION_IPV4_IPV6;

    sx_status = sx_api_router_neigh_set(get_sdk_handle(),
                                        SX_ACCESS_CMD_DELETE_ALL,
                                        g_resource_limits.router_rifs_dontcare,
                                        &ipaddr,
                                        &neigh_data);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove all neighbor entries - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_neighbor_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_neighbor_api_t mlnx_neighbor_api = {
    mlnx_create_neighbor_entry,
    mlnx_remove_neighbor_entry,
    mlnx_set_neighbor_attribute,
    mlnx_get_neighbor_attribute,
    mlnx_remove_all_neighbor_entries,
    NULL,
    NULL,
    NULL,
    NULL
};
