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
#define __MODULE__ SAI_NEIGHBOR

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;
static const sai_attribute_entry_t neighbor_attribs[] = {
    { SAI_NEIGHBOR_ATTR_DST_MAC_ADDRESS, true, true, true,
      "Neighbor destination MAC", SAI_ATTR_VAL_TYPE_MAC },
    { SAI_NEIGHBOR_ATTR_PACKET_ACTION, false, true, true,
      "Neighbor L3 forwarding action", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

sai_status_t mlnx_neighbor_mac_get(_In_ const sai_object_key_t   *key,
                                   _Inout_ sai_attribute_value_t *value,
                                   _In_ uint32_t                  attr_index,
                                   _Inout_ vendor_cache_t        *cache,
                                   void                          *arg);
sai_status_t mlnx_neighbor_action_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
sai_status_t mlnx_neighbor_mac_set(_In_ const sai_object_key_t      *key,
                                   _In_ const sai_attribute_value_t *value,
                                   void                             *arg);
sai_status_t mlnx_neighbor_action_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);

static const sai_vendor_attribute_entry_t neighbor_vendor_attribs[] = {
    { SAI_NEIGHBOR_ATTR_DST_MAC_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_neighbor_mac_get, NULL,
      mlnx_neighbor_mac_set, NULL },
    { SAI_NEIGHBOR_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_neighbor_action_get, NULL,
      mlnx_neighbor_action_set, NULL },
};
static void neighbor_key_to_str(_In_ const sai_neighbor_entry_t* neighbor_entry, _Out_ char *key_str)
{
    int res1, res2;

    res1 = snprintf(key_str, MAX_KEY_STR_LEN, "neighbor ip ");
    sai_ipaddr_to_str(neighbor_entry->ip_address, MAX_KEY_STR_LEN - res1, key_str + res1, &res2);
    snprintf(key_str + res1 + res2, MAX_KEY_STR_LEN - res1 - res2, " rif %u", neighbor_entry->rif_id);
}

static sai_status_t mlnx_translate_sai_neighbor_entry_to_sdk(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                                             _Out_ sx_ip_addr_t              *ip_addr_p)
{
    if (SAI_IP_ADDR_FAMILY_IPV4 == neighbor_entry->ip_address.addr_family) {
        ip_addr_p->version = SX_IP_VERSION_IPV4;
        ip_addr_p->addr.ipv4.s_addr = ntohl(neighbor_entry->ip_address.addr.ip4);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == neighbor_entry->ip_address.addr_family) {
        ip_addr_p->version = SX_IP_VERSION_IPV6;
        memcpy(ip_addr_p->addr.ipv6.s6_addr32, neighbor_entry->ip_address.addr.ip6,
               sizeof(ip_addr_p->addr.ipv6.s6_addr32));
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", neighbor_entry->ip_address.addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t get_vrid_from_rif(_In_ sai_router_interface_id_t rif_id, _Out_ sx_router_id_t *vrid)
{
    sai_status_t                status;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_get(gh_sdk, rif_id, vrid, &intf_params, &intf_attribs))) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
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
sai_status_t mlnx_create_neighbor_entry(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                        _In_ uint32_t                    attr_count,
                                        _In_ const sai_attribute_t      *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *mac, *action;
    uint32_t                     mac_index, action_index;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    sx_ip_addr_t                 ipaddr;
    sx_neigh_data_t              neigh_data;
    sx_router_id_t               vrid;

    SX_LOG_ENTER();

    if (NULL == neighbor_entry) {
        SX_LOG_ERR("NULL neighbor entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, neighbor_attribs, neighbor_vendor_attribs,
                                    SAI_OPERATION_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    neighbor_key_to_str(neighbor_entry, key_str);
    sai_attr_list_to_str(attr_count, attr_list, neighbor_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create neighbor entry %s\n", key_str);
    SX_LOG_NTC("Attribs %s\n", list_str);

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&neigh_data, 0, sizeof(neigh_data));
    neigh_data.action = SX_ROUTER_ACTION_FORWARD;
    neigh_data.rif = neighbor_entry->rif_id;
    neigh_data.trap_attr.prio = SX_TRAP_PRIORITY_MED;

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_NEIGHBOR_ATTR_DST_MAC_ADDRESS, &mac, &mac_index));
    memcpy(&neigh_data.mac_addr, mac->mac, sizeof(neigh_data.mac_addr));

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_NEIGHBOR_ATTR_PACKET_ACTION, &action, &action_index))) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sai_router_action_to_sdk(action->s32, &neigh_data.action, action_index))) {
            return status;
        }
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = get_vrid_from_rif(neighbor_entry->rif_id, &vrid))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_neigh_set(gh_sdk, SX_ACCESS_CMD_ADD, vrid, &ipaddr, &neigh_data))) {
        SX_LOG_ERR("Failed to create neighbor entry - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
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
sai_status_t mlnx_remove_neighbor_entry(_In_ const sai_neighbor_entry_t* neighbor_entry)
{
    sai_status_t    status;
    char            key_str[MAX_KEY_STR_LEN];
    sx_router_id_t  vrid;
    sx_ip_addr_t    ipaddr;
    sx_neigh_data_t neigh_data;

    SX_LOG_ENTER();

    if (NULL == neighbor_entry) {
        SX_LOG_ERR("NULL neighbor entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    neighbor_key_to_str(neighbor_entry, key_str);
    SX_LOG_NTC("Remove neighbor entry %s\n", key_str);

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&neigh_data, 0, sizeof(neigh_data));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = get_vrid_from_rif(neighbor_entry->rif_id, &vrid))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_neigh_set(gh_sdk, SX_ACCESS_CMD_DELETE, vrid, &ipaddr, &neigh_data))) {
        SX_LOG_ERR("Failed to remove neighbor entry - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
sai_status_t mlnx_set_neighbor_attribute(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                         _In_ const sai_attribute_t      *attr)
{
    const sai_object_key_t key = { .neighbor_entry = neighbor_entry };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == neighbor_entry) {
        SX_LOG_ERR("NULL neighbor entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    neighbor_key_to_str(neighbor_entry, key_str);
    return sai_set_attribute(&key, key_str, neighbor_attribs, neighbor_vendor_attribs, attr);
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
sai_status_t mlnx_get_neighbor_attribute(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                         _In_ uint32_t                    attr_count,
                                         _Inout_ sai_attribute_t         *attr_list)
{
    const sai_object_key_t key = { .neighbor_entry = neighbor_entry };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == neighbor_entry) {
        SX_LOG_ERR("NULL neighbor entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    neighbor_key_to_str(neighbor_entry, key_str);
    return sai_get_attributes(&key, key_str, neighbor_attribs, neighbor_vendor_attribs, attr_count, attr_list);
}

static sai_status_t mlnx_get_neighbor(const sai_neighbor_entry_t* neighbor_entry, sx_neigh_get_entry_t *neigh_entry)
{
    sx_status_t       status;
    uint32_t          entries_count = 1;
    sx_ip_addr_t      ipaddr;
    sx_router_id_t    vrid;
    sx_neigh_filter_t filter;

    SX_LOG_ENTER();

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&filter, 0, sizeof(filter));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = get_vrid_from_rif(neighbor_entry->rif_id, &vrid))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_neigh_get(gh_sdk, SX_ACCESS_CMD_GET, vrid, &ipaddr, &filter, neigh_entry,
                                     &entries_count))) {
        SX_LOG_ERR("Failed to get %d neighbor entries %s.\n", entries_count, SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Destination mac address for the neighbor [sai_mac_t] */
sai_status_t mlnx_neighbor_mac_get(_In_ const sai_object_key_t   *key,
                                   _Inout_ sai_attribute_value_t *value,
                                   _In_ uint32_t                  attr_index,
                                   _Inout_ vendor_cache_t        *cache,
                                   void                          *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = key->neighbor_entry;
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
sai_status_t mlnx_neighbor_action_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = key->neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_neighbor(neighbor_entry, &neigh_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sdk_router_action_to_sai(neigh_entry.neigh_data.action, &value->s32))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_modify_neighbor_entry(_In_ const sai_neighbor_entry_t* neighbor_entry,
                                               _In_ const sx_neigh_data_t      *new_neigh_data)
{
    sai_status_t    status;
    sx_router_id_t  vrid;
    sx_ip_addr_t    ipaddr;
    sx_neigh_data_t neigh_data;

    SX_LOG_ENTER();

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&neigh_data, 0, sizeof(neigh_data));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_neighbor_entry_to_sdk(neighbor_entry, &ipaddr))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = get_vrid_from_rif(neighbor_entry->rif_id, &vrid))) {
        return status;
    }

    /* To modify a neighbor, we delete and readd it with new data */
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_neigh_set(gh_sdk, SX_ACCESS_CMD_DELETE, vrid, &ipaddr, &neigh_data))) {
        SX_LOG_ERR("Failed to remove neighbor entry - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_neigh_set(gh_sdk, SX_ACCESS_CMD_ADD, vrid, &ipaddr, new_neigh_data))) {
        SX_LOG_ERR("Failed to create neighbor entry - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Destination mac address for the neighbor [sai_mac_t] */
sai_status_t mlnx_neighbor_mac_set(_In_ const sai_object_key_t *key, _In_ const sai_attribute_value_t *value,
                                   void *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = key->neighbor_entry;
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
sai_status_t mlnx_neighbor_action_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t                status;
    const sai_neighbor_entry_t* neighbor_entry = key->neighbor_entry;
    sx_neigh_get_entry_t        neigh_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_neighbor(neighbor_entry, &neigh_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_router_action_to_sdk(value->s32, &neigh_entry.neigh_data.action, 0))) {
        return status;
    }

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
sai_status_t mlnx_remove_all_neighbor_entries(void)
{
    sai_status_t    status;
    sx_ip_addr_t    ipaddr;
    sx_neigh_data_t neigh_data;

    SX_LOG_ENTER();

    SX_LOG_NTC("Remove all neighbor entries\n");

    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&neigh_data, 0, sizeof(neigh_data));
    /* TODO : replace with resource manager implementation in future version */
    neigh_data.rif = g_resource_limits.router_rifs_dontcare;

    /* TODO : After enabling IPv6 in router use IPV4_IPV6 */
    ipaddr.version = SX_IP_VERSION_IPV4;

    /* TODO : If need to support multiple VRIDs, need to get the vrid as input */
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_neigh_set(gh_sdk, SX_ACCESS_CMD_DELETE_ALL, DEFAULT_VRID, &ipaddr, &neigh_data))) {
        SX_LOG_ERR("Failed to remove all neighbor entries - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_neighbor_api_t neighbor_api = {
    mlnx_create_neighbor_entry,
    mlnx_remove_neighbor_entry,
    mlnx_set_neighbor_attribute,
    mlnx_get_neighbor_attribute,
    mlnx_remove_all_neighbor_entries
};
