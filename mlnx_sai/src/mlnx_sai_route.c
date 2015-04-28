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
#define __MODULE__ SAI_ROUTE

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;
static const sai_attribute_entry_t route_attribs[] = {
    { SAI_ROUTE_ATTR_PACKET_ACTION, false, true, true,
      "Route packet action", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ROUTE_ATTR_TRAP_PRIORITY, false, true, true,
      "Route trap priority", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_ROUTE_ATTR_NEXT_HOP_ID, false, true, true,
      "Route next hop ID", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_ROUTE_ATTR_NEXT_HOP_GROUP_ID, false, true, true,
      "Route next hop group ID", SAI_ATTR_VAL_TYPE_U32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

sai_status_t mlnx_route_packet_action_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
sai_status_t mlnx_route_trap_priority_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
sai_status_t mlnx_route_next_hop_id_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
sai_status_t mlnx_route_next_hop_group_id_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
sai_status_t mlnx_route_packet_action_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
sai_status_t mlnx_route_trap_priority_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
sai_status_t mlnx_route_next_hop_id_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
sai_status_t mlnx_route_next_hop_group_id_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);

static const sai_vendor_attribute_entry_t route_vendor_attribs[] = {
    { SAI_ROUTE_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_packet_action_get, NULL,
      mlnx_route_packet_action_set, NULL },
    { SAI_ROUTE_ATTR_TRAP_PRIORITY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_trap_priority_get, NULL,
      mlnx_route_trap_priority_set, NULL },
    { SAI_ROUTE_ATTR_NEXT_HOP_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_next_hop_id_get, NULL,
      mlnx_route_next_hop_id_set, NULL },
    { SAI_ROUTE_ATTR_NEXT_HOP_GROUP_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_next_hop_group_id_get, NULL,
      mlnx_route_next_hop_group_id_set, NULL },
};
static void route_key_to_str(_In_ const sai_unicast_route_entry_t* unicast_route_entry, _Out_ char *key_str)
{
    int res;

    res = snprintf(key_str, MAX_KEY_STR_LEN, "route ");
    sai_ipprefix_to_str(unicast_route_entry->destination, MAX_KEY_STR_LEN - res, key_str + res);
}

static sai_status_t mlnx_translate_sai_route_entry_to_sdk(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
                                                          _Out_ sx_ip_prefix_t                 *ip_prefix)
{
    if (SAI_IP_ADDR_FAMILY_IPV4 == unicast_route_entry->destination.addr_family) {
        ip_prefix->version = SX_IP_VERSION_IPV4;
        ip_prefix->prefix.ipv4.addr.s_addr = ntohl(unicast_route_entry->destination.addr.ip4);
        ip_prefix->prefix.ipv4.mask.s_addr = ntohl(unicast_route_entry->destination.mask.ip4);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == unicast_route_entry->destination.addr_family) {
        ip_prefix->version = SX_IP_VERSION_IPV6;
        memcpy(ip_prefix->prefix.ipv6.addr.s6_addr32, unicast_route_entry->destination.addr.ip6,
               sizeof(ip_prefix->prefix.ipv6.addr.s6_addr32));
        memcpy(ip_prefix->prefix.ipv6.mask.s6_addr32, unicast_route_entry->destination.mask.ip6,
               sizeof(ip_prefix->prefix.ipv6.mask.s6_addr32));
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", unicast_route_entry->destination.addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Create Route
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP prefix/mask expected in Network Byte Order.
 *
 */
sai_status_t mlnx_create_route(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
                               _In_ uint32_t                         attr_count,
                               _In_ const sai_attribute_t           *attr_list)
{
    sx_status_t                  status;
    const sai_attribute_value_t *action, *priority, *next_hop, *next_hop_group;
    uint32_t                     action_index, priority_index, next_hop_index, next_hop_group_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_ip_prefix_t               ip_prefix;
    sx_uc_route_data_t           route_data;
    bool                         next_hop_id_found = false;
    bool                         next_hop_group_id_found = false;
    uint32_t                     ii;
    sai_next_hop_list_t          hop_list;

    SX_LOG_ENTER();

    if (NULL == unicast_route_entry) {
        SX_LOG_ERR("NULL unicast_route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, route_attribs, route_vendor_attribs,
                                    SAI_OPERATION_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    route_key_to_str(unicast_route_entry, key_str);
    sai_attr_list_to_str(attr_count, attr_list, route_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create route %s\n", key_str);
    SX_LOG_NTC("Attribs %s\n", list_str);

    memset(&ip_prefix, 0, sizeof(ip_prefix));
    memset(&route_data, 0, sizeof(route_data));
    route_data.action = SX_ROUTER_ACTION_FORWARD;
    route_data.trap_attr.prio = SX_TRAP_PRIORITY_MED;

    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ATTR_PACKET_ACTION, &action, &action_index))) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sai_router_action_to_sdk(action->s32, &route_data.action, action_index))) {
            return status;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ATTR_TRAP_PRIORITY, &priority, &priority_index))) {
        /* TODO : better define priority mappings */
        if (priority->u8 > SX_TRAP_PRIORITY_MAX) {
            SX_LOG_ERR("Trap priority %u out of range (%u,%u)\n",
                       priority->u8,
                       SX_TRAP_PRIORITY_MIN,
                       SX_TRAP_PRIORITY_MAX);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + priority_index;
        }
        route_data.trap_attr.prio = priority->u8;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ATTR_NEXT_HOP_ID, &next_hop, &next_hop_index))) {
        route_data.next_hop_cnt = 1;
        /* TODO : Add support for IPv6 */
        route_data.next_hop_list_p[0].addr.ipv4.s_addr = ntohl(next_hop->u32);
        route_data.next_hop_list_p[0].version = SX_IP_VERSION_IPV4;
        next_hop_id_found = true;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ATTR_NEXT_HOP_GROUP_ID, &next_hop_group,
                                 &next_hop_group_index))) {
        if (next_hop_id_found) {
            SX_LOG_ERR("Can't set next hop ID and next hop group ID together\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + next_hop_group_index;
        }

        if (SAI_STATUS_SUCCESS !=
            (status = db_get_next_hop_group(next_hop_group->u32, &hop_list))) {
            return status;
        }

        route_data.next_hop_cnt = hop_list.next_hop_count;

        /* TODO : Add support for IPv6 */
        for (ii = 0; ii < hop_list.next_hop_count; ii++) {
            route_data.next_hop_list_p[ii].addr.ipv4.s_addr = ntohl(hop_list.next_hop_list[ii]);
            route_data.next_hop_list_p[ii].version = SX_IP_VERSION_IPV4;
        }

        next_hop_group_id_found = true;
    }

    if (((SX_ROUTER_ACTION_FORWARD == route_data.action) || (SX_ROUTER_ACTION_MIRROR == route_data.action)) &&
        (!next_hop_id_found) && (!next_hop_group_id_found)) {
        SX_LOG_ERR("Packet action forward/log without next hop / next hop group is not allowed\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_route_entry_to_sdk(unicast_route_entry, &ip_prefix))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_uc_route_set(gh_sdk, SX_ACCESS_CMD_ADD, unicast_route_entry->vr_id, &ip_prefix,
                                        &route_data))) {
        SX_LOG_ERR("Failed to set route - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove Route
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP prefix/mask expected in Network Byte Order.
 */
sai_status_t mlnx_remove_route(_In_ const sai_unicast_route_entry_t* unicast_route_entry)
{
    sx_status_t    status;
    sx_ip_prefix_t ip_prefix;
    char           key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == unicast_route_entry) {
        SX_LOG_ERR("NULL unicast_route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    route_key_to_str(unicast_route_entry, key_str);
    SX_LOG_NTC("Remove route %s\n", key_str);

    memset(&ip_prefix, 0, sizeof(ip_prefix));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_route_entry_to_sdk(unicast_route_entry, &ip_prefix))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_uc_route_set(gh_sdk, SX_ACCESS_CMD_DELETE, unicast_route_entry->vr_id, &ip_prefix, NULL))) {
        SX_LOG_ERR("Failed to remove route - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Set route attribute value
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_route_attribute(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
                                      _In_ const sai_attribute_t           *attr)
{
    const sai_object_key_t key = { .unicast_route_entry = unicast_route_entry };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == unicast_route_entry) {
        SX_LOG_ERR("NULL unicast_route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    route_key_to_str(unicast_route_entry, key_str);
    return sai_set_attribute(&key, key_str, route_attribs, route_vendor_attribs, attr);
}

/*
 * Routine Description:
 *    Get route attribute value
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_route_attribute(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
                                      _In_ uint32_t                         attr_count,
                                      _Inout_ sai_attribute_t              *attr_list)
{
    const sai_object_key_t key = { .unicast_route_entry = unicast_route_entry };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == unicast_route_entry) {
        SX_LOG_ERR("NULL unicast_route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    route_key_to_str(unicast_route_entry, key_str);
    return sai_get_attributes(&key, key_str, route_attribs, route_vendor_attribs, attr_count, attr_list);
}

static sai_status_t mlnx_get_route(const sai_unicast_route_entry_t* unicast_route_entry,
                                   sx_uc_route_get_entry_t         *route_get_entry)
{
    sx_status_t              status;
    uint32_t                 entries_count = 1;
    sx_ip_prefix_t           ip_prefix;
    sx_uc_route_key_filter_t filter;

    SX_LOG_ENTER();

    memset(&ip_prefix, 0, sizeof(ip_prefix));
    memset(&filter, 0, sizeof(filter));

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_route_entry_to_sdk(unicast_route_entry, &ip_prefix))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_uc_route_get(gh_sdk, SX_ACCESS_CMD_GET, unicast_route_entry->vr_id, &ip_prefix, &filter,
                                        route_get_entry, &entries_count))) {
        SX_LOG_ERR("Failed to get %d route entries %s.\n", entries_count, SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet action [sai_packet_action_t] */
sai_status_t mlnx_route_packet_action_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sdk_router_action_to_sai(route_get_entry.route_data.action, &value->s32))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet priority for trap/log actions [uint8_t] */
sai_status_t mlnx_route_trap_priority_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry))) {
        return status;
    }

    value->u8 = route_get_entry.route_data.trap_attr.prio;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Next hop id for the packet [sai_next_hop_id_t] */
sai_status_t mlnx_route_next_hop_id_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry))) {
        return status;
    }

    if (route_get_entry.route_data.next_hop_cnt > 1) {
        SX_LOG_ERR("Can't get next hop ID when next hop group ID (%u next hops) is set\n",
                   route_get_entry.route_data.next_hop_cnt);
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }
    if (0 == route_get_entry.route_data.next_hop_cnt) {
        SX_LOG_ERR("Can't get next hop ID when no next hop is set\n");
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    if (SX_IP_VERSION_IPV4 == route_get_entry.route_data.next_hop_list_p[0].version) {
        value->u32 = htonl(route_get_entry.route_data.next_hop_list_p[0].addr.ipv4.s_addr);
    } else {
        /* TODO : Add support for IPv6 */
        SX_LOG_ERR("IPv6 not implemented\n");
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Next hop group id for the packet [sai_next_hop_group_id_t] */
sai_status_t mlnx_route_next_hop_group_id_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    /* TODO : implement once ECMP container is implemented in HW */
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t mlnx_modify_route(const sai_unicast_route_entry_t* unicast_route_entry,
                                      sx_uc_route_get_entry_t         *route_get_entry,
                                      sx_access_cmd_t                  cmd)
{
    sx_status_t status;

    /* Delete and Add for action/priority, or Set for next hops changes */
    if (SX_ACCESS_CMD_ADD == cmd) {
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_router_uc_route_set(gh_sdk, SX_ACCESS_CMD_DELETE, unicast_route_entry->vr_id,
                                                 &route_get_entry->network_addr, &route_get_entry->route_data))) {
            SX_LOG_ERR("Failed to delete route - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_uc_route_set(gh_sdk, cmd, unicast_route_entry->vr_id,
                                             &route_get_entry->network_addr, &route_get_entry->route_data))) {
        SX_LOG_ERR("Failed to set route - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet action [sai_packet_action_t] */
sai_status_t mlnx_route_packet_action_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_router_action_to_sdk(value->s32, &route_get_entry.route_data.action, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_route(unicast_route_entry, &route_get_entry, SX_ACCESS_CMD_ADD))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet priority for trap/log actions [uint8_t] */
sai_status_t mlnx_route_trap_priority_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry))) {
        return status;
    }

    /* TODO : better define priority mappings */
    if (value->u8 > SX_TRAP_PRIORITY_MAX) {
        SX_LOG_ERR("Trap priority %u out of range (%u,%u)\n",
                   value->u8,
                   SX_TRAP_PRIORITY_MIN,
                   SX_TRAP_PRIORITY_MAX);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }
    route_get_entry.route_data.trap_attr.prio = value->u8;

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_route(unicast_route_entry, &route_get_entry, SX_ACCESS_CMD_ADD))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Next hop id for the packet [sai_next_hop_id_t] */
sai_status_t mlnx_route_next_hop_id_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry))) {
        return status;
    }

    route_get_entry.route_data.next_hop_cnt = 1;
    /* TODO : Add support for IPv6 */
    route_get_entry.route_data.next_hop_list_p[0].addr.ipv4.s_addr = ntohl(value->u32);
    route_get_entry.route_data.next_hop_list_p[0].version = SX_IP_VERSION_IPV4;

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_route(unicast_route_entry, &route_get_entry, SX_ACCESS_CMD_SET))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Next hop group id for the packet [sai_next_hop_group_id_t] */
sai_status_t mlnx_route_next_hop_group_id_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;
    uint32_t                         ii;
    sai_next_hop_list_t              hop_list;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = db_get_next_hop_group(value->u32, &hop_list))) {
        return status;
    }

    route_get_entry.route_data.next_hop_cnt = hop_list.next_hop_count;

    /* TODO : Add support for IPv6 */
    for (ii = 0; ii < hop_list.next_hop_count; ii++) {
        route_get_entry.route_data.next_hop_list_p[ii].addr.ipv4.s_addr = ntohl(hop_list.next_hop_list[ii]);
        route_get_entry.route_data.next_hop_list_p[ii].version = SX_IP_VERSION_IPV4;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_route(unicast_route_entry, &route_get_entry, SX_ACCESS_CMD_SET))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_route_api_t route_api = {
    mlnx_create_route,
    mlnx_remove_route,
    mlnx_set_route_attribute,
    mlnx_get_route_attribute,
};
