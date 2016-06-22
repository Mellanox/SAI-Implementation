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

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t route_attribs[] = {
    { SAI_ROUTE_ATTR_PACKET_ACTION, false, true, true, true,
      "Route packet action", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ROUTE_ATTR_TRAP_PRIORITY, false, true, true, true,
      "Route trap priority", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_ROUTE_ATTR_NEXT_HOP_ID, false, true, true, true,
      "Route next hop ID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_ROUTE_ATTR_META_DATA, false, true, true, true,
      "Route meta data", SAI_ATTR_VAL_TYPE_U32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_route_packet_action_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_route_trap_priority_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_route_next_hop_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_route_packet_action_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_route_trap_priority_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_route_next_hop_id_set(_In_ const sai_object_key_t      *key,
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
    { SAI_ROUTE_ATTR_META_DATA,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static void route_key_to_str(_In_ const sai_unicast_route_entry_t* unicast_route_entry, _Out_ char *key_str)
{
    int res;

    res = snprintf(key_str, MAX_KEY_STR_LEN, "route ");
    sai_ipprefix_to_str(unicast_route_entry->destination, MAX_KEY_STR_LEN - res, key_str + res);
}

static sai_status_t mlnx_translate_sai_route_entry_to_sdk(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
                                                          _Out_ sx_ip_prefix_t                 *ip_prefix,
                                                          _Out_ sx_router_id_t                 *vrid)
{
    uint32_t     data;
    sai_status_t status;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_ip_prefix_to_sdk(&unicast_route_entry->destination, ip_prefix))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(unicast_route_entry->vr_id, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &data, NULL))) {
        return status;
    }
    *vrid = (sx_router_id_t)data;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fill_route_data(sx_uc_route_data_t              *route_data,
                                         sai_object_id_t                  oid,
                                         uint32_t                         next_hop_param_index,
                                         const sai_unicast_route_entry_t* unicast_route_entry)
{
    sai_status_t  status;
    sx_ecmp_id_t  sdk_ecmp_id;
    sx_next_hop_t sdk_next_hop;
    uint32_t      sdk_next_hop_cnt;
    uint32_t      rif_data;

    SX_LOG_ENTER();

    if (SAI_OBJECT_TYPE_NEXT_HOP == sai_object_type_query(oid)) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_NEXT_HOP, &sdk_ecmp_id, NULL))) {
            return status;
        }

        /* ECMP container should contains exactly 1 next hop */
        sdk_next_hop_cnt = 1;
        memset(&sdk_next_hop, 0, sizeof(sdk_next_hop));
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, &sdk_next_hop, &sdk_next_hop_cnt))) {
            SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
        if (1 != sdk_next_hop_cnt) {
            SX_LOG_ERR("Invalid next hop object\n");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + next_hop_param_index;
        }
        route_data->type                       = SX_UC_ROUTE_TYPE_NEXT_HOP;
        route_data->next_hop_cnt               = sdk_next_hop_cnt;
        route_data->uc_route_param.ecmp_id     = SX_ROUTER_ECMP_ID_INVALID;
        route_data->next_hop_list_p[0].version =
            sdk_next_hop.next_hop_key.next_hop_key_entry.ip_next_hop.address.version;

        if (SX_IP_VERSION_IPV4 == route_data->next_hop_list_p[0].version) {
            route_data->next_hop_list_p[0].addr.ipv4 =
                sdk_next_hop.next_hop_key.next_hop_key_entry.ip_next_hop.address.addr.ipv4;
        } else if (SX_IP_VERSION_IPV6 == route_data->next_hop_list_p[0].version) {
            memcpy(&route_data->next_hop_list_p[0].addr.ipv6.s6_addr32,
                   sdk_next_hop.next_hop_key.next_hop_key_entry.ip_next_hop.address.addr.ipv6.s6_addr32,
                   sizeof(route_data->next_hop_list_p[0].addr.ipv6.s6_addr32));
        } else {
            SX_LOG_ERR("Get next hop with incorrect version - %d.\n", route_data->next_hop_list_p[0].version);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    } else if (SAI_OBJECT_TYPE_NEXT_HOP_GROUP == sai_object_type_query(oid)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &sdk_ecmp_id, NULL))) {
            return status;
        }

        route_data->type                   = SX_UC_ROUTE_TYPE_NEXT_HOP;
        route_data->next_hop_cnt           = 0;
        route_data->uc_route_param.ecmp_id = sdk_ecmp_id;
    } else if (SAI_OBJECT_TYPE_ROUTER_INTERFACE == sai_object_type_query(oid)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &rif_data, NULL))) {
            return status;
        }
        route_data->uc_route_param.local_egress_rif = (sx_router_interface_t)rif_data;
        route_data->type                            = SX_UC_ROUTE_TYPE_LOCAL;
    } else {
        SX_LOG_ERR("Invalid next hop object type - %s\n", SAI_TYPE_STR(sai_object_type_query(oid)));
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + next_hop_param_index;
    }

    SX_LOG_EXIT();
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
static sai_status_t mlnx_create_route(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
                                      _In_ uint32_t                         attr_count,
                                      _In_ const sai_attribute_t           *attr_list)
{
    sx_status_t                  status;
    const sai_attribute_value_t *action, *priority, *next_hop;
    uint32_t                     action_index, priority_index, next_hop_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_ip_prefix_t               ip_prefix;
    sx_router_id_t               vrid;
    sx_uc_route_data_t           route_data;
    bool                         next_hop_id_found = false;

    SX_LOG_ENTER();

    if (NULL == unicast_route_entry) {
        SX_LOG_ERR("NULL unicast_route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, route_attribs, route_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    route_key_to_str(unicast_route_entry, key_str);
    sai_attr_list_to_str(attr_count, attr_list, route_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create route %s\n", key_str);
    SX_LOG_NTC("Attribs %s\n", list_str);

    memset(&ip_prefix, 0, sizeof(ip_prefix));
    memset(&route_data, 0, sizeof(route_data));
    route_data.action         = SX_ROUTER_ACTION_FORWARD;
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
        if (SAI_STATUS_SUCCESS != (status = mlnx_fill_route_data(&route_data, next_hop->oid, next_hop_index,
                                                                 unicast_route_entry))) {
            return status;
        }

        next_hop_id_found = true;
    }

    if (((SX_ROUTER_ACTION_FORWARD == route_data.action) || (SX_ROUTER_ACTION_MIRROR == route_data.action)) &&
        (!next_hop_id_found)) {
        SX_LOG_ERR(
            "Packet action forward/log without next hop / next hop group is not allowed for non directly reachable route\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_route_entry_to_sdk(unicast_route_entry, &ip_prefix, &vrid))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_uc_route_set(gh_sdk, SX_ACCESS_CMD_ADD, vrid, &ip_prefix, &route_data))) {
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
static sai_status_t mlnx_remove_route(_In_ const sai_unicast_route_entry_t* unicast_route_entry)
{
    sx_status_t    status;
    sx_ip_prefix_t ip_prefix;
    char           key_str[MAX_KEY_STR_LEN];
    sx_router_id_t vrid;

    SX_LOG_ENTER();

    if (NULL == unicast_route_entry) {
        SX_LOG_ERR("NULL unicast_route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    route_key_to_str(unicast_route_entry, key_str);
    SX_LOG_NTC("Remove route %s\n", key_str);

    memset(&ip_prefix, 0, sizeof(ip_prefix));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_route_entry_to_sdk(unicast_route_entry, &ip_prefix, &vrid))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_uc_route_set(gh_sdk, SX_ACCESS_CMD_DELETE, vrid, &ip_prefix, NULL))) {
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
static sai_status_t mlnx_set_route_attribute(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
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
static sai_status_t mlnx_get_route_attribute(_In_ const sai_unicast_route_entry_t* unicast_route_entry,
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
                                   sx_uc_route_get_entry_t         *route_get_entry,
                                   sx_router_id_t                  *vrid)
{
    sx_status_t              status;
    uint32_t                 entries_count = 1;
    sx_ip_prefix_t           ip_prefix;
    sx_uc_route_key_filter_t filter;

    SX_LOG_ENTER();

    memset(&ip_prefix, 0, sizeof(ip_prefix));
    memset(&filter, 0, sizeof(filter));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_route_entry_to_sdk(unicast_route_entry, &ip_prefix, vrid))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_uc_route_get(gh_sdk, SX_ACCESS_CMD_GET, *vrid, &ip_prefix, &filter,
                                        route_get_entry, &entries_count))) {
        SX_LOG_ERR("Failed to get %d route entries %s.\n", entries_count, SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet action [sai_packet_action_t] */
static sai_status_t mlnx_route_packet_action_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;
    sx_router_id_t                   vrid;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry, &vrid))) {
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
static sai_status_t mlnx_route_trap_priority_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;
    sx_router_id_t                   vrid;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry, &vrid))) {
        return status;
    }

    value->u8 = route_get_entry.route_data.trap_attr.prio;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Next hop or next hop group id for the packet or a router interface
 * in case of directly reachable route [sai_object_id_t]
 * The next hop id can be a generic next hop object, such as next hop,
 * next hop group.
 * Directly reachable routes are the IP subnets that are directly attached to the router.
 * For such routes, fill the router interface id to which the subnet is attached */
static sai_status_t mlnx_route_next_hop_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;
    sx_router_id_t                   vrid;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry, &vrid))) {
        return status;
    }

    if (SX_UC_ROUTE_TYPE_LOCAL == route_get_entry.route_data.type) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_ROUTER_INTERFACE,
                                                               route_get_entry.route_data.uc_route_param.
                                                               local_egress_rif, NULL,
                                                               &value->oid))) {
            return status;
        }
    } else if (SX_UC_ROUTE_TYPE_NEXT_HOP == route_get_entry.route_data.type) {
        if ((0 == route_get_entry.route_data.next_hop_cnt) &&
            (SX_ROUTER_ECMP_ID_INVALID != route_get_entry.route_data.uc_route_param.ecmp_id)) {
            if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                                                                   route_get_entry.route_data.uc_route_param.ecmp_id,
                                                                   NULL,
                                                                   &value->oid))) {
                return status;
            }
        } else if (0 == route_get_entry.route_data.next_hop_cnt) {
            SX_LOG_ERR("Can't get next hop ID when no next hop is set\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        /* TODO : implement next hop to ECMP container lookup */
        else {
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    } else {
        SX_LOG_ERR("Can't get next hop ID for IP2ME/directly reachable route %u\n", route_get_entry.route_data.type);
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_modify_route(sx_router_id_t           vrid,
                                      sx_uc_route_get_entry_t *route_get_entry,
                                      sx_access_cmd_t          cmd)
{
    sx_status_t status;

    /* Delete and Add for action/priority, or Set for next hops changes */
    if (SX_ACCESS_CMD_ADD == cmd) {
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_router_uc_route_set(gh_sdk, SX_ACCESS_CMD_DELETE, vrid,
                                                 &route_get_entry->network_addr, &route_get_entry->route_data))) {
            SX_LOG_ERR("Failed to delete route - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_uc_route_set(gh_sdk, cmd, vrid,
                                             &route_get_entry->network_addr, &route_get_entry->route_data))) {
        SX_LOG_ERR("Failed to set route - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet action [sai_packet_action_t] */
static sai_status_t mlnx_route_packet_action_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;
    sx_router_id_t                   vrid;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry, &vrid))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_router_action_to_sdk(value->s32, &route_get_entry.route_data.action, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_route(vrid, &route_get_entry, SX_ACCESS_CMD_ADD))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet priority for trap/log actions [uint8_t] */
static sai_status_t mlnx_route_trap_priority_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;
    sx_router_id_t                   vrid;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry, &vrid))) {
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

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_route(vrid, &route_get_entry, SX_ACCESS_CMD_ADD))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Next hop or next hop group id for the packet or a router interface
 * in case of directly reachable route [sai_object_id_t]
 * The next hop id can be a generic next hop object, such as next hop,
 * next hop group.
 * Directly reachable routes are the IP subnets that are directly attached to the router.
 * For such routes, fill the router interface id to which the subnet is attached */
static sai_status_t mlnx_route_next_hop_id_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sai_status_t                     status;
    const sai_unicast_route_entry_t* unicast_route_entry = key->unicast_route_entry;
    sx_uc_route_get_entry_t          route_get_entry;
    sx_router_id_t                   vrid;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(unicast_route_entry, &route_get_entry, &vrid))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_fill_route_data(&route_get_entry.route_data, value->oid, 0,
                                                             unicast_route_entry))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_modify_route(vrid, &route_get_entry, SX_ACCESS_CMD_SET))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_route_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_route_api_t mlnx_route_api = {
    mlnx_create_route,
    mlnx_remove_route,
    mlnx_set_route_attribute,
    mlnx_get_route_attribute,
};
