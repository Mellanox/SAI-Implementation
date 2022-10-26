/*
 *  Copyright (C) 2017-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
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
#define __MODULE__ SAI_UTILS_ETH

const sai_u32_list_t mlnx_sai_not_mandatory_attrs[SAI_OBJECT_TYPE_EXTENSIONS_RANGE_END] = {
    [SAI_OBJECT_TYPE_QOS_MAP] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST}
    },

    [SAI_OBJECT_TYPE_SCHEDULER_GROUP] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE}
    },

    [SAI_OBJECT_TYPE_NEXT_HOP] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID}
    },
    [SAI_OBJECT_TYPE_ROUTER_INTERFACE] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_ROUTER_INTERFACE_ATTR_BRIDGE_ID}
    },
};
const sai_u32_list_t mlnx_sai_attrs_valid_for_set[SAI_OBJECT_TYPE_EXTENSIONS_RANGE_END] = {
    [SAI_OBJECT_TYPE_TUNNEL] =
    {.count = 2, .list = (sai_attr_id_t[2]) {SAI_TUNNEL_ATTR_ENCAP_MAPPERS, SAI_TUNNEL_ATTR_DECAP_MAPPERS}
    },
};
const sai_u32_list_t mlnx_sai_attrs_with_empty_list[SAI_OBJECT_TYPE_EXTENSIONS_RANGE_END] = {
    [SAI_OBJECT_TYPE_ACL_ENTRY] = {.count = 3, .list = (sai_attr_id_t[3])
                                   { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
                                     SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE}
    },
};
const sai_u32_list_t mlnx_sai_hostif_table_valid_obj_types[] = {
    [SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID] =
    {.count = 1, .list = (uint32_t[1]) {SAI_OBJECT_TYPE_VLAN}
    },
};
const sai_u32_list_t mlnx_sai_tunnel_valid_obj_types[] = {
    [SAI_TUNNEL_ATTR_OVERLAY_INTERFACE] =
    {.count = 1, .list = (uint32_t[1]) {SAI_OBJECT_TYPE_PORT}
    },
};
const sai_u32_list_t mlnx_sai_acl_entry_valid_obj_types[] = {
    [SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS] =
    {.count = 1, .list = (uint32_t[1]) {SAI_OBJECT_TYPE_LAG}
    },
    [SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS] =
    {.count = 1, .list = (uint32_t[1]) {SAI_OBJECT_TYPE_LAG}
    },
};
const sai_u32_list_t mlnx_sai_valid_obj_types[SAI_OBJECT_TYPE_EXTENSIONS_RANGE_END] = {
    [SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY] =
    {.count = ARRAY_SIZE(mlnx_sai_hostif_table_valid_obj_types), .list = (void*)mlnx_sai_hostif_table_valid_obj_types},
    [SAI_OBJECT_TYPE_TUNNEL] =
    {.count = ARRAY_SIZE(mlnx_sai_tunnel_valid_obj_types), .list = (void*)mlnx_sai_tunnel_valid_obj_types},
    [SAI_OBJECT_TYPE_ACL_ENTRY] =
    {.count = ARRAY_SIZE(mlnx_sai_acl_entry_valid_obj_types), .list = (void*)mlnx_sai_acl_entry_valid_obj_types},
};

/* Data needed for sai_query_attribute_capability and sai_query_attribute_enum_values_capability APIs */
extern const mlnx_obj_type_attrs_info_t mlnx_port_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_lag_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_router_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_next_hop_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_next_hop_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_rif_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_table_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_counter_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_range_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_table_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_table_group_mem_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_mirror_session_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_samplepacket_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_stp_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_trap_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_policer_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_wred_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_qos_map_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_queue_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_scheduler_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_sched_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_buffer_pool_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_buffer_profile_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_ingress_pg_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_lag_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hash_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_udf_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_udf_match_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_udf_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_fdb_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_switch_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_trap_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_table_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_neighbor_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_route_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_vlan_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_vlan_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_packet_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_map_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_term_table_entry_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_switch_tunnel_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_fdb_flush_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_nh_group_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_stp_port_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_l2mcgroup_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_l2mcgroup_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_user_defined_trap_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_bridge_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_bridge_port_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_map_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_port_pool_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_debug_counter_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_bfd_session_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_counter_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_isolation_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_isolation_group_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_fg_hash_field_obj_type_info;
const mlnx_obj_type_attrs_info_t      * mlnx_obj_types_info[] = {
    [SAI_OBJECT_TYPE_PORT] = &mlnx_port_obj_type_info,
    [SAI_OBJECT_TYPE_LAG] = &mlnx_lag_obj_type_info,
    [SAI_OBJECT_TYPE_VIRTUAL_ROUTER] = &mlnx_router_obj_type_info,
    [SAI_OBJECT_TYPE_NEXT_HOP] = &mlnx_next_hop_obj_type_info,
    [SAI_OBJECT_TYPE_NEXT_HOP_GROUP] = &mlnx_next_hop_group_obj_type_info,
    [SAI_OBJECT_TYPE_ROUTER_INTERFACE] = &mlnx_rif_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_TABLE] = &mlnx_acl_table_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_ENTRY] = &mlnx_acl_entry_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_COUNTER] = &mlnx_acl_counter_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_RANGE] = &mlnx_acl_range_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_TABLE_GROUP] = &mlnx_acl_table_group_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER] = &mlnx_acl_table_group_mem_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF] = &mlnx_hostif_obj_type_info,
    [SAI_OBJECT_TYPE_MIRROR_SESSION] = &mlnx_mirror_session_obj_type_info,
    [SAI_OBJECT_TYPE_SAMPLEPACKET] = &mlnx_samplepacket_obj_type_info,
    [SAI_OBJECT_TYPE_STP] = &mlnx_stp_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP] = &mlnx_hostif_trap_group_obj_type_info,
    [SAI_OBJECT_TYPE_POLICER] = &mlnx_policer_obj_type_info,
    [SAI_OBJECT_TYPE_WRED] = &mlnx_wred_obj_type_info,
    [SAI_OBJECT_TYPE_QOS_MAP] = &mlnx_qos_map_obj_type_info,
    [SAI_OBJECT_TYPE_QUEUE] = &mlnx_queue_obj_type_info,
    [SAI_OBJECT_TYPE_SCHEDULER] = &mlnx_scheduler_obj_type_info,
    [SAI_OBJECT_TYPE_SCHEDULER_GROUP] = &mlnx_sched_group_obj_type_info,
    [SAI_OBJECT_TYPE_BUFFER_POOL] = &mlnx_buffer_pool_obj_type_info,
    [SAI_OBJECT_TYPE_BUFFER_PROFILE] = &mlnx_buffer_profile_obj_type_info,
    [SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP] = &mlnx_ingress_pg_obj_type_info,
    [SAI_OBJECT_TYPE_LAG_MEMBER] = &mlnx_lag_member_obj_type_info,
    [SAI_OBJECT_TYPE_HASH] = &mlnx_hash_obj_type_info,
    [SAI_OBJECT_TYPE_UDF] = &mlnx_udf_obj_type_info,
    [SAI_OBJECT_TYPE_UDF_MATCH] = &mlnx_udf_match_obj_type_info,
    [SAI_OBJECT_TYPE_UDF_GROUP] = &mlnx_udf_group_obj_type_info,
    [SAI_OBJECT_TYPE_FDB_ENTRY] = &mlnx_fdb_entry_obj_type_info,
    [SAI_OBJECT_TYPE_SWITCH] = &mlnx_switch_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_TRAP] = &mlnx_hostif_trap_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY] = &mlnx_hostif_table_entry_obj_type_info,
    [SAI_OBJECT_TYPE_NEIGHBOR_ENTRY] = &mlnx_neighbor_obj_type_info,
    [SAI_OBJECT_TYPE_ROUTE_ENTRY] = &mlnx_route_obj_type_info,
    [SAI_OBJECT_TYPE_VLAN] = &mlnx_vlan_obj_type_info,
    [SAI_OBJECT_TYPE_VLAN_MEMBER] = &mlnx_vlan_member_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_PACKET] = &mlnx_hostif_packet_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL_MAP] = &mlnx_tunnel_map_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL] = &mlnx_tunnel_obj_type_info,
    [SAI_OBJECT_TYPE_SWITCH_TUNNEL] = &mlnx_switch_tunnel_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY] = &mlnx_tunnel_term_table_entry_type_info,
    [SAI_OBJECT_TYPE_FDB_FLUSH] = &mlnx_fdb_flush_obj_type_info,
    [SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER] = &mlnx_nh_group_member_obj_type_info,
    [SAI_OBJECT_TYPE_STP_PORT] = &mlnx_stp_port_obj_type_info,
    [SAI_OBJECT_TYPE_L2MC_GROUP] = &mlnx_l2mcgroup_obj_type_info,
    [SAI_OBJECT_TYPE_L2MC_GROUP_MEMBER] = &mlnx_l2mcgroup_member_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP] = &mlnx_hostif_user_defined_trap_obj_type_info,
    [SAI_OBJECT_TYPE_BRIDGE] = &mlnx_bridge_obj_type_info,
    [SAI_OBJECT_TYPE_BRIDGE_PORT] = &mlnx_bridge_port_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY] = &mlnx_tunnel_map_entry_obj_type_info,
    [SAI_OBJECT_TYPE_PORT_POOL] = &mlnx_port_pool_obj_type_info,
    [SAI_OBJECT_TYPE_DEBUG_COUNTER] = &mlnx_debug_counter_obj_type_info,
    [SAI_OBJECT_TYPE_BFD_SESSION] = &mlnx_bfd_session_obj_type_info,
    [SAI_OBJECT_TYPE_COUNTER] = &mlnx_counter_obj_type_info,
    [SAI_OBJECT_TYPE_ISOLATION_GROUP] = &mlnx_isolation_group_obj_type_info,
    [SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER] = &mlnx_isolation_group_member_obj_type_info,
    [SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD] = &mlnx_fg_hash_field_obj_type_info,
};
const uint32_t                          mlnx_obj_types_info_arr_size = ARRAY_SIZE(mlnx_obj_types_info);

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t sdk_to_sai(sx_status_t status)
{
    switch (status) {
    case SX_STATUS_SUCCESS:
        return SAI_STATUS_SUCCESS;

    case SX_STATUS_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_SDK_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_INVALID_HANDLE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_COMM_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_NO_RESOURCES:
        return SAI_STATUS_INSUFFICIENT_RESOURCES;

    case SX_STATUS_NO_MEMORY:
        return SAI_STATUS_NO_MEMORY;

    case SX_STATUS_MEMORY_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_INCOMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_CMD_UNPERMITTED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARAM_NULL:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_ERROR:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_EXCEEDS_RANGE:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_MESSAGE_SIZE_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_MESSAGE_SIZE_EXCEEDS_LIMIT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_DB_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_DB_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_DB_NOT_EMPTY:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_END_OF_DB:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_NOT_FOUND:
        return SAI_STATUS_ITEM_NOT_FOUND;

    case SX_STATUS_ENTRY_ALREADY_EXISTS:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_ENTRY_NOT_BOUND:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_ALREADY_BOUND:
        return SAI_STATUS_OBJECT_IN_USE;

    case SX_STATUS_WRONG_POLICER_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_UNEXPECTED_EVENT_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_TRAP_ID_NOT_CONFIGURED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_INT_COMM_CLOSE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_RESOURCE_IN_USE:
        return SAI_STATUS_OBJECT_IN_USE;

    case SX_STATUS_EVENT_TRAP_ALREADY_ASSOCIATED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_TIMEOUT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_MODULE_UNINITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_SX_UTILS_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARTIALLY_COMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_SXD_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    default:
        SX_LOG_NTC("Unexpected status code %d, mapping to failure\n", status);
        return SAI_STATUS_FAILURE;
    }
}

bool sdk_is_valid_ip_address(const sx_ip_addr_t *sdk_addr)
{
    return (sdk_addr->version == SX_IP_VERSION_IPV4 || sdk_addr->version == SX_IP_VERSION_IPV6);
}

bool mlnx_is_valid_ip_address(const sai_ip_address_t *sai_addr)
{
    return ((SAI_IP_ADDR_FAMILY_IPV4 == sai_addr->addr_family)
            || (SAI_IP_ADDR_FAMILY_IPV6 == sai_addr->addr_family));
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sai_ip_address_to_sdk(_In_ const sai_ip_address_t *sai_addr, _Out_ sx_ip_addr_t *sdk_addr)
{
    int       ii;
    uint32_t *from, *to;

    if (!mlnx_is_valid_ip_address(sai_addr)) {
        SX_LOG_ERR("Invalid addr family %d\n", sai_addr->addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_IP_ADDR_FAMILY_IPV4 == sai_addr->addr_family) {
        /* SDK IPv4 is in host order, while SAI is in network order */
        sdk_addr->version = SX_IP_VERSION_IPV4;
        sdk_addr->addr.ipv4.s_addr = ntohl(sai_addr->addr.ip4);
    } else {
        /* SDK IPv6 is 4*uint32. Each uint32 is in host order. Between uint32s there is network byte order */
        sdk_addr->version = SX_IP_VERSION_IPV6;
        from = (uint32_t*)sai_addr->addr.ip6;
        to = (uint32_t*)sdk_addr->addr.ipv6.s6_addr32;

        for (ii = 0; ii < 4; ii++) {
            to[ii] = ntohl(from[ii]);
        }
    }
    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sdk_ip_address_to_sai(_In_ const sx_ip_addr_t *sdk_addr, _Out_ sai_ip_address_t *sai_addr)
{
    int       ii;
    uint32_t *from, *to;

    if (!sdk_is_valid_ip_address(sdk_addr)) {
        SX_LOG_ERR("Invalid addr family %d\n", sdk_addr->version);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SX_IP_VERSION_IPV4 == sdk_addr->version) {
        sai_addr->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sai_addr->addr.ip4 = htonl(sdk_addr->addr.ipv4.s_addr);
    } else {
        sai_addr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        from = (uint32_t*)sdk_addr->addr.ipv6.s6_addr32;
        to = (uint32_t*)sai_addr->addr.ip6;

        for (ii = 0; ii < 4; ii++) {
            to[ii] = htonl(from[ii]);
        }
    }

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sai_ip_prefix_to_sdk(_In_ const sai_ip_prefix_t *sai_prefix,
                                                 _Out_ sx_ip_prefix_t       *sdk_prefix)
{
    int       ii;
    uint32_t *from_addr, *to_addr, *from_mask, *to_mask;

    if (SAI_IP_ADDR_FAMILY_IPV4 == sai_prefix->addr_family) {
        sdk_prefix->version = SX_IP_VERSION_IPV4;
        sdk_prefix->prefix.ipv4.addr.s_addr = ntohl(sai_prefix->addr.ip4);
        sdk_prefix->prefix.ipv4.mask.s_addr = ntohl(sai_prefix->mask.ip4);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_prefix->addr_family) {
        sdk_prefix->version = SX_IP_VERSION_IPV6;

        from_addr = (uint32_t*)sai_prefix->addr.ip6;
        to_addr = (uint32_t*)sdk_prefix->prefix.ipv6.addr.s6_addr32;

        from_mask = (uint32_t*)sai_prefix->mask.ip6;
        to_mask = (uint32_t*)sdk_prefix->prefix.ipv6.mask.s6_addr32;

        for (ii = 0; ii < 4; ii++) {
            to_addr[ii] = htonl(from_addr[ii]);
            to_mask[ii] = htonl(from_mask[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sai_prefix->addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sdk_ip_prefix_to_sai(_In_ const sx_ip_prefix_t *sdk_prefix,
                                                 _Out_ sai_ip_prefix_t     *sai_prefix)
{
    int       ii;
    uint32_t *from_addr, *to_addr, *from_mask, *to_mask;

    if (SX_IP_VERSION_IPV4 == sdk_prefix->version) {
        sai_prefix->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sai_prefix->addr.ip4 = htonl(sdk_prefix->prefix.ipv4.addr.s_addr);
        sai_prefix->mask.ip4 = htonl(sdk_prefix->prefix.ipv4.mask.s_addr);
    } else if (SX_IP_VERSION_IPV6 == sdk_prefix->version) {
        sai_prefix->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        from_addr = (uint32_t*)sdk_prefix->prefix.ipv6.addr.s6_addr32;
        to_addr = (uint32_t*)sai_prefix->addr.ip6;

        from_mask = (uint32_t*)sdk_prefix->prefix.ipv6.mask.s6_addr32;
        to_mask = (uint32_t*)sai_prefix->mask.ip6;

        for (ii = 0; ii < 4; ii++) {
            to_addr[ii] = htonl(from_addr[ii]);
            to_mask[ii] = htonl(from_mask[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sdk_prefix->version);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_object_to_log_port(sai_object_id_t object_id, sx_port_log_id_t *port_id)
{
    sai_status_t      status;
    uint32_t          ii;
    sai_object_type_t type = sai_object_type_query(object_id);

    if (type == SAI_OBJECT_TYPE_PORT) {
        return mlnx_object_to_type(object_id, type, port_id, NULL);
    } else if (type == SAI_OBJECT_TYPE_LAG) {
        status = mlnx_object_to_type(object_id, type, &ii, NULL);
        if (SAI_ERR(status)) {
            return status;
        }

        if ((ii < MAX_PORTS) || (ii >= MAX_PORTS * 2) || (!mlnx_ports_db[ii].is_present)) {
            return SAI_STATUS_INVALID_OBJECT_ID;
        }

        *port_id = mlnx_ports_db[ii].logical;

        return SAI_STATUS_SUCCESS;
    } else {
        SX_LOG_ERR("Object type %s is not LAG nor Port\n", SAI_TYPE_STR(type));
        return SAI_STATUS_INVALID_PARAMETER;
    }
}

sai_status_t mlnx_log_port_to_object(sx_port_log_id_t port_id, sai_object_id_t *object_id)
{
    mlnx_port_config_t *lag;
    uint32_t            ii;

    if (SX_PORT_TYPE_ID_GET(port_id) == SX_PORT_TYPE_NETWORK) {
        return mlnx_create_object(SAI_OBJECT_TYPE_PORT, port_id, NULL, object_id);
    } else if (SX_PORT_TYPE_ID_GET(port_id) == SX_PORT_TYPE_LAG) {
        mlnx_lag_foreach(lag, ii) {
            if (lag->logical == port_id) {
                *object_id = lag->saiport;
                return SAI_STATUS_SUCCESS;
            }
        }

        SX_LOG_ERR("Failed to find log port %x in SAI DB\n", port_id);
        return SAI_STATUS_FAILURE;
    } else {
        SX_LOG_ERR("Logical port id %x is not LAG nor Port\n", port_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
}

sai_status_t mlnx_create_queue_object(_In_ sx_port_log_id_t port_id, _In_ uint8_t index, _Out_ sai_object_id_t *id)
{
    uint8_t ext_data[EXTENDED_DATA_SIZE];

    memset(ext_data, 0, EXTENDED_DATA_SIZE);
    ext_data[0] = index;
    return mlnx_create_object(SAI_OBJECT_TYPE_QUEUE, port_id, ext_data, id);
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_queue_parse_id(_In_ sai_object_id_t id, _Out_ sx_port_log_id_t *port_id, _Out_ uint8_t *queue_index)
{
    uint8_t      ext_data[EXTENDED_DATA_SIZE];
    sai_status_t status;

    status = mlnx_object_to_type(id, SAI_OBJECT_TYPE_QUEUE, port_id, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    if (queue_index) {
        *queue_index = ext_data[0];
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_sched_group(_In_ sx_port_log_id_t  port_id,
                                     _In_ uint8_t           level,
                                     _In_ uint8_t           index,
                                     _Out_ sai_object_id_t *id)
{
    uint8_t ext_data[EXTENDED_DATA_SIZE];

    memset(ext_data, 0, EXTENDED_DATA_SIZE);
    ext_data[0] = level;
    ext_data[1] = index;
    return mlnx_create_object(SAI_OBJECT_TYPE_SCHEDULER_GROUP, port_id, ext_data, id);
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_sched_group_parse_id(_In_ sai_object_id_t    id,
                                       _Out_ sx_port_log_id_t *port_id_ptr,
                                       _Out_ uint8_t          *level_ptr,
                                       _Out_ uint8_t          *index_ptr)
{
    uint8_t          ext_data[EXTENDED_DATA_SIZE];
    sx_port_log_id_t port_id;
    sai_status_t     status;

    status = mlnx_object_to_type(id, SAI_OBJECT_TYPE_SCHEDULER_GROUP, &port_id, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    if (port_id_ptr) {
        *port_id_ptr = port_id;
    }
    if (level_ptr) {
        *level_ptr = ext_data[0];
    }
    if (index_ptr) {
        *index_ptr = ext_data[1];
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_utils_eth_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_get_switch_log_ports_not_in_lag(const sx_port_log_id_t *exclude_phy_ports,
                                                  const uint32_t          exclude_phy_ports_count,
                                                  sx_port_log_id_t       *ports,
                                                  uint32_t               *ports_count)
{
    const mlnx_port_config_t *port;
    uint32_t                  ii, jj, ports_count_tmp = 0;
    sx_port_log_id_t          log_port_list[MAX_PORTS_DB * 2];
    uint32_t                  log_port_count = MAX_PORTS_DB * 2;
    bool                      exclude_port;
    sx_status_t               sx_status;
    const bool                is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                                       (!g_sai_db_ptr->issu_end_called);

    SX_LOG_ENTER();

    assert(ports);
    if (exclude_phy_ports_count > 0) {
        assert(exclude_phy_ports);
    }

    mlnx_phy_port_not_in_lag_foreach(port, ii) {
        exclude_port = false;
        for (jj = 0; jj < exclude_phy_ports_count; jj++) {
            if (port->logical == exclude_phy_ports[jj]) {
                exclude_port = true;
                break;
            }
        }
        if (exclude_port) {
            continue;
        }

        ports[ports_count_tmp] = port->logical;
        ports_count_tmp++;
    }

    if (is_warmboot_init_stage) {
        sx_status = sx_api_port_swid_port_list_get(gh_sdk, DEFAULT_ETH_SWID, log_port_list, &log_port_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Error getting switch port list: %s\n",
                       SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        for (ii = 0; ii < log_port_count; ii++) {
            if (SX_PORT_TYPE_LAG & SX_PORT_TYPE_ID_GET(log_port_list[ii])) {
                ports[ports_count_tmp] = log_port_list[ii];
                ports_count_tmp++;
            }
        }
    } else {
        mlnx_lag_foreach(port, ii) {
            ports[ports_count_tmp] = port->logical;
            ports_count_tmp++;
        }
    }


    *ports_count = ports_count_tmp;

    return SAI_STATUS_SUCCESS;
}

sai_status_t check_port_type_attr(const sai_object_id_t *ports,
                                  uint32_t               count,
                                  attr_port_type_check_t check,
                                  sai_attr_id_t          attr_id,
                                  uint32_t               idx)
{
    mlnx_port_config_t *port;
    uint32_t            ii;

    if (!ports) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < count; ii++) {
        sai_status_t     status;
        sai_object_id_t  obj_id = ports[ii];
        sx_port_log_id_t log_id;

        if (obj_id == SAI_NULL_OBJECT_ID) {
            continue;
        }

        status = mlnx_object_to_log_port(obj_id, &log_id);
        if (SAI_ERR(status)) {
            return status;
        }
        if (log_id == CPU_PORT) {
            continue;
        }

        status = mlnx_port_by_obj_id(obj_id, &port);
        if (SAI_ERR(status)) {
            goto err;
        }

        if (!(check & ATTR_PORT_IS_LAG_ENABLED) && mlnx_port_is_lag(port)) {
            SX_LOG_ERR("LAG object id %" PRIx64 " is not supported by attr id %u\n",
                       obj_id, attr_id);

            goto err;
        }
        if (!(check & ATTR_PORT_IS_IN_LAG_ENABLED) && mlnx_port_is_lag_member(port)) {
            SX_LOG_ERR("Port LAG member object id %" PRIx64 " is not supported by attr id %u\n",
                       obj_id, attr_id);

            goto err;
        }
    }

    return SAI_STATUS_SUCCESS;

err:
    return SAI_STATUS_INVALID_PORT_NUMBER;
}

sai_status_t mlnx_translate_sai_trap_action_to_sdk(sai_int32_t       action,
                                                   sx_trap_action_t *trap_action,
                                                   uint32_t          param_index,
                                                   bool              is_l2_trap)
{
    if (NULL == trap_action) {
        SX_LOG_ERR("NULL trap action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_PACKET_ACTION_FORWARD:
        *trap_action = SX_TRAP_ACTION_IGNORE;
        break;

    /* trap soft discard allows the packet to travel in the pipeline till end of l2 stage. this allows
     *  mirroring by ACL (Everflow for MS). The downside is such packets will be counted as drops,
     *  as some of the packets are dropped by the pipeline according to spec.
     *  Since we don't want to count such drops (counted when aggregate bridge drops is enabled), we use
     *  regular trap when feature is enabled.
     *  In addition, soft discard has another side effect, of allowing learning. If needed, can be disabled
     *  by ACL */
    case SAI_PACKET_ACTION_TRAP:
        *trap_action =
            ((MLNX_L2_TRAP == is_l2_trap) &&
             (!g_sai_db_ptr->aggregate_bridge_drops)) ? SX_TRAP_ACTION_TRAP_SOFT_DISCARD : SX_TRAP_ACTION_TRAP_2_CPU;
        break;

    case SAI_PACKET_ACTION_LOG:
    case SAI_PACKET_ACTION_COPY:
        *trap_action = SX_TRAP_ACTION_MIRROR_2_CPU;
        break;

    case SAI_PACKET_ACTION_DROP:
        *trap_action = (MLNX_L2_TRAP == is_l2_trap) ? SX_TRAP_ACTION_SOFT_DISCARD : SX_TRAP_ACTION_DISCARD;
        break;

    default:
        SX_LOG_ERR("Invalid packet action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_router_action_to_sdk(sai_int32_t         action,
                                                     sx_router_action_t *router_action,
                                                     uint32_t            param_index)
{
    if (NULL == router_action) {
        SX_LOG_ERR("NULL router action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_PACKET_ACTION_FORWARD:
        *router_action = SX_ROUTER_ACTION_FORWARD;
        break;

    case SAI_PACKET_ACTION_TRAP:
        *router_action = SX_ROUTER_ACTION_TRAP;
        break;

    case SAI_PACKET_ACTION_LOG:
        *router_action = SX_ROUTER_ACTION_MIRROR;
        break;

    case SAI_PACKET_ACTION_DROP:
        *router_action = SX_ROUTER_ACTION_DROP;
        break;

    default:
        SX_LOG_ERR("Invalid packet action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sdk_router_action_to_sai(sx_router_action_t router_action, sai_packet_action_t *sai_action)
{
    if (NULL == sai_action) {
        SX_LOG_ERR("NULL sai action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (router_action) {
    case SX_ROUTER_ACTION_FORWARD:
        *sai_action = SAI_PACKET_ACTION_FORWARD;
        break;

    case SX_ROUTER_ACTION_TRAP:
        *sai_action = SAI_PACKET_ACTION_TRAP;
        break;

    case SX_ROUTER_ACTION_MIRROR:
        *sai_action = SAI_PACKET_ACTION_LOG;
        break;

    case SX_ROUTER_ACTION_DROP:
        *sai_action = SAI_PACKET_ACTION_DROP;
        break;

    default:
        SX_LOG_ERR("Unexpected router action %d\n", router_action);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_stats_mode_to_sdk(sai_stats_mode_t sai_mode, sx_access_cmd_t *sdk_mode)
{
    if (NULL == sdk_mode) {
        SX_LOG_ERR("NULL sdk mode value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (sai_mode) {
    case SAI_STATS_MODE_READ:
    case SAI_STATS_MODE_BULK_READ:
        *sdk_mode = SX_ACCESS_CMD_READ;
        break;

    case SAI_STATS_MODE_READ_AND_CLEAR:
    case SAI_STATS_MODE_BULK_READ_AND_CLEAR:
    case SAI_STATS_MODE_BULK_CLEAR:
        *sdk_mode = SX_ACCESS_CMD_READ_CLEAR;
        break;

    default:
        SX_LOG_ERR("Invalid stats mode %d\n", sai_mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}
