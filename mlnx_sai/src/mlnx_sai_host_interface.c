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
#ifndef _WIN32
#include <net/if.h>
#include <unistd.h>
#include <libnl3/netlink/genl/ctrl.h>
#endif

#undef  __MODULE__
#define __MODULE__ SAI_HOST_INTERFACE

#define SAI_HOSTIF_GENETLINK_GROUP_NAME "psample"

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_host_interface_type_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_host_interface_rif_port_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_host_interface_name_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_host_interface_oper_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_host_interface_oper_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_host_interface_vlan_tag_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_host_interface_genetlink_mcrp_name_get(_In_ const sai_object_key_t   *key,
                                                                _Inout_ sai_attribute_value_t *value,
                                                                _In_ uint32_t                  attr_index,
                                                                _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg);
static sai_status_t mlnx_trap_group_admin_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_trap_group_admin_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_trap_group_queue_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_trap_group_queue_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_trap_group_policer_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_trap_group_policer_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_trap_group_policer_set_internal(_In_ sai_object_id_t trap_id,
                                                         _In_ sai_object_id_t policer_id);
static sai_status_t mlnx_trap_group_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_trap_mirror_session_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_trap_type_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg);
static sai_status_t mlnx_trap_action_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_trap_counter_id_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_trap_group_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_trap_exclude_port_list_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_trap_mirror_session_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_trap_counter_id_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg);
static sai_status_t mlnx_trap_action_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
static sai_status_t mlnx_trap_filter_set(uint32_t index, sai_object_list_t ports);
static sai_status_t mlnx_table_entry_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_table_entry_channel_type_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg);
static sai_status_t mlnx_table_entry_hostif_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static const sai_vendor_attribute_entry_t host_interface_vendor_attribs[] = {
    { SAI_HOSTIF_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_host_interface_type_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_ATTR_OBJ_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_host_interface_rif_port_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_ATTR_NAME,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_host_interface_name_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_host_interface_genetlink_mcrp_name_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_ATTR_OPER_STATUS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_host_interface_oper_get, NULL,
      mlnx_host_interface_oper_set, NULL },
    { SAI_HOSTIF_ATTR_QUEUE,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_ATTR_VLAN_TAG,
      { true, false, true, false },
      { true, false, true, true },
      NULL, NULL,
      mlnx_host_interface_vlan_tag_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        hostif_enum_info[] = {
    [SAI_HOSTIF_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_HOSTIF_TYPE_GENETLINK,
        SAI_HOSTIF_TYPE_FD,
        SAI_HOSTIF_TYPE_NETDEV
        ),
    [SAI_HOSTIF_ATTR_VLAN_TAG] = ATTR_ENUM_VALUES_ALL(),
};
static size_t hostif_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[hostif_db[%u]]", mlnx_oid.id.u32);
}
const mlnx_obj_type_attrs_info_t mlnx_hostif_obj_type_info =
{ host_interface_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(hostif_enum_info), OBJ_STAT_CAP_INFO_EMPTY(), hostif_info_print};
static const sai_vendor_attribute_entry_t trap_group_vendor_attribs[] = {
    { SAI_HOSTIF_TRAP_GROUP_ATTR_ADMIN_STATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_trap_group_admin_get, NULL,
      mlnx_trap_group_admin_set, NULL },
    { SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_trap_group_queue_get, NULL,
      mlnx_trap_group_queue_set, NULL },
    { SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER,
      { true, false, true, true},
      { true, false, true, true},
      mlnx_trap_group_policer_get, NULL,
      mlnx_trap_group_policer_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static size_t hostif_trap_group_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[trap_group_valid[%u]]", mlnx_oid.id.u32);
}
const mlnx_obj_type_attrs_info_t mlnx_hostif_trap_group_obj_type_info =
{ trap_group_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY(), hostif_trap_group_info_print};
static const sai_vendor_attribute_entry_t trap_vendor_attribs[] = {
    { SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_trap_type_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_trap_action_get, NULL,
      mlnx_trap_action_set, NULL },
    { SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY,
      { true, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_TRAP_ATTR_EXCLUDE_PORT_LIST,
      { true, false, true, false },
      { true, false, true, false },
      NULL, NULL,
      mlnx_trap_exclude_port_list_set, NULL },
    { SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_trap_group_get, NULL,
      mlnx_trap_group_set, NULL },
    { SAI_HOSTIF_TRAP_ATTR_MIRROR_SESSION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_trap_mirror_session_get, NULL,
      mlnx_trap_mirror_session_set, NULL },
    { SAI_HOSTIF_TRAP_ATTR_COUNTER_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_trap_counter_id_get, NULL,
      mlnx_trap_counter_id_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        hostif_trap_enum_info[] = {
    [SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_HOSTIF_TRAP_TYPE_STP,
        SAI_HOSTIF_TRAP_TYPE_LACP,
        SAI_HOSTIF_TRAP_TYPE_EAPOL,
        SAI_HOSTIF_TRAP_TYPE_LLDP,
        SAI_HOSTIF_TRAP_TYPE_PVRST,
        SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_QUERY,
        SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_LEAVE,
        SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V1_REPORT,
        SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V2_REPORT,
        SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V3_REPORT,
        SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET,
        SAI_HOSTIF_TRAP_TYPE_UDLD,
        SAI_HOSTIF_TRAP_TYPE_PTP,
        SAI_HOSTIF_TRAP_TYPE_PTP_TX_EVENT,
        SAI_HOSTIF_TRAP_TYPE_DHCP_L2,
        SAI_HOSTIF_TRAP_TYPE_DHCPV6_L2,
        SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST,
        SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE,
        SAI_HOSTIF_TRAP_TYPE_DHCP,
        SAI_HOSTIF_TRAP_TYPE_OSPF,
        SAI_HOSTIF_TRAP_TYPE_PIM,
        SAI_HOSTIF_TRAP_TYPE_VRRP,
        SAI_HOSTIF_TRAP_TYPE_BGP,
        SAI_HOSTIF_TRAP_TYPE_DHCPV6,
        SAI_HOSTIF_TRAP_TYPE_OSPFV6,
        SAI_HOSTIF_TRAP_TYPE_VRRPV6,
        SAI_HOSTIF_TRAP_TYPE_BGPV6,
        SAI_HOSTIF_TRAP_TYPE_BFD,
        SAI_HOSTIF_TRAP_TYPE_BFDV6,
        SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY,
        SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_V2,
        SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_REPORT,
        SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_DONE,
        SAI_HOSTIF_TRAP_TYPE_MLD_V2_REPORT,
        SAI_HOSTIF_TRAP_TYPE_IP2ME,
        SAI_HOSTIF_TRAP_TYPE_SSH,
        SAI_HOSTIF_TRAP_TYPE_SNMP,
        SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR,
        SAI_HOSTIF_TRAP_TYPE_TTL_ERROR,
        SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED,
        SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER
        ),
    [SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION] = ATTR_ENUM_VALUES_LIST(
        SAI_PACKET_ACTION_FORWARD,
        SAI_PACKET_ACTION_TRAP,
        SAI_PACKET_ACTION_LOG,
        SAI_PACKET_ACTION_COPY,
        SAI_PACKET_ACTION_DROP
        )
};
static size_t trap_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[mlnx_traps_info[%u], name:%s]", mlnx_oid.id.u32,
                    mlnx_traps_info[mlnx_oid.id.u32].trap_name);
}
const mlnx_obj_type_attrs_info_t mlnx_hostif_trap_obj_type_info =
{ trap_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(hostif_trap_enum_info), OBJ_STAT_CAP_INFO_EMPTY(), trap_info_print};
static const sai_vendor_attribute_entry_t user_defined_trap_vendor_attribs[] = {
    { SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_trap_type_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TRAP_PRIORITY,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TRAP_GROUP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_trap_group_get, NULL,
      mlnx_trap_group_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        user_defined_trap_enum_info[] = {
    [SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL,
        SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ROUTER,
        SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_NEIGHBOR,
        SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_FDB)
};
const mlnx_obj_type_attrs_info_t          mlnx_hostif_user_defined_trap_obj_type_info =
{ user_defined_trap_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(user_defined_trap_enum_info), OBJ_STAT_CAP_INFO_EMPTY(),
  trap_info_print};
static const sai_vendor_attribute_entry_t host_interface_packet_vendor_attribs[] = {
    { SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID,
      { false, false, false, true },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT,
      { false, false, false, true },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG,
      { false, false, false, true },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE,
      { true, false, false, false },
      { true, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG,
      { true, false, false, false },
      { true, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_TIMESTAMP,
      { true, false, false, false },
      { true, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_EGRESS_QUEUE_INDEX,
      { true, false, false, false },
      { true, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        hostif_packet_enum_info[] = {
    [SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE] = ATTR_ENUM_VALUES_ALL()
};
const mlnx_obj_type_attrs_info_t          mlnx_hostif_packet_obj_type_info =
{ host_interface_packet_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(hostif_packet_enum_info), OBJ_STAT_CAP_INFO_EMPTY(),
  NULL};
static const sai_vendor_attribute_entry_t host_table_entry_vendor_attribs[] = {
    { SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_table_entry_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE,
      NULL, NULL },
    { SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_table_entry_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID,
      NULL, NULL },
    { SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_table_entry_get, (void*)SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID,
      NULL, NULL },
    { SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_table_entry_channel_type_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_table_entry_hostif_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        hostif_table_entry_enum_info[] = {
    [SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE] = ATTR_ENUM_VALUES_ALL(),
};

#define HOSTMISS_TRAP_TYPE (SAI_HOSTIF_TRAP_TYPE_END + 1) /* only for internal use */

static size_t hostif_table_entry_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[hostif_db[%u], trap_db[%u], type:%u]",
                    mlnx_oid.id.u32, mlnx_oid.id.hostif_table_entry.trap_db_idx, mlnx_oid.field.sub_type);
}

const mlnx_obj_type_attrs_info_t mlnx_hostif_table_entry_obj_type_info =
{ host_table_entry_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(hostif_table_entry_enum_info), OBJ_STAT_CAP_INFO_EMPTY(),
  hostif_table_entry_info_print};
const mlnx_trap_info_t mlnx_traps_info[] = {
    { SAI_HOSTIF_TRAP_TYPE_STP, 1, { SX_TRAP_ID_ETH_L2_STP }, SAI_PACKET_ACTION_DROP, "STP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_LACP, 1, { SX_TRAP_ID_ETH_L2_LACP }, SAI_PACKET_ACTION_DROP, "LACP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_EAPOL, 1, { SX_TRAP_ID_ETH_L2_EAPOL }, SAI_PACKET_ACTION_DROP, "EAPOL",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_LLDP, 1, { SX_TRAP_ID_ETH_L2_LLDP }, SAI_PACKET_ACTION_DROP, "LLDP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_PVRST, 1, { SX_TRAP_ID_ETH_L2_RPVST }, SAI_PACKET_ACTION_DROP, "PVRST",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_QUERY, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_QUERY }, SAI_PACKET_ACTION_FORWARD,
      "IGMP query", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_LEAVE, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V2_LEAVE }, SAI_PACKET_ACTION_FORWARD,
      "IGMP leave", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V1_REPORT, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V1_REPORT },
      SAI_PACKET_ACTION_FORWARD,
      "IGMP V1 report", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V2_REPORT, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V2_REPORT },
      SAI_PACKET_ACTION_FORWARD,
      "IGMP V2 report", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V3_REPORT, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V3_REPORT },
      SAI_PACKET_ACTION_FORWARD,
      "IGMP V3 report", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET, 1, { SX_TRAP_ID_ETH_L2_PACKET_SAMPLING }, SAI_PACKET_ACTION_TRAP,
      "Sample packet", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_UDLD, 1, { SX_TRAP_ID_ETH_L2_UDLD }, SAI_PACKET_ACTION_DROP, "UDLD",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_PTP,
      3,
      { SX_TRAP_ID_PTP_EVENT, SX_TRAP_ID_PTP_GENERAL, SX_TRAP_ID_PTP_ING_EVENT},
#ifdef PTP
      SAI_PACKET_ACTION_TRAP,
#else
      SAI_PACKET_ACTION_DROP,
#endif
      "PTP", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_PTP_TX_EVENT,
      1,
      { SX_TRAP_ID_PTP_EGR_EVENT },
#ifdef PTP
      SAI_PACKET_ACTION_TRAP,
#else
      SAI_PACKET_ACTION_DROP,
#endif
      "PTP TX Event", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_DHCP_L2, 1, { SX_TRAP_ID_ETH_L2_DHCP }, SAI_PACKET_ACTION_FORWARD, "L2 DHCP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_DHCPV6_L2, 1, { SX_TRAP_ID_ETH_L2_DHCPV6 }, SAI_PACKET_ACTION_FORWARD, "L2 DHCPv6",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, 1, { SX_TRAP_ID_ROUTER_ARPBC }, SAI_PACKET_ACTION_FORWARD, "ARP request",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE, 1, { SX_TRAP_ID_ROUTER_ARPUC }, SAI_PACKET_ACTION_FORWARD, "ARP response",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_DHCP, 1, { SX_TRAP_ID_IPV4_DHCP }, SAI_PACKET_ACTION_FORWARD, "DHCP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_OSPF, 1, { SX_TRAP_ID_OSPF }, SAI_PACKET_ACTION_FORWARD, "OSPF",
      SAI_OBJECT_TYPE_HOSTIF_TRAP,
      MLNX_NON_L2_TRAP },
    /* TODO : Allow forward on PIM */
    { SAI_HOSTIF_TRAP_TYPE_PIM, 1, { SX_TRAP_ID_PIM }, SAI_PACKET_ACTION_DROP, "PIM", SAI_OBJECT_TYPE_HOSTIF_TRAP,
      MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_VRRP, 1, { SX_TRAP_ID_VRRP }, SAI_PACKET_ACTION_FORWARD, "VRRP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP,
      MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_BGP, 1, { SX_TRAP_ID_IPV4_BGP }, SAI_PACKET_ACTION_FORWARD, "BGP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP,
      MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_DHCPV6, 1, { SX_TRAP_ID_IPV6_DHCP }, SAI_PACKET_ACTION_FORWARD, "DHCPv6",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_OSPFV6, 1, { SX_TRAP_ID_IPV6_OSPF }, SAI_PACKET_ACTION_FORWARD, "OSPFv6",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_VRRPV6, 0, { 0 }, SAI_PACKET_ACTION_FORWARD, "VRRPv6", SAI_OBJECT_TYPE_HOSTIF_TRAP,
      MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_BGPV6, 1, { SX_TRAP_ID_IPV6_BGP }, SAI_PACKET_ACTION_FORWARD, "BGPv6",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, 5,
      { SX_TRAP_ID_IPV6_ROUTER_SOLICIATION, SX_TRAP_ID_IPV6_ROUTER_ADVERTISEMENT, SX_TRAP_ID_IPV6_NEIGHBOR_SOLICIATION,
        SX_TRAP_ID_IPV6_NEIGHBOR_ADVERTISEMENT, SX_TRAP_ID_IPV6_NEIGHBOR_DIRECTION },
      SAI_PACKET_ACTION_FORWARD, "IPv6 neighbor discovery", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_V2, 1, { SX_TRAP_ID_IPV6_MLD_V1_V2 }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD V1 V2",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_REPORT, 1, { SX_TRAP_ID_IPV6_MLD_V1_REPORT }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD V1 report", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_DONE, 1, { SX_TRAP_ID_IPV6_MLD_V1_DONE }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD done", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_MLD_V2_REPORT, 1, { SX_TRAP_ID_IPV6_MLD_V2_REPORT }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD V2 report", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_IP2ME, 1, { SX_TRAP_ID_IP2ME }, SAI_PACKET_ACTION_TRAP, "IP2ME",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_SSH, 2, { SX_TRAP_ID_SSH_IPV4, SX_TRAP_ID_SSH_IPV6 }, SAI_PACKET_ACTION_TRAP, "SSH",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_SNMP, 2, { SX_TRAP_ID_SNMP_IPV4, SX_TRAP_ID_SNMP_IPV6 }, SAI_PACKET_ACTION_TRAP, "SNMP",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR, 1, { SX_TRAP_ID_ETH_L3_MTUERROR }, SAI_PACKET_ACTION_TRAP, "MTU error",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_TTL_ERROR, 1, { SX_TRAP_ID_ETH_L3_TTLERROR }, SAI_PACKET_ACTION_TRAP, "TTL error",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED, 0, { 0 }, SAI_PACKET_ACTION_DROP, "Discard WRED 1",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED, 0, { 0 }, SAI_PACKET_ACTION_DROP, "Discard WRED 2",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER, 0, { 0 }, SAI_PACKET_ACTION_DROP, "Discard Router 1",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER, 0, { 0 }, SAI_PACKET_ACTION_DROP, "Discard Router 2",
      SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN }, SAI_PACKET_ACTION_TRAP,
      "ACL 1",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 1 },
      SAI_PACKET_ACTION_TRAP, "ACL 2", SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 2 },
      SAI_PACKET_ACTION_TRAP, "ACL 3", SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 3 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 4",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 4 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 5",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 5},
      SAI_PACKET_ACTION_TRAP,
      "ACL 6",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 6},
      SAI_PACKET_ACTION_TRAP,
      "ACL 7",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 7 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 8",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 8 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 9",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 9 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 10",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 10 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 11",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 11 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 12",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 12 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 13",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 13 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 14",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN + 14 },
      SAI_PACKET_ACTION_TRAP,
      "ACL 15",
      SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ROUTER, 3,
      { SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_BEST_EFFORT, SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_LOW,
        SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_MED },
      SAI_PACKET_ACTION_TRAP, "Router 1", SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ROUTER, 1,
      { SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_HIGH },
      SAI_PACKET_ACTION_TRAP, "Router 2", SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_NEIGHBOR, 3,
      { SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_BEST_EFFORT, SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_LOW,
        SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_MED },
      SAI_PACKET_ACTION_TRAP, "Neigh 1", SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { (sai_hostif_trap_type_t)SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_NEIGHBOR, 1,
      { SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_HIGH },
      SAI_PACKET_ACTION_TRAP, "Neigh", SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, MLNX_NON_L2_TRAP },
    { SAI_HOSTIF_TRAP_TYPE_BFD, 2, { SX_TRAP_ID_BFD_IPV4, SX_TRAP_ID_BFD_IPV6 },
      SAI_PACKET_ACTION_DROP, "BFD", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP},
    { HOSTMISS_TRAP_TYPE, 2, { SX_TRAP_ID_HOST_MISS_IPV4, SX_TRAP_ID_HOST_MISS_IPV6 },
      SAI_PACKET_ACTION_TRAP, "Host miss", SAI_OBJECT_TYPE_HOSTIF_TRAP, MLNX_NON_L2_TRAP},
    { END_TRAP_INFO_ID, 1, { END_TRAP_INFO_ID }, 0, "", 0, MLNX_NON_L2_TRAP }
};

#define MAX_SAI_TRAPS (sizeof(mlnx_traps_info) / sizeof(*mlnx_traps_info) - 1)

static sai_status_t mlnx_trap_mirror_array_drop_set(_In_ uint32_t         trap_db_idx,
                                                    _In_ sai_object_id_t *sai_mirror_oid,
                                                    _In_ uint32_t         sai_mirror_oid_count,
                                                    _In_ bool             is_create);
static sai_status_t mlnx_trap_mirror_array_drop_clear(_In_ uint32_t trap_db_idx);
static sai_status_t mlnx_trap_mirror_db_fill(_In_ uint32_t                 trap_db_idx,
                                             _In_ const sai_object_list_t *sai_mirror_objlist);
static sai_status_t mlnx_trap_unset(uint32_t index);
static sai_status_t mlnx_trap_set(uint32_t index, sai_packet_action_t sai_action, sai_object_id_t trap_group);
static sai_status_t mlnx_get_trap_db_index_by_oid(sai_object_id_t oid, _Out_ uint32_t *index);
static sai_status_t mlnx_register_wildcard_channel(sx_access_cmd_t cmd, uint32_t trap_idx);

/*requires sai_db read lock*/
static sai_status_t mlnx_get_trap_db_idx_by_prio(sai_object_type_t type, sx_trap_priority_t prio, uint32_t *idx)
{
    uint32_t     ii, jj;
    sx_trap_id_t trap_to_find;

    assert(idx);

    SX_LOG_ENTER();

    assert((type == SAI_OBJECT_TYPE_ROUTE_ENTRY) || (type == SAI_OBJECT_TYPE_NEIGHBOR_ENTRY));

    if (prio > SX_TRAP_PRIORITY_MAX) {
        SX_LOG_ERR("Invalid priority %d\n", prio);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (type == SAI_OBJECT_TYPE_ROUTE_ENTRY) {
        trap_to_find = SX_TRAP_ID_L3_UC_IP_BASE + prio;
    } else {
        trap_to_find = SX_TRAP_ID_L3_NEIGH_IP_BASE + prio;
    }

    for (ii = 0; ii < MAX_SAI_TRAPS; ii++) {
        for (jj = 0; jj < mlnx_traps_info[ii].sdk_traps_num; jj++) {
            if (mlnx_traps_info[ii].sdk_trap_ids[jj] == trap_to_find) {
                if (!g_sai_db_ptr->traps_db[ii].is_used) {
                    SX_LOG_ERR("Trap %s is not configured\n", mlnx_traps_info[ii].trap_name);
                    return SAI_STATUS_FAILURE;
                } else {
                    *idx = ii;
                    return SAI_STATUS_SUCCESS;
                }
            }
        }
    }

    return SAI_STATUS_ITEM_NOT_FOUND;
}

/*requires sai_db read lock*/
sai_status_t mlnx_trap_refcount_increase(sai_object_id_t trap)
{
    sai_status_t status;
    uint32_t     trap_db_idx;

    SX_LOG_ENTER();

    status = mlnx_get_trap_db_index_by_oid(trap, &trap_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap index - trap id 0x%" PRIx64 "\n", trap);
        return status;
    }

    g_sai_db_ptr->traps_db[trap_db_idx].refcount++;

    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
sai_status_t mlnx_trap_refcount_decrease(sai_object_id_t trap)
{
    sai_status_t status;
    uint32_t     trap_db_idx;

    SX_LOG_ENTER();

    status = mlnx_get_trap_db_index_by_oid(trap, &trap_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap index - trap id 0x%" PRIx64 "\n", trap);
        return status;
    }

    assert(g_sai_db_ptr->traps_db[trap_db_idx].refcount != 0);

    g_sai_db_ptr->traps_db[trap_db_idx].refcount--;

    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
sai_status_t mlnx_trap_refcount_decrease_by_prio(sai_object_type_t obj_type, sx_trap_priority_t trap_prio)
{
    sai_status_t status;
    uint32_t     trap_db_idx;

    SX_LOG_ENTER();

    status = mlnx_get_trap_db_idx_by_prio(obj_type, trap_prio, &trap_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap index for %s prio %d\n", SAI_TYPE_STR(obj_type), trap_prio);
        return status;
    }

    assert(g_sai_db_ptr->traps_db[trap_db_idx].refcount != 0);

    g_sai_db_ptr->traps_db[trap_db_idx].refcount--;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_validate_user_defined_trap_by_object_type(sai_object_type_t type, uint32_t trap_db_idx)
{
    sai_hostif_user_defined_trap_type_t trap_type;

    if (mlnx_traps_info[trap_db_idx].object_type != SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP) {
        SX_LOG_ERR("Invalid trap type - %s\n", SAI_TYPE_STR(type));
        return SAI_STATUS_FAILURE;
    }

    trap_type = mlnx_traps_info[trap_db_idx].trap_type;
    if ((type == SAI_OBJECT_TYPE_ROUTE_ENTRY) && (trap_type != SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ROUTER)) {
        SX_LOG_ERR("Invalid trap type %s for route entry object\n", SAI_TYPE_STR(type));
        return SAI_STATUS_FAILURE;
    }

    if ((type == SAI_OBJECT_TYPE_NEIGHBOR_ENTRY) && (trap_type != SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_NEIGHBOR)) {
        SX_LOG_ERR("Invalid trap type %s for neighbor entry object\n", SAI_TYPE_STR(type));
        return SAI_STATUS_FAILURE;
    }

    if ((type == SAI_OBJECT_TYPE_ACL_ENTRY) && (trap_type != SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL)) {
        SX_LOG_ERR("Invalid trap type %s for ACL entry object\n", SAI_TYPE_STR(type));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
sai_status_t mlnx_get_user_defined_trap_acl_sx_trap_id(sai_object_id_t trap, sx_trap_id_t *sx_trap_id)
{
    sai_status_t status;
    uint32_t     trap_db_idx;

    SX_LOG_ENTER();

    assert(sx_trap_id);

    status = mlnx_get_trap_db_index_by_oid(trap, &trap_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap db index - trap id 0x%" PRIx64 "\n", trap);
        return status;
    }

    status = mlnx_validate_user_defined_trap_by_object_type(SAI_OBJECT_TYPE_ACL_ENTRY, trap_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid trap for object type ACL entry - trap id 0x%" PRIx64 "\n", trap);
        return status;
    }

    if (mlnx_traps_info[trap_db_idx].sdk_traps_num == 0) {
        SX_LOG_ERR("Invalid ACL user defined trap 0x%" PRIx64 " - no sdk traps configured\n", trap);
        return SAI_STATUS_FAILURE;
    }

    *sx_trap_id = mlnx_traps_info[trap_db_idx].sdk_trap_ids[0];

    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
sai_status_t mlnx_get_user_defined_trap_by_prio(sai_object_type_t  type,
                                                sx_trap_priority_t prio,
                                                sai_object_id_t   *trap_oid)
{
    sai_status_t status;
    uint32_t     idx;

    SX_LOG_ENTER();

    assert(trap_oid);
    assert((type == SAI_OBJECT_TYPE_ROUTE_ENTRY) || (type == SAI_OBJECT_TYPE_NEIGHBOR_ENTRY));

    status = mlnx_get_trap_db_idx_by_prio(type, prio, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap db index, obj type %s, priority %d\n", SAI_TYPE_STR(type), prio);
        return status;
    }

    status = mlnx_create_object(mlnx_traps_info[idx].object_type, idx, NULL, trap_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create trap object for trap idx %d\n", idx);
        *trap_oid = SAI_NULL_OBJECT_ID;
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
sai_status_t mlnx_get_user_defined_trap_prio(sai_object_type_t type, sai_object_id_t trap, sx_trap_priority_t *prio)
{
    uint32_t     trap_db_idx = 0;
    sai_status_t status;

    SX_LOG_ENTER();

    assert(prio);

    if (!mlnx_is_hostif_trap_valid(trap)) {
        SX_LOG_ERR("Invalid trap - id 0x%" PRIx64 "\n", trap);
        status = SAI_STATUS_INVALID_PARAMETER;
        return status;
    }

    status = mlnx_object_to_type(trap,
                                 SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                                 &trap_db_idx,
                                 NULL);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to create to get trap idx from id 0x%" PRIx64 "\n", trap);
        return status;
    }

    status = mlnx_validate_user_defined_trap_by_object_type(type, trap_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid trap for object type %s\n", SAI_TYPE_STR(type));
        return status;
    }

    if (mlnx_traps_info[trap_db_idx].trap_type == SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ROUTER) {
        *prio = mlnx_traps_info[trap_db_idx].sdk_trap_ids[0] - SX_TRAP_ID_L3_UC_IP_BASE;
    } else if (mlnx_traps_info[trap_db_idx].trap_type == SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_NEIGHBOR) {
        *prio = mlnx_traps_info[trap_db_idx].sdk_trap_ids[0] - SX_TRAP_ID_L3_NEIGH_IP_BASE;
    } else {
        SX_LOG_ERR("Invalid trap type %s to get prio\n", mlnx_traps_info[trap_db_idx].trap_name);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static bool mlnx_is_hostif_trap_valid_impl(uint32_t trap_db_idx)
{
    if (trap_db_idx >= MAX_SAI_TRAPS) {
        SX_LOG_ERR("Invalid trap with idx %u, max value - %zu\n", trap_db_idx, MAX_SAI_TRAPS);
        return false;
    }

    if (mlnx_traps_info[trap_db_idx].trap_type == HOSTMISS_TRAP_TYPE) {
        SX_LOG_ERR("Idx %d is reserved for host miss traps\n", trap_db_idx);
        return false;
    }

    if (!g_sai_db_ptr->traps_db[trap_db_idx].is_used) {
        SX_LOG_ERR("Trap %s is not configured\n", mlnx_traps_info[trap_db_idx].trap_name);
        return false;
    }

    if ((mlnx_traps_info[trap_db_idx].sdk_traps_num == 0) &&
        (mlnx_traps_info[trap_db_idx].trap_type != SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED) &&
        ((mlnx_traps_info[trap_db_idx].trap_type != SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER))) {
        SX_LOG_ERR("No SDK traps matching SAI trap %s\n", mlnx_traps_info[trap_db_idx].trap_name);
        return false;
    }

    return true;
}

bool mlnx_is_hostif_user_defined_trap_valid_for_set(sai_object_type_t obj_type, sai_object_id_t trap)
{
    sai_object_type_t trap_obj_type = sai_object_type_query(trap);
    uint32_t          trap_db_idx;
    sai_status_t      status;

    if (trap_obj_type != SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP) {
        SX_LOG_ERR("Invalid trap type - %s\n", SAI_TYPE_STR(obj_type));
        return false;
    }

    status = mlnx_object_to_type(trap, trap_obj_type, &trap_db_idx, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap db idx - trap 0x%" PRIx64 "\n", trap);
        return false;
    }

    if (!mlnx_is_hostif_trap_valid_impl(trap_db_idx)) {
        SX_LOG_ERR("Invalid trap - trap idx %d\n", trap_db_idx);
        return false;
    }

    if (mlnx_traps_info[trap_db_idx].object_type != SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP) {
        SX_LOG_ERR("Invalid trap type %s\n", SAI_TYPE_STR(mlnx_traps_info[trap_db_idx].object_type));
        return false;
    }

    if ((mlnx_traps_info[trap_db_idx].trap_type != SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL) &&
        (obj_type == SAI_OBJECT_TYPE_ACL_ENTRY)) {
        SX_LOG_ERR("Invalid trap type %s for ACL entry\n", mlnx_traps_info[trap_db_idx].trap_name);
        return false;
    }

    if ((mlnx_traps_info[trap_db_idx].trap_type != SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ROUTER) &&
        (obj_type == SAI_OBJECT_TYPE_ROUTE_ENTRY)) {
        SX_LOG_ERR("Invalid trap type %s for route entry\n", mlnx_traps_info[trap_db_idx].trap_name);
        return false;
    }

    if ((mlnx_traps_info[trap_db_idx].trap_type != SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_NEIGHBOR) &&
        (obj_type == SAI_OBJECT_TYPE_NEIGHBOR_ENTRY)) {
        SX_LOG_ERR("Invalid trap type %s for neighbor entry\n", mlnx_traps_info[trap_db_idx].trap_name);
        return false;
    }

    return true;
}

/*requires sai_db read lock*/
bool mlnx_is_hostif_trap_valid(sai_object_id_t trap)
{
    sai_object_type_t obj_type = sai_object_type_query(trap);
    uint32_t          trap_db_idx;
    sai_status_t      status;

    if ((obj_type != SAI_OBJECT_TYPE_HOSTIF_TRAP) && (obj_type != SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP)) {
        SX_LOG_ERR("Invalid trap type %s\n", SAI_TYPE_STR(obj_type));
        return false;
    }

    status = mlnx_object_to_type(trap, obj_type, &trap_db_idx, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap db idx, id 0x%" PRIx64 "\n", trap);
        return false;
    }

    if (!mlnx_is_hostif_trap_valid_impl(trap_db_idx)) {
        SX_LOG_ERR("Invalid trap - trap idx %d\n", trap_db_idx);
        return false;
    }

    if (obj_type != mlnx_traps_info[trap_db_idx].object_type) {
        SX_LOG_ERR("Invalid trap type %s\n", SAI_TYPE_STR(obj_type));
        return false;
    }

    return true;
}

static sai_status_t mlnx_find_sai_trap_index_by_trap_type(_In_ uint32_t          trap_type,
                                                          _In_ sai_object_type_t trap_object_type,
                                                          _Out_ uint32_t        *index)
{
    uint32_t curr_index;

    SX_LOG_ENTER();

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (curr_index = 0; END_TRAP_INFO_ID != mlnx_traps_info[curr_index].trap_type; curr_index++) {
        if ((trap_type == mlnx_traps_info[curr_index].trap_type) &&
            (trap_object_type == mlnx_traps_info[curr_index].object_type)) {
            *index = curr_index;
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

/*requires sai_db read lock*/
static sai_status_t find_available_sai_trap_index(_In_ uint32_t          trap_type,
                                                  _In_ sai_object_type_t trap_object_type,
                                                  _Out_ uint32_t        *index)
{
    uint32_t curr_index;

    SX_LOG_ENTER();

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (curr_index = 0; END_TRAP_INFO_ID != mlnx_traps_info[curr_index].trap_type; curr_index++) {
        if ((trap_type == mlnx_traps_info[curr_index].trap_type) &&
            (trap_object_type == mlnx_traps_info[curr_index].object_type) &&
            (!g_sai_db_ptr->traps_db[curr_index].is_used)) {
            *index = curr_index;
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

/*require sai_db read lock*/
static sai_status_t mlnx_get_trap_db_index_by_oid(sai_object_id_t oid, _Out_ uint32_t *index)
{
    sai_status_t      status;
    sai_object_type_t trap_type = sai_object_type_query(oid);

    assert(index);

    if (!mlnx_is_hostif_trap_valid(oid)) {
        SX_LOG_ERR("Invalid trap - id 0x%" PRIx64 "\n", oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_object_to_type(oid, trap_type, index, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap object id data, oid 0x%" PRIx64 "\n", oid);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_get_trap_db_index_by_sx_trap(_In_ sx_trap_id_t sx_trap, _Out_ uint32_t   *index)
{
    assert(index);

    for (uint32_t trap_idx = 0; END_TRAP_INFO_ID != mlnx_traps_info[trap_idx].trap_type; trap_idx++) {
        for (uint32_t sx_trap_idx = 0; sx_trap_idx < mlnx_traps_info[trap_idx].sdk_traps_num; sx_trap_idx++) {
            if (sx_trap == mlnx_traps_info[trap_idx].sdk_trap_ids[sx_trap_idx]) {
                *index = trap_idx;
                return SAI_STATUS_SUCCESS;
            }
        }
    }

    return SAI_STATUS_ITEM_NOT_FOUND;
}

/* requires sai_db read lock */
sai_status_t mlnx_hostif_sx_trap_is_configured(_In_ sx_trap_id_t          sx_trap,
                                               _Out_ sai_packet_action_t *action,
                                               _Out_ bool                *is_present,
                                               _Out_ bool                *is_configured)
{
    uint32_t trap_idx, sx_trap_idx;

    assert(action);
    assert(is_configured);
    assert(is_present);


#ifdef ACS_OS
    if (sx_trap == SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_DIP) {
        *is_configured = true;
        return SAI_STATUS_SUCCESS;
    }
#endif

    for (trap_idx = 0; END_TRAP_INFO_ID != mlnx_traps_info[trap_idx].trap_type; trap_idx++) {
        for (sx_trap_idx = 0; sx_trap_idx < mlnx_traps_info[trap_idx].sdk_traps_num; sx_trap_idx++) {
            if (sx_trap == mlnx_traps_info[trap_idx].sdk_trap_ids[sx_trap_idx]) {
                *is_present = true;
                *is_configured = g_sai_db_ptr->traps_db[trap_idx].is_used;

                if (*is_configured) {
                    *action = g_sai_db_ptr->traps_db[trap_idx].action;
                }

                return SAI_STATUS_SUCCESS;
            }
        }
    }

    *is_present = false;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sdk_trap_to_sai(_In_ sx_trap_id_t      sdk_trap_id,
                                            _Out_ const char     **trap_name,
                                            _Out_ sai_object_id_t *trap_oid)
{
    uint32_t     curr_index, curr_trap;
    sai_status_t status;

    SX_LOG_ENTER();

    if (NULL == trap_oid) {
        SX_LOG_ERR("NULL value trap id\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (NULL == trap_name) {
        SX_LOG_ERR("NULL value trap name\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (curr_index = 0; END_TRAP_INFO_ID != mlnx_traps_info[curr_index].trap_type; curr_index++) {
        for (curr_trap = 0; curr_trap < mlnx_traps_info[curr_index].sdk_traps_num; curr_trap++) {
            if (sdk_trap_id == mlnx_traps_info[curr_index].sdk_trap_ids[curr_trap]) {
                *trap_name = mlnx_traps_info[curr_index].trap_name;

                status = mlnx_create_object(mlnx_traps_info[curr_index].object_type, curr_index, NULL, trap_oid);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to create trap object for index %d, trap name %s\n", curr_index,
                               mlnx_traps_info[curr_index].trap_name);
                    *trap_oid = SAI_NULL_OBJECT_ID;
                    return status;
                }

                SX_LOG_EXIT();
                return SAI_STATUS_SUCCESS;
            }
        }
    }

    *trap_oid = SAI_NULL_OBJECT_ID;

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

/* requires sai_db read lock*/
sai_status_t mlnx_translate_sai_trap_to_sdk(_In_ sai_object_id_t trap_oid,
                                            _Out_ uint8_t       *sdk_traps_num,
                                            _Out_ sx_trap_id_t(*sx_trap_ids)[MAX_SDK_TRAPS_PER_SAI_TRAP])
{
    sai_status_t status;
    uint32_t     index;

    assert(sx_trap_ids);

    status = mlnx_get_trap_db_index_by_oid(trap_oid, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap db index - trap id 0x%" PRIx64 "\n", trap_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *sdk_traps_num = mlnx_traps_info[index].sdk_traps_num;
    memcpy(*sx_trap_ids, mlnx_traps_info[index].sdk_trap_ids, sizeof(mlnx_traps_info[index].sdk_trap_ids));

    return SAI_STATUS_SUCCESS;
}

/* Creates netdev. Called under read/write lock */
static sai_status_t create_netdev(uint32_t index)
{
    char add_link_command[100], disable_ipv6_command[100], set_addr_command[100], command[420];

#ifdef ACS_OS
    char up_command[100];
#endif
    int system_err;

    if (SAI_HOSTIF_OBJECT_TYPE_VLAN == g_sai_db_ptr->hostif_db[index].sub_type) {
        snprintf(add_link_command, sizeof(add_link_command), "ip link add link swid%u_eth name %s type vlan id %u",
                 DEFAULT_ETH_SWID, g_sai_db_ptr->hostif_db[index].ifname, g_sai_db_ptr->hostif_db[index].vid);
    } else {
        snprintf(add_link_command, sizeof(add_link_command), "ip link add %s type sx_netdev swid %u port 0x%x",
                 g_sai_db_ptr->hostif_db[index].ifname, DEFAULT_ETH_SWID, g_sai_db_ptr->hostif_db[index].port_id);
    }

    /* TODO : temporary WA for SwitchX. L2 and Router port are created with port MAC. But since we want to use them for
     * routing, we set them with the router MAC to avoid mismatch of the MAC value.
     */
    snprintf(set_addr_command, sizeof(set_addr_command), "ip link set dev %s address %s > /dev/null 2>&1",
             g_sai_db_ptr->hostif_db[index].ifname, g_sai_db_ptr->dev_mac);

    /* Enable ipv6 for router port (by default, ipv6 is off on port/lag netdev)
     * TODO : Right now we are enabling on any port/lag netdev, could improve by enabling just on router port.
     * This will require iteration on all router ports and checking port id match, and also different order sequences.
     */
    if ((SAI_HOSTIF_OBJECT_TYPE_PORT == g_sai_db_ptr->hostif_db[index].sub_type) ||
        (SAI_HOSTIF_OBJECT_TYPE_LAG == g_sai_db_ptr->hostif_db[index].sub_type)) {
        snprintf(disable_ipv6_command, sizeof(disable_ipv6_command), "sysctl -w net.ipv6.conf.%s.disable_ipv6=0",
                 g_sai_db_ptr->hostif_db[index].ifname);
        snprintf(command, sizeof(command), "%s && %s && %s",
                 add_link_command, disable_ipv6_command, set_addr_command);
    } else {
        /* TODO : temporary WA to bring vlan interface up for ping tool in Sonic. Usually vlan interfaces in Sonic are
         * bridge over the port netdevs. Sonic creates vlan netdev directly only for ping, and these should be brought
         * up as currently there is no manager in Sonic for these interfaces.
         */
#ifdef ACS_OS
        snprintf(up_command, sizeof(up_command), "ip link set dev %s up > /dev/null 2>&1",
                 g_sai_db_ptr->hostif_db[index].ifname);
        snprintf(command, sizeof(command), "%s && %s && %s",
                 add_link_command, set_addr_command, up_command);
#else
        snprintf(command, sizeof(command), "%s && %s",
                 add_link_command, set_addr_command);
#endif
    }

    system_err = system(command);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", command);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/* Resolve generic netlink multicast group name */
static sai_status_t resolve_group(uint32_t index, const char* mcgrp_name)
{
#ifndef _WIN32
    struct nl_sock *sk = NULL;
    int             group;
    int             error;

    /* Socket allocation */
    sk = nl_socket_alloc();
    if (!sk) {
        SX_LOG_ERR("Failed to allocate socket \n");
        return SAI_STATUS_FAILURE;
    }

    nl_socket_disable_seq_check(sk);

    error = nl_connect(sk, NETLINK_GENERIC);
    if (error) {
        nl_socket_free(sk);
        SX_LOG_ERR("Failed to genl_connect \n");
        return SAI_STATUS_FAILURE;
    }

    /* Find the multicast group identifier and register ourselves to it. */
    group = genl_ctrl_resolve_grp(sk, "psample", mcgrp_name);
    if (group < 0) {
        nl_socket_free(sk);
        SX_LOG_ERR("Failed to resolve group \n");
        return SAI_STATUS_FAILURE;
    }

#ifdef ACS_OS
    /* sonic uses hard coded group 1 and not "packets" resolved group id */
    g_sai_db_ptr->hostif_db[index].psample_group.group_id = 1;
#else
    g_sai_db_ptr->hostif_db[index].psample_group.group_id = group;
#endif
    nl_socket_free(sk);
#endif
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Create host interface.
 *
 * Arguments:
 *    [out] hif_id - host interface id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_host_interface(_Out_ sai_object_id_t     * hif_id,
                                               _In_ sai_object_id_t        switch_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *type, *rif_port, *name, *mcgrp_name;
    uint32_t                     type_index, rif_port_index, name_index, mcgrp_name_index, rif_port_data;
    uint32_t                     ii;
    uint32_t                     port_db_idx;
    mlnx_object_id_t             mlnx_hif = {0};

    SX_LOG_ENTER();

    status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF, hif_id);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    for (ii = 0; ii < MAX_HOSTIFS; ii++) {
        if (false == g_sai_db_ptr->hostif_db[ii].is_used) {
            break;
        }
    }

    if (MAX_HOSTIFS == ii) {
        SX_LOG_ERR("Hostifs table full\n");
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return SAI_STATUS_TABLE_FULL;
    }

    if (SAI_HOSTIF_TYPE_NETDEV == type->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_OBJ_ID, &rif_port,
                                     &rif_port_index))) {
            SX_LOG_ERR("Missing mandatory attribute rif port id on create of host if netdev type\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_NAME, &name, &name_index))) {
            SX_LOG_ERR("Missing mandatory attribute name on create of host if netdev type\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (SAI_OBJECT_TYPE_VLAN == sai_object_type_query(rif_port->oid)) {
            status = sai_object_to_vlan(rif_port->oid, &g_sai_db_ptr->hostif_db[ii].vid);
            if (SAI_ERR(status)) {
                cl_plock_release(&g_sai_db_ptr->p_lock);
                return status;
            }

            g_sai_db_ptr->hostif_db[ii].sub_type = SAI_HOSTIF_OBJECT_TYPE_VLAN;
        } else if (SAI_OBJECT_TYPE_PORT == sai_object_type_query(rif_port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(rif_port->oid, SAI_OBJECT_TYPE_PORT, &rif_port_data, NULL))) {
                cl_plock_release(&g_sai_db_ptr->p_lock);
                return status;
            }

            g_sai_db_ptr->hostif_db[ii].sub_type = SAI_HOSTIF_OBJECT_TYPE_PORT;
            g_sai_db_ptr->hostif_db[ii].port_id = (sx_port_log_id_t)rif_port_data;
            status = mlnx_port_idx_by_obj_id(rif_port->oid, &port_db_idx);
            if (SAI_ERR(status)) {
                sai_db_unlock();
                SX_LOG_ERR("Failed to get port db idx from port oid %" PRIx64 "\n", rif_port->oid);
                SX_LOG_EXIT();
                return status;
            }
            mlnx_ports_db[port_db_idx].has_hostif = true;
            mlnx_ports_db[port_db_idx].hostif_db_idx = ii;
        } else if (SAI_OBJECT_TYPE_LAG == sai_object_type_query(rif_port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_log_port(rif_port->oid, &rif_port_data))) {
                cl_plock_release(&g_sai_db_ptr->p_lock);
                return status;
            }

            g_sai_db_ptr->hostif_db[ii].sub_type = SAI_HOSTIF_OBJECT_TYPE_LAG;
            g_sai_db_ptr->hostif_db[ii].port_id = (sx_port_log_id_t)rif_port_data;
            status = mlnx_port_idx_by_obj_id(rif_port->oid, &port_db_idx);
            if (SAI_ERR(status)) {
                sai_db_unlock();
                SX_LOG_ERR("Failed to get port db idx from port oid %" PRIx64 "\n", rif_port->oid);
                SX_LOG_EXIT();
                return status;
            }
            mlnx_ports_db[port_db_idx].has_hostif = true;
            mlnx_ports_db[port_db_idx].hostif_db_idx = ii;
        } else {
            SX_LOG_ERR("Invalid rif port object type %s", SAI_TYPE_STR(sai_object_type_query(rif_port->oid)));
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + rif_port_index;
        }

#if __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
        strncpy(g_sai_db_ptr->hostif_db[ii].ifname, name->chardata, SAI_HOSTIF_NAME_SIZE);
        g_sai_db_ptr->hostif_db[ii].ifname[SAI_HOSTIF_NAME_SIZE] = '\0';
#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
        status = create_netdev(ii);
        if (SAI_ERR(status)) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }
    } else if (SAI_HOSTIF_TYPE_FD == type->s32) {
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_OBJ_ID, &rif_port,
                                     &rif_port_index))) {
            SX_LOG_ERR("Invalid attribute rif port id for fd channel host if on create\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + rif_port_index;
        }

        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_NAME, &name, &name_index))) {
            SX_LOG_ERR("Invalid attribute name for fd channel host if on create\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + name_index;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_open(gh_sdk, &g_sai_db_ptr->hostif_db[ii].fd))) {
            SX_LOG_ERR("host ifc open fd failed - %s.\n", SX_STATUS_MSG(status));
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }

        g_sai_db_ptr->hostif_db[ii].sub_type = SAI_HOSTIF_OBJECT_TYPE_FD;
    } else if (SAI_HOSTIF_TYPE_GENETLINK == type->s32) {
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_OBJ_ID, &rif_port,
                                     &rif_port_index))) {
            SX_LOG_ERR("Invalid attribute rif port id for genetlink host if on create\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + rif_port_index;
        }

        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_NAME, &name, &name_index))) {
            SX_LOG_ERR("Missing mandatory attribute name on create of host if genetlink type\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (strncmp(name->chardata, SAI_HOSTIF_GENETLINK_GROUP_NAME, SAI_HOSTIF_NAME_SIZE)) {
            SX_LOG_ERR("Wrong generic netlink group name on create of host if genetlink type\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME, &mcgrp_name,
                                     &mcgrp_name_index))) {
            SX_LOG_ERR("Missing mandatory attribute name on create of host if genetlink type\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        /* check if genetlink hostif already exists */
        for (int i = 0; i < MAX_HOSTIFS; i++) {
            if ((SAI_HOSTIF_OBJECT_TYPE_GENETLINK == g_sai_db_ptr->hostif_db[i].sub_type) &&
                (true == g_sai_db_ptr->hostif_db[i].is_used)) {
                SX_LOG_ERR("Failed to create genetlink hostif, already exist\n");
                cl_plock_release(&g_sai_db_ptr->p_lock);
                return SAI_STATUS_ITEM_ALREADY_EXISTS;
            }
        }

        status = resolve_group(ii, mcgrp_name->chardata);
        if (SAI_ERR(status)) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }
#if __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
        strncpy(g_sai_db_ptr->hostif_db[ii].ifname, name->chardata, SAI_HOSTIF_NAME_SIZE);
        g_sai_db_ptr->hostif_db[ii].ifname[SAI_HOSTIF_NAME_SIZE] = '\0';

        strncpy(g_sai_db_ptr->hostif_db[ii].mcgrpname, mcgrp_name->chardata, SAI_HOSTIF_GENETLINK_MCGRP_NAME_SIZE - 1);
        g_sai_db_ptr->hostif_db[ii].mcgrpname[SAI_HOSTIF_GENETLINK_MCGRP_NAME_SIZE - 1] = '\0';
#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
        g_sai_db_ptr->hostif_db[ii].sub_type =
            SAI_HOSTIF_OBJECT_TYPE_GENETLINK;
    } else {
        SX_LOG_ERR("Invalid host interface type %d\n", type->s32);
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    g_sai_db_ptr->hostif_db[ii].is_used = true;
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    mlnx_hif.id.u32 = ii;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_HOSTIF, &mlnx_hif, hif_id);
    if (SAI_ERR(status)) {
        return status;
    }

    MLNX_LOG_OID_CREATED(*hif_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* requires sai_db read lock */
static sai_status_t check_hostif_is_valid_by_idx_unlocked(uint32_t hif_idx)
{
    if (hif_idx >= MAX_HOSTIFS) {
        SX_LOG_ERR("Invalid Host if ID %u\n", hif_idx);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!g_sai_db_ptr->hostif_db[hif_idx].is_used) {
        SX_LOG_ERR("Invalid Host if ID %u\n entry not used", hif_idx);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t check_host_if_is_valid(mlnx_object_id_t mlnx_hif)
{
    sai_status_t status;

    sai_db_read_lock();
    status = check_hostif_is_valid_by_idx_unlocked(mlnx_hif.id.u32);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}


/*
 * Routine Description:
 *    Remove host interface
 *
 * Arguments:
 *    [in] hif_id - host interface id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_host_interface(_In_ sai_object_id_t hif_id)
{
    int              system_err;
    char             command[100];
    mlnx_object_id_t mlnx_hif;
    uint32_t         port_db_idx;
    sai_status_t     status;

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(hif_id);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hif_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    status = check_host_if_is_valid(mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    if (g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].refcount > 0) {
        SX_LOG_ERR("Failed to remove hostif with refcount %d - object in use\n",
                   g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].refcount);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    if (SAI_HOSTIF_OBJECT_TYPE_FD == g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_host_ifc_close(gh_sdk, &g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].fd))) {
            SX_LOG_ERR("host ifc close fd failed - %s.\n", SX_STATUS_MSG(status));
            goto out;
        }
    } else if (SAI_HOSTIF_OBJECT_TYPE_GENETLINK != g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
        if ((SAI_HOSTIF_OBJECT_TYPE_PORT == g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) ||
            (SAI_HOSTIF_OBJECT_TYPE_LAG == g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type)) {
            status = mlnx_port_idx_by_log_id(g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].port_id, &port_db_idx);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get port db idx from port id 0x%x\n",
                           g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].port_id);
                goto out;
            }
            mlnx_ports_db[port_db_idx].has_hostif = false;
            mlnx_ports_db[port_db_idx].hostif_db_idx = 0;
        }
        snprintf(command, sizeof(command), "ip link delete %s", g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].ifname);
        system_err = system(command);
        if (0 != system_err) {
            SX_LOG_ERR("Command \"%s\" failed\n", command);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    memset(&g_sai_db_ptr->hostif_db[mlnx_hif.id.u32], 0, sizeof(g_sai_db_ptr->hostif_db[mlnx_hif.id.u32]));
    sai_db_sync();
out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/* Restores netdevs in kernel after warm boot */
sai_status_t mlnx_netdev_restore(void)
{
    uint32_t     ii;
    sai_status_t status;

    cl_plock_acquire(&g_sai_db_ptr->p_lock);

    for (ii = 0; ii < MAX_HOSTIFS; ii++) {
        if ((false == g_sai_db_ptr->hostif_db[ii].is_used) ||
            (SAI_HOSTIF_OBJECT_TYPE_FD == g_sai_db_ptr->hostif_db[ii].sub_type)) {
            continue;
        }

        status = create_netdev(ii);
        if (SAI_ERR(status)) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }
    }

    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Set host interface attribute
 *
 * Arguments:
 *    [in] hif_id - host interface id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_host_interface_attribute(_In_ sai_object_id_t hif_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = hif_id };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_HOSTIF, attr);
}

/*
 * Routine Description:
 *    Get host interface attribute
 *
 * Arguments:
 *    [in] hif_id - host interface id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_host_interface_attribute(_In_ sai_object_id_t     hif_id,
                                                      _In_ uint32_t            attr_count,
                                                      _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = hif_id };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_HOSTIF, attr_count, attr_list);
}

/* Type [sai_host_interface_type_t] */
static sai_status_t mlnx_host_interface_type_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    mlnx_object_id_t mlnx_hif;
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    status = check_host_if_is_valid(mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_HOSTIF_OBJECT_TYPE_FD == g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
        value->s32 = SAI_HOSTIF_TYPE_FD;
    } else if (SAI_HOSTIF_OBJECT_TYPE_GENETLINK == g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
        value->s32 = SAI_HOSTIF_TYPE_GENETLINK;
    } else {
        value->s32 = SAI_HOSTIF_TYPE_NETDEV;
    }
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Associated port or router interface [sai_object_id_t] */
static sai_status_t mlnx_host_interface_rif_port_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    mlnx_object_id_t       mlnx_hif = {0};
    sai_host_object_type_t type;
    sai_status_t           status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    status = check_host_if_is_valid(mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();

    type = g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type;

    switch (type) {
    case SAI_HOSTIF_OBJECT_TYPE_FD:
        SX_LOG_ERR("Rif_port can not be retrieved for host interface channel type FD\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        break;

    case SAI_HOSTIF_OBJECT_TYPE_PORT:
    case SAI_HOSTIF_OBJECT_TYPE_LAG:
        status = mlnx_log_port_to_object(g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].port_id,
                                         &value->oid);
        break;

    case SAI_HOSTIF_OBJECT_TYPE_VLAN:
        status = mlnx_vlan_oid_create(g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].vid,
                                      &value->oid);
        break;

    default:
        SX_LOG_ERR("Unexpected host if type %d\n", g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type);
        status = SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/* Name [char[HOST_INTERFACE_NAME_SIZE]] (MANDATORY_ON_CREATE)
 * The maximum number of characters for the name is HOST_INTERFACE_NAME_SIZE - 1 since
 * it needs the terminating null byte ('\0') at the end.  */
static sai_status_t mlnx_host_interface_name_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    mlnx_object_id_t mlnx_hif = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    status = check_host_if_is_valid(mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);

    if (SAI_HOSTIF_OBJECT_TYPE_FD == g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
        SX_LOG_ERR("Name can not be retrieved for host interface channel type FD\n");
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    strncpy(value->chardata, g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].ifname, SAI_HOSTIF_NAME_SIZE);
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Name [char[SAI_HOSTIF_GENETLINK_MCGRP_NAME_SIZE]] (MANDATORY_ON_CREATE)
 * The maximum number of characters for the name is SAI_HOSTIF_GENETLINK_MCGRP_NAME_SIZE - 1 since
 * it needs the terminating null byte ('\0') at the end.  */
static sai_status_t mlnx_host_interface_genetlink_mcrp_name_get(_In_ const sai_object_key_t   *key,
                                                                _Inout_ sai_attribute_value_t *value,
                                                                _In_ uint32_t                  attr_index,
                                                                _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg)
{
    mlnx_object_id_t mlnx_hif = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    status = check_host_if_is_valid(mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);

    if (SAI_HOSTIF_OBJECT_TYPE_GENETLINK != g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
        SX_LOG_ERR("Multicast group name can be retrieved only for host interface channel type genetlink\n");
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    strncpy(value->chardata, g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].mcgrpname, SAI_HOSTIF_GENETLINK_MCGRP_NAME_SIZE);
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get the operational status for this host interface [bool] */
static sai_status_t mlnx_host_interface_oper_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    SX_LOG_ENTER();

    /* automatic on Mellanox implementation */
    value->booldata = true;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get the operational status for this host interface [bool] */
static sai_status_t mlnx_host_interface_oper_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    SX_LOG_ENTER();

    /* automatic on Mellanox implementation */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Strip/keep vlan tag for received packet [sai_hostif_vlan_tag_t] */
static sai_status_t mlnx_host_interface_vlan_tag_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    SX_LOG_ENTER();

    /* No handling needed on Mellanox implementation. Currently driver passes packet as is */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Admin Mode [bool] */
static sai_status_t mlnx_trap_group_admin_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    SX_LOG_ENTER();

    value->booldata = true;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Admin Mode [bool] */
static sai_status_t mlnx_trap_group_admin_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    SX_LOG_ENTER();

    /* The group is always enabled in our SDK */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* cpu egress queue [uint32_t] */
static sai_status_t mlnx_trap_group_queue_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_status_t               status;
    uint32_t                   group_id;
    sx_trap_group_attributes_t trap_group_attributes;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_id, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                                                       group_id, &trap_group_attributes))) {
        SX_LOG_ERR("Failed to sx_api_host_ifc_trap_group_get %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    trap_group_attributes.prio = (value->u32 > SX_TRAP_PRIORITY_HIGH) ? SX_TRAP_PRIORITY_HIGH : value->u32;

    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_group_ext_set(gh_sdk, SX_ACCESS_CMD_SET, DEFAULT_ETH_SWID,
                                                                           group_id, &trap_group_attributes))) {
        SX_LOG_ERR("Failed to sx_api_host_ifc_trap_group_ext_set %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* cpu egress queue [uint32_t] */
static sai_status_t mlnx_trap_group_queue_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t               status;
    uint32_t                   group_id;
    sx_trap_group_attributes_t trap_group_attributes;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_id, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                                                       group_id, &trap_group_attributes))) {
        SX_LOG_ERR("Failed to sx_api_host_ifc_trap_group_get %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u32 = trap_group_attributes.prio;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_trap_group_policer_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t    sai_status;
    sx_status_t     sx_status;
    sx_policer_id_t sx_policer_id = SX_POLICER_ID_INVALID;
    uint32_t        entry_index;
    uint32_t        group_id;

    UNREFERENCED_PARAMETER(attr_index);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(arg);

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_id, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_host_ifc_policer_bind_get(gh_sdk,
                                                      DEFAULT_ETH_SWID,
                                                      group_id,
                                                      &sx_policer_id))) {
        if (SX_STATUS_ENTRY_NOT_FOUND == sx_status) {
            sai_status = SAI_STATUS_SUCCESS;
            SX_LOG_NTC("No policer is bound to trap group:%d\n", group_id);
            value->oid = SAI_NULL_OBJECT_ID;
            SX_LOG_EXIT();
            return sai_status;
        }

        SX_LOG_ERR("Failed to obtain sx_policer for trap group:%d. err:%s\n", group_id, SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        sai_status = sdk_to_sai(sx_status);
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = db_find_sai_policer_entry_ind(sx_policer_id, &entry_index))) {
        SX_LOG_ERR("Failed to obtain sai_policer from sx_policer:0x%" PRIx64 "for trap group:%d. err:%d.\n",
                   sx_policer_id,
                   group_id,
                   sai_status);
        SX_LOG_EXIT();

        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_POLICER, entry_index, NULL, &value->oid))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_trap_group_policer_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sai_status_t sai_status;

    UNREFERENCED_PARAMETER(arg);
    SX_LOG_ENTER();
    sai_status = mlnx_trap_group_policer_set_internal(key->key.object_id, value->oid);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_trap_group_policer_set_internal(_In_ sai_object_id_t trap_id, _In_ sai_object_id_t policer_id)
{
    sai_status_t     sai_status;
    sai_object_key_t key = { .key.object_id = trap_id };
    uint32_t         group_id;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(key.key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_id, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (false == g_sai_db_ptr->trap_group_valid[group_id]) {
        SX_LOG_ERR("Invalid group id specified %u\n", group_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_NULL_OBJECT_ID != policer_id) {
        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_bind_policer(trap_id, policer_id, NULL))) {
            SX_LOG_ERR("Failed to bind. trap_group id:0x%" PRIx64 ". sai policer object_id:0x%" PRIx64 "\n",
                       trap_id,
                       policer_id);
            SX_LOG_EXIT();
            return sai_status;
        }
    } else {
        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_unbind_policer(trap_id, NULL))) {
            SX_LOG_ERR("Failed to un-bind. trap_group_id id:0x%" PRIx64 ". sai policer object_id:0x%" PRIx64 "\n",
                       trap_id,
                       policer_id);
            SX_LOG_EXIT();
            return sai_status;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_unbind_policer_from_trap_group(_In_ sai_object_id_t sai_trap_group_id)
{
    sai_status_t    sai_status;
    sx_status_t     sx_status;
    sx_policer_id_t sx_policer = SX_POLICER_ID_INVALID;
    uint32_t        group_id;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_trap_group_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_id, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_host_ifc_policer_bind_get(gh_sdk,
                                                      DEFAULT_ETH_SWID,
                                                      group_id,
                                                      &sx_policer))) {
        if (SX_STATUS_ENTRY_NOT_FOUND == sx_status) {
            SX_LOG_DBG("No policer is bound to trap group:%d\n", group_id);
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        SX_LOG_ERR("Failed to obtain sx_policer for trap group:%d. err:%s\n", group_id, SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }

    if (SX_STATUS_SUCCESS != (
            sx_status = sx_api_host_ifc_policer_bind_set(
                gh_sdk,
                SX_ACCESS_CMD_UNBIND,
                DEFAULT_ETH_SWID,
                group_id,
                sx_policer))) {
        SX_LOG_ERR("Policer unbind failed - %s\n", SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }

    SX_LOG_NTC("Sai trap group :0x%" PRIx64 ". sx_policer_id:0x%" PRIx64 ". group prio:%u\n",
               sai_trap_group_id,
               sx_policer,
               group_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

uint32_t mlnx_hostif_trap_group_db_free_entries_count(void)
{
    sx_trap_group_t group_id;
    uint32_t        free = 0;

    for (group_id = 0; group_id < MAX_TRAP_GROUPS; group_id++) {
        if (!g_sai_db_ptr->trap_group_valid[group_id]) {
            free++;
        }
    }

    return free;
}

sai_status_t mlnx_hostif_trap_group_allocate(_Out_ sx_trap_group_t *trap_group)
{
    sx_trap_group_t group_id;

    assert(trap_group);

    for (group_id = 0; group_id < MAX_TRAP_GROUPS; group_id++) {
        if (!g_sai_db_ptr->trap_group_valid[group_id]) {
            g_sai_db_ptr->trap_group_valid[group_id] = true;
            *trap_group = group_id;
            return SAI_STATUS_SUCCESS;
        }
    }

    *trap_group = SX_TRAP_GROUP_INVALID;
    SX_LOG_ERR("All trap groups are already used\n");

    return SAI_STATUS_INSUFFICIENT_RESOURCES;
}

sai_status_t mlnx_hostif_trap_group_free(_In_ sx_trap_group_t trap_group)
{
    if (trap_group == SX_TRAP_GROUP_INVALID) {
        return SAI_STATUS_SUCCESS;
    }

    if (trap_group >= MAX_TRAP_GROUPS) {
        SX_LOG_ERR("Invalid trap group id - %d\n", trap_group);
        return SAI_STATUS_FAILURE;
    }

    g_sai_db_ptr->trap_group_valid[trap_group] = false;
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Create host interface trap group
 *
 * Arguments:
 *  [out] hostif_trap_group_id  - host interface trap group id
 *  [in] attr_count - number of attributes
 *  [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_hostif_trap_group(_Out_ sai_object_id_t      *hostif_trap_group_id,
                                                  _In_ sai_object_id_t        switch_id,
                                                  _In_ uint32_t               attr_count,
                                                  _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *prio;
    uint32_t                     prio_index;
    sx_trap_group_attributes_t   trap_group_attributes;
    uint32_t                     policer_attr_index = 0;
    const sai_attribute_value_t *policer_id_attr = NULL;
    uint32_t                     group_id;

    SX_LOG_ENTER();

    memset(&trap_group_attributes, 0, sizeof(trap_group_attributes));

    status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, hostif_trap_group_id);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP);

    trap_group_attributes.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
    trap_group_attributes.truncate_size = 0;
    trap_group_attributes.prio = 0;

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, &prio, &prio_index)) {
        trap_group_attributes.prio = (prio->u32 > SX_TRAP_PRIORITY_HIGH) ? SX_TRAP_PRIORITY_HIGH : prio->u32;
    }

    sai_db_write_lock();

    status = mlnx_hostif_trap_group_allocate(&group_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_group_ext_set(gh_sdk, SX_ACCESS_CMD_SET, DEFAULT_ETH_SWID,
                                                                           group_id, &trap_group_attributes))) {
        SX_LOG_ERR("Failed to sx_api_host_ifc_trap_group_ext_set %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, group_id, NULL, hostif_trap_group_id))) {
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER, &policer_id_attr,
                            &policer_attr_index)) {
        if (SAI_NULL_OBJECT_ID != policer_id_attr->oid) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_sai_bind_policer(*hostif_trap_group_id, policer_id_attr->oid, NULL))) {
                SX_LOG_ERR("Failed to bind. trap_group id:0x%" PRIx64 ". sai policer object_id:0x%" PRIx64 "\n",
                           *hostif_trap_group_id,
                           policer_id_attr->oid);
                goto out;
            }
        }
    }

    MLNX_LOG_OID_CREATED(*hostif_trap_group_id);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Remove host interface trap group
 *
 * Arguments:
 *  [in] hostif_trap_group_id - host interface trap group id
 *
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_hostif_trap_group(_In_ sai_object_id_t hostif_trap_group_id)
{
    sx_status_t  sx_status;
    uint32_t     group_id, trap_idx;
    sai_status_t status;

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(hostif_trap_group_id);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(hostif_trap_group_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_id, NULL))) {
        SX_LOG_EXIT();
        return status;
    }
    if (DEFAULT_TRAP_GROUP_ID == group_id) {
        SX_LOG_ERR("Can't delete the default trap group\n");
        return SAI_STATUS_OBJECT_IN_USE;
    }
    if (group_id >= MAX_TRAP_GROUPS) {
        SX_LOG_ERR("Invalid group id %u\n", group_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_write_lock();

    if (false == g_sai_db_ptr->trap_group_valid[group_id]) {
        SX_LOG_ERR("Invalid group id %u\n", group_id);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    for (trap_idx = 0; END_TRAP_INFO_ID != mlnx_traps_info[trap_idx].trap_type; trap_idx++) {
        if (g_sai_db_ptr->traps_db[trap_idx].trap_group == hostif_trap_group_id) {
            SX_LOG_ERR("Trap group is in use for trap %u (%s)\n", trap_idx, mlnx_traps_info[trap_idx].trap_name);
            status = SAI_STATUS_OBJECT_IN_USE;
            goto out;
        }
    }

    status = mlnx_sai_unbind_policer_from_trap_group(hostif_trap_group_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_status = sx_api_host_ifc_trap_group_ext_set(gh_sdk, SX_ACCESS_CMD_UNSET, DEFAULT_ETH_SWID, group_id, NULL);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to unset sx trap group %d - %s\n", group_id, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    g_sai_db_ptr->trap_group_valid[group_id] = false;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *   Set host interface trap group attribute value.
 *
 * Arguments:
 *    [in] hostif_trap_group_id - host interface trap group id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_hostif_trap_group_attribute(_In_ sai_object_id_t        hostif_trap_group_id,
                                                         _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = hostif_trap_group_id };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, attr);
}

/*
 * Routine Description:
 *   get host interface trap group attribute value.
 *
 * Arguments:
 *    [in] hostif_trap_group_id - host interface trap group id
 *    [in] attr_count - number of attributes
 *    [in,out] attr_list - array of attributes
 *
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_hostif_trap_group_attribute(_In_ sai_object_id_t     hostif_trap_group_id,
                                                         _In_ uint32_t            attr_count,
                                                         _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = hostif_trap_group_id };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, attr_count, attr_list);
}

/**
 * @brief Create host interface trap
 *
 * @param[out] hostif_trap_id Host interface trap id
 * @param[in] switch_id Switch object id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_create_hostif_trap(_Out_ sai_object_id_t      *hostif_trap_id,
                                     _In_ sai_object_id_t        switch_id,
                                     _In_ uint32_t               attr_count,
                                     _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sai_status_t                 sai_status_mirror_session;
    const sai_attribute_value_t *trap_type = NULL, *action = NULL, *exclude = NULL, *counter_id = NULL;
    const sai_attribute_value_t *group = NULL, *mirror_session = NULL;
    uint32_t                     trap_type_idx, action_index, exclude_index, group_index, counter_index;
    uint32_t                     mirror_session_index;
    uint32_t                     index, prio;
    sx_trap_action_t             sx_action;
    const bool                   is_create = true;

    SX_LOG_ENTER();

    /* In Mellanox platform, trap group queue defines the trap priority */
    status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP, hostif_trap_id);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, &trap_type, &trap_type_idx);
    assert(SAI_STATUS_SUCCESS == status);

    sai_db_write_lock();

    status = find_available_sai_trap_index(trap_type->s32, SAI_OBJECT_TYPE_HOSTIF_TRAP, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("No traps of type %x available\n", trap_type->s32);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (g_sai_db_ptr->traps_db[index].is_used) {
        SX_LOG_ERR("Trap %s is already configured\n", mlnx_traps_info[index].trap_name);
        status = SAI_STATUS_ITEM_ALREADY_EXISTS;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, &action, &action_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_translate_sai_trap_action_to_sdk(action->s32, &sx_action, 0, mlnx_traps_info[index].is_l2_trap))) {
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, &group, &group_index)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(group->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
            goto out;
        }
    }

    sai_status_mirror_session = find_attrib_in_list(attr_count,
                                                    attr_list,
                                                    SAI_HOSTIF_TRAP_ATTR_MIRROR_SESSION,
                                                    &mirror_session,
                                                    &mirror_session_index);
    if (SAI_STATUS_SUCCESS == sai_status_mirror_session) {
        status = mlnx_trap_mirror_array_drop_clear(index);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Error clearing trap mirror array\n");
            goto out;
        }
        status = mlnx_trap_mirror_array_drop_set(index,
                                                 mirror_session->objlist.list,
                                                 mirror_session->objlist.count,
                                                 is_create);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Error setting trap mirror session\n");
            goto out;
        }

        status = mlnx_trap_mirror_db_fill(index, &mirror_session->objlist);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Error filling trap mirror db for index %d\n", index);
            goto out;
        }
    } else {
        status = mlnx_trap_set(index, action->s32, (group) ? group->oid : g_sai_db_ptr->default_trap_group);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (g_sai_db_ptr->wildcard_channel.is_in_use) {
            status = mlnx_register_wildcard_channel(SX_ACCESS_CMD_REGISTER, index);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to register wildcard channel for trap %s\n", mlnx_traps_info[index].trap_name);
                goto out;
            }
        }
    }

    g_sai_db_ptr->traps_db[index].action = action->s32;
    g_sai_db_ptr->traps_db[index].trap_group = (group) ? group->oid : g_sai_db_ptr->default_trap_group;

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_EXCLUDE_PORT_LIST, &exclude, &exclude_index)) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_trap_filter_set(index, exclude->objlist))) {
            goto out;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HOSTIF_TRAP, index, NULL, hostif_trap_id))) {
        goto out;
    }

    g_sai_db_ptr->traps_db[index].is_used = true;

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_COUNTER_ID, &counter_id, &counter_index);
    if (!SAI_ERR(status)) {
        status = mlnx_update_hostif_trap_counter_unlocked(*hostif_trap_id, counter_id->oid);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    MLNX_LOG_OID_CREATED(*hostif_trap_id);

    status = SAI_STATUS_SUCCESS;
out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove host interface trap
 *
 * @param[in] hostif_trap_id Host interface trap id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_remove_hostif_trap(_In_ sai_object_id_t hostif_trap_id)
{
    uint32_t               index;
    sai_status_t           status;
    sai_object_list_t      exclude = {0};
    sai_hostif_trap_type_t sai_trap_type;

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(hostif_trap_id);

    sai_db_write_lock();

    status = mlnx_get_trap_db_index_by_oid(hostif_trap_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap db index - id 0x%" PRIx64 "\n", hostif_trap_id);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (g_sai_db_ptr->traps_db[index].is_used == false) {
        SX_LOG_ERR("Failed to remove host interface trap %s - entry is not configured\n",
                   mlnx_traps_info[index].trap_name);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (g_sai_db_ptr->traps_db[index].refcount > 0) {
        SX_LOG_ERR("Failed to remove trap with refcount %d - trap %s is in use\n",
                   g_sai_db_ptr->traps_db[index].refcount, mlnx_traps_info[index].trap_name);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    status = mlnx_update_hostif_trap_counter_unlocked(hostif_trap_id, SAI_NULL_OBJECT_ID);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unbound counter from trap %s\n", mlnx_traps_info[index].trap_name);
        goto out;
    }

    sai_trap_type = mlnx_traps_info[index].trap_type;
    if ((SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED != sai_trap_type) &&
        (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER != sai_trap_type)) {
        if (g_sai_db_ptr->wildcard_channel.is_in_use) {
            status = mlnx_register_wildcard_channel(SX_ACCESS_CMD_DEREGISTER, index);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to deregister wildcard channel for trap %s\n", mlnx_traps_info[index].trap_name);
                goto out;
            }
        }

        status = mlnx_trap_unset(index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to unset trap %s\n", mlnx_traps_info[index].trap_name);
            goto out;
        }

        exclude.count = 0;
        if (SAI_STATUS_SUCCESS != (status = mlnx_trap_filter_set(index, exclude))) {
            goto out;
        }
    } else {
        status = mlnx_trap_mirror_array_drop_clear(index);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Error clearing trap mirror array for trap index %d\n", index);
            goto out;
        }
    }

    g_sai_db_ptr->traps_db[index].action = mlnx_traps_info[index].action;
    g_sai_db_ptr->traps_db[index].trap_group = g_sai_db_ptr->default_trap_group;

    g_sai_db_ptr->traps_db[index].is_used = false;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *   Set trap attribute value.
 *
 * Arguments:
 *    [in] hostif_trap_id - host interface trap id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_hostif_trap_attribute(_In_ sai_object_id_t        hostif_trap_id,
                                                   _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = hostif_trap_id };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_HOSTIF_TRAP, attr);
}

/*
 * Routine Description:
 *   Get trap attribute value.
 *
 * Arguments:
 *    [in] hostif_trap_id - host interface trap id
 *    [in] attr_count - number of attributes
 *    [in,out] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_hostif_trap_attribute(_In_ sai_object_id_t     hostif_trap_id,
                                                   _In_ uint32_t            attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = hostif_trap_id };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_HOSTIF_TRAP, attr_count, attr_list);
}

/**
 * @brief Create host interface user defined trap
 *
 * @param[out] hostif_user_defined_trap_id Host interface user defined trap id
 * @param[in] switch_id Switch object id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_create_hostif_user_defined_trap(_Out_ sai_object_id_t      *hostif_user_defined_trap_id,
                                                  _In_ sai_object_id_t        switch_id,
                                                  _In_ uint32_t               attr_count,
                                                  _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *trap_type, *group_attr = NULL;
    uint32_t                     trap_type_index, group_index;
    uint32_t                     index, prio;
    sai_object_id_t              trap_group;

    SX_LOG_ENTER();

    status = check_attribs_on_create(attr_count,
                                     attr_list,
                                     SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                                     hostif_user_defined_trap_id);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP);

    sai_db_write_lock();

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TYPE,
                                 &trap_type,
                                 &trap_type_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = find_available_sai_trap_index(trap_type->s32, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("No traps of type %x available\n", trap_type->s32);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TRAP_GROUP, &group_attr,
                                 &group_index);
    if (SAI_OK(status)) {
        status = mlnx_object_to_type(group_attr->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get trap group data\n");
            goto out;
        }

        trap_group = group_attr->oid;
    } else {
        trap_group = g_sai_db_ptr->default_trap_group;
    }

    status = mlnx_trap_set(index, g_sai_db_ptr->traps_db[index].action, trap_group);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set trap SDK\n");
        goto out;
    }

    if (g_sai_db_ptr->wildcard_channel.is_in_use) {
        status = mlnx_register_wildcard_channel(SX_ACCESS_CMD_REGISTER, index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to register wildcard channel for trap %s\n", mlnx_traps_info[index].trap_name);
            goto out;
        }
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, index, NULL, hostif_user_defined_trap_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create trap object id\n");
        goto out;
    }

    g_sai_db_ptr->traps_db[index].trap_group = trap_group;
    g_sai_db_ptr->traps_db[index].is_used = true;

    MLNX_LOG_OID_CREATED(*hostif_user_defined_trap_id);

out:
    sai_db_unlock();
    SX_LOG_EXIT();

    return status;
}

/**
 * @brief Remove host interface user defined trap
 *
 * @param[in] hostif_user_defined_trap_id Host interface user defined trap id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_remove_hostif_user_defined_trap(_In_ sai_object_id_t hostif_user_defined_trap_id)
{
    uint32_t     index;
    sai_status_t status;

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(hostif_user_defined_trap_id);

    sai_db_write_lock();

    status = mlnx_get_trap_db_index_by_oid(hostif_user_defined_trap_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap db index, trap id 0x%" PRIx64 "\n", hostif_user_defined_trap_id);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (g_sai_db_ptr->traps_db[index].is_used == false) {
        SX_LOG_ERR("Failed to remove host interface trap - entry is not configured\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (g_sai_db_ptr->traps_db[index].refcount > 0) {
        SX_LOG_ERR("Failed to remove trap %s with refcount %d - trap is in use\n", mlnx_traps_info[index].trap_name,
                   g_sai_db_ptr->traps_db[index].refcount);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    if (g_sai_db_ptr->wildcard_channel.is_in_use) {
        status = mlnx_register_wildcard_channel(SX_ACCESS_CMD_DEREGISTER, index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to deregister wildcard channel for trap %s\n", mlnx_traps_info[index].trap_name);
            goto out;
        }
    }

    status = mlnx_trap_unset(index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unset trap %s\n", mlnx_traps_info[index].trap_name);
        goto out;
    }

    g_sai_db_ptr->traps_db[index].action = mlnx_traps_info[index].action;
    g_sai_db_ptr->traps_db[index].trap_group = g_sai_db_ptr->default_trap_group;
    g_sai_db_ptr->traps_db[index].is_used = false;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *   Set user defined trap attribute value.
 *
 * Arguments:
 *    [in] hostif_user_defined_trap_id - host interface user defined trap id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_hostif_user_defined_trap_attribute(
    _In_ sai_object_id_t        hostif_user_defined_trap_id,
    _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = hostif_user_defined_trap_id };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, attr);
}

/*
 * Routine Description:
 *   Get user defined trap attribute value.
 *
 * Arguments:
 *    [in] hostif_user_defined_trap_id - host interface user defined trap id
 *    [in] attr_count - number of attributes
 *    [in,out] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_hostif_user_defined_trap_attribute(_In_ sai_object_id_t     hostif_user_defined_trap_id,
                                                                _In_ uint32_t            attr_count,
                                                                _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = hostif_user_defined_trap_id };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, attr_count, attr_list);
}

static sai_status_t mlnx_trap_update(_In_ uint32_t            index,
                                     _In_ sai_packet_action_t sai_action,
                                     _In_ sai_object_id_t     trap_group,
                                     _In_ bool                is_set)
{
    sx_status_t             sx_status;
    sx_trap_action_t        action;
    sx_host_ifc_trap_key_t  trap_key;
    sx_host_ifc_trap_attr_t trap_attr;
    sx_access_cmd_t         cmd;
    sai_status_t            status;
    uint32_t                prio, trap_index;

    memset(&trap_key, 0, sizeof(trap_key));
    memset(&trap_attr, 0, sizeof(trap_attr));

    cmd = is_set ? SX_ACCESS_CMD_SET : SX_ACCESS_CMD_UNSET;

    if (is_set) {
        status = mlnx_translate_sai_trap_action_to_sdk(sai_action, &action, 0, mlnx_traps_info[index].is_l2_trap);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        action = SX_TRAP_ACTION_SET_FW_DEFAULT;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(trap_group,
                                                            SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
        return status;
    }

    for (trap_index = 0; trap_index < mlnx_traps_info[index].sdk_traps_num; trap_index++) {
        status = mlnx_debug_counter_db_trap_action_update(mlnx_traps_info[index].sdk_trap_ids[trap_index],
                                                          is_set ? sai_action : SAI_PACKET_ACTION_DROP);
        if (SAI_ERR(status)) {
            return status;
        }

        trap_key.type = HOST_IFC_TRAP_KEY_TRAP_ID_E;
        trap_key.trap_key_attr.trap_id = mlnx_traps_info[index].sdk_trap_ids[trap_index];
        trap_attr.attr.trap_id_attr.trap_group = prio;
        trap_attr.attr.trap_id_attr.trap_action = action;

        sx_status = sx_api_host_ifc_trap_id_ext_set(gh_sdk, cmd, &trap_key, &trap_attr);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to %s for index %u trap %u/%u=%u, error is %s\n", SX_ACCESS_CMD_STR(cmd),
                       index, trap_index + 1, mlnx_traps_info[index].sdk_traps_num,
                       mlnx_traps_info[index].sdk_trap_ids[trap_index], SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_trap_set(uint32_t index, sai_packet_action_t sai_action, sai_object_id_t trap_group)
{
    return mlnx_trap_update(index, sai_action, trap_group, true);
}

static sai_status_t mlnx_trap_unset(uint32_t index)
{
    return mlnx_trap_update(index,
                            g_sai_db_ptr->traps_db[index].action,
                            g_sai_db_ptr->traps_db[index].trap_group,
                            false);
}

static sai_status_t mlnx_register_trap(const sx_access_cmd_t             cmd,
                                       const uint32_t                    trap_db_idx,
                                       const sx_host_ifc_register_key_t *register_key,
                                       const sx_user_channel_t          *user_channel)
{
    sx_status_t status;
    uint32_t    trap_index;

    assert(register_key);
    assert(user_channel);

    for (trap_index = 0; trap_index < mlnx_traps_info[trap_db_idx].sdk_traps_num; trap_index++) {
        if (register_key->key_type == SX_HOST_IFC_REGISTER_KEY_TYPE_GLOBAL) {
            status = sx_api_host_ifc_trap_id_register_set(gh_sdk, cmd, DEFAULT_ETH_SWID,
                                                          mlnx_traps_info[trap_db_idx].sdk_trap_ids[trap_index],
                                                          user_channel);
        } else {
            status = sx_api_host_ifc_port_vlan_trap_id_register_set(
                gh_sdk, cmd, DEFAULT_ETH_SWID, mlnx_traps_info[trap_db_idx].sdk_trap_ids[trap_index],
                register_key, user_channel);
        }

        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to %s for index %u trap %u/%u=%u, error is %s\n",
                       (SX_ACCESS_CMD_DEREGISTER == cmd) ? "deregister" : "register",
                       trap_db_idx, trap_index + 1, mlnx_traps_info[trap_db_idx].sdk_traps_num,
                       mlnx_traps_info[trap_db_idx].sdk_trap_ids[trap_index], SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_register_all_traps(const sx_access_cmd_t             cmd,
                                            const sx_host_ifc_register_key_t *register_key,
                                            const sx_user_channel_t          *user_channel)
{
    uint32_t     trap_db_idx;
    sai_status_t status;
    uint32_t     hostmiss_idx;

    assert(register_key);
    assert(user_channel);

    for (trap_db_idx = 0; mlnx_traps_info[trap_db_idx].trap_type != END_TRAP_INFO_ID; trap_db_idx++) {
        if ((mlnx_traps_info[trap_db_idx].sdk_traps_num == 0) || (!g_sai_db_ptr->traps_db[trap_db_idx].is_used)) {
            continue;
        }

        if (g_sai_db_ptr->traps_db[trap_db_idx].trap_channel.is_in_use) {
            continue;
        }

        status = mlnx_register_trap(cmd, trap_db_idx, register_key, user_channel);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to register trap, trap idx - %d\n", trap_db_idx);
            return status;
        }
    }

    status = mlnx_find_sai_trap_index_by_trap_type(HOSTMISS_TRAP_TYPE, SAI_OBJECT_TYPE_HOSTIF_TRAP, &hostmiss_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to find host miss trap index\n");
        return status;
    }

    if (cmd == SX_ACCESS_CMD_REGISTER) {
        status = mlnx_trap_set(hostmiss_idx, mlnx_traps_info[hostmiss_idx].action, g_sai_db_ptr->default_trap_group);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set host miss traps SDK\n");
            return status;
        }
    }

    status = mlnx_register_trap(cmd, hostmiss_idx, register_key, user_channel);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to register host miss trap, trap idx - %d\n", hostmiss_idx);
        return status;
    }

    if (cmd == SX_ACCESS_CMD_DEREGISTER) {
        status = mlnx_trap_update(hostmiss_idx, SAI_PACKET_ACTION_TRAP, g_sai_db_ptr->default_trap_group, false);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to unset host miss traps SDK\n");
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_trap_filter_set(uint32_t index, sai_object_list_t ports)
{
    sai_status_t      status;
    uint32_t          trap_index, ii, count;
    sx_port_log_id_t *filter_list;

    SX_LOG_ENTER();

    count = ports.count;
    filter_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * count);
    if (!filter_list) {
        SX_LOG_ERR("Failed to alloc filter list\n");
        return SAI_STATUS_NO_MEMORY;
    }

    for (ii = 0; ii < count; ii++) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(ports.list[ii], SAI_OBJECT_TYPE_PORT, &filter_list[ii], NULL))) {
            free(filter_list);
            SX_LOG_EXIT();
            return status;
        }
    }

    for (trap_index = 0; trap_index < mlnx_traps_info[index].sdk_traps_num; trap_index++) {
        if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_filter_set(gh_sdk,
                                                                            SX_ACCESS_CMD_DELETE_ALL, DEFAULT_ETH_SWID,
                                                                            mlnx_traps_info[index].sdk_trap_ids[
                                                                                trap_index], NULL, NULL))) {
            SX_LOG_ERR("Failed to clear filter list for index %u trap %u/%u=%u, error is %s\n",
                       index, trap_index + 1, mlnx_traps_info[index].sdk_traps_num,
                       mlnx_traps_info[index].sdk_trap_ids[trap_index], SX_STATUS_MSG(status));
            free(filter_list);
            return sdk_to_sai(status);
        }

        if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_filter_set(gh_sdk,
                                                                            SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                                                            mlnx_traps_info[index].sdk_trap_ids[
                                                                                trap_index], filter_list, &count))) {
            SX_LOG_ERR("Failed to set filter list for index %u trap %u/%u=%u, error is %s\n",
                       index, trap_index + 1, mlnx_traps_info[index].sdk_traps_num,
                       mlnx_traps_info[index].sdk_trap_ids[trap_index], SX_STATUS_MSG(status));
            free(filter_list);
            return sdk_to_sai(status);
        }
    }

    free(filter_list);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* trap action [sai_packet_action_t] */
static sai_status_t mlnx_trap_action_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg)
{
    sai_status_t     status;
    uint32_t         index;
    sx_trap_action_t action;

    SX_LOG_ENTER();

    sai_db_write_lock();

    status = mlnx_get_trap_db_index_by_oid(key->key.object_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap DB index\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_trap_action_to_sdk(value->s32, &action, 0, mlnx_traps_info[index].is_l2_trap))) {
        goto out;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(index, value->s32, g_sai_db_ptr->traps_db[index].trap_group))) {
        goto out;
    }

    g_sai_db_ptr->traps_db[index].action = value->s32;

out:
    sai_db_sync();
    sai_db_unlock();

    SX_LOG_EXIT();

    return status;
}

/* trap type [sai_hostif_trap_type_t] */
static sai_status_t mlnx_trap_type_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    uint32_t     index;
    sai_status_t status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_get_trap_db_index_by_oid(key->key.object_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap DB index\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    value->s32 = mlnx_traps_info[index].trap_type;

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/* trap action [sai_packet_action_t] */
static sai_status_t mlnx_trap_action_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    uint32_t     index;
    sai_status_t status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_get_trap_db_index_by_oid(key->key.object_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap DB index for trap oid 0x%" PRIx64 "\n", key->key.object_id);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    value->s32 = g_sai_db_ptr->traps_db[index].action;

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_trap_reset_group_impl(_In_ uint32_t trap_db_index, _In_ sai_object_id_t trap_group)
{
    sai_status_t status;

    status = mlnx_trap_unset(trap_db_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unset trap at index [%u].\n", trap_db_index);
        return status;
    }

    status = mlnx_trap_set(trap_db_index,
                           g_sai_db_ptr->traps_db[trap_db_index].action,
                           trap_group);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unset trap at index [%u].\n", trap_db_index);
        return status;
    }

    g_sai_db_ptr->traps_db[trap_db_index].trap_group = trap_group;

    return SAI_STATUS_SUCCESS;
}

/* trap-group ID for the trap [sai_object_id_t] */
static sai_status_t mlnx_trap_group_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t status;
    uint32_t     index, prio;

    SX_LOG_ENTER();

    sai_db_write_lock();

    status = mlnx_get_trap_db_index_by_oid(key->key.object_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap DB index\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(value->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
        goto out;
    }

    status = mlnx_trap_reset_group_impl(index, value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Reset trap_group failed.\n");
        goto out;
    }

out:
    sai_db_sync();
    sai_db_unlock();

    return status;
}

/* trap-group ID for the trap [sai_object_id_t] */
static sai_status_t mlnx_trap_group_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    uint32_t     index;
    sai_status_t status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_get_trap_db_index_by_oid(key->key.object_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap DB index\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    value->oid = g_sai_db_ptr->traps_db[index].trap_group;

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/* List of SAI ports to be excluded (disabled) from the trap generation [sai_object_list_t] */
static sai_status_t mlnx_trap_exclude_port_list_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    sai_status_t status;
    uint32_t     index;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_get_trap_db_index_by_oid(key->key.object_id, &index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get trap DB index\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_trap_filter_set(index, value->objlist);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set trap filter\n");
        goto out;
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/* This function should be guarded by lock */
static sai_status_t mlnx_trap_mirror_drop_by_wred_set(_In_ sx_span_session_id_t span_session_id, _In_ bool is_create)
{
    sai_status_t        sai_status = SAI_STATUS_FAILURE;
    uint32_t            port_idx = 0;
    mlnx_port_config_t *port = NULL;
    sx_port_log_id_t    ingress_port;

    SX_LOG_ENTER();

    mlnx_port_not_in_lag_foreach(port, port_idx) {
        assert(NULL != port);
        if (port->is_span_analyzer_port) {
            continue;
        }
        ingress_port = port->logical;

        sai_status = mlnx_port_wred_mirror_set_impl(ingress_port, span_session_id, is_create);
        if (SAI_ERR(sai_status)) {
            return sai_status;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_trap_mirror_drop_by_router_set(_In_ sx_span_session_id_t span_session_id, _In_ bool is_create)
{
    sx_span_drop_mirroring_attr_t drop_mirroring_attr_p;
    sx_span_drop_reason_t         drop_reason_list_p = SX_SPAN_DROP_REASON_ALL_ROUTER_DROPS_E;
    const uint32_t                drop_reason_cnt = 1;
    sai_status_t                  sai_status = SAI_STATUS_FAILURE;
    sx_status_t                   sx_status = SX_STATUS_ERROR;
    const sx_access_cmd_t         cmd = is_create ?
                                        SX_ACCESS_CMD_SET :
                                        SX_ACCESS_CMD_DELETE_ALL;

    SX_LOG_ENTER();

    memset(&drop_mirroring_attr_p, 0, sizeof(drop_mirroring_attr_p));
    sx_status = sx_api_span_drop_mirror_set(gh_sdk, cmd, span_session_id,
                                            &drop_mirroring_attr_p,
                                            &drop_reason_list_p,
                                            drop_reason_cnt);

    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Error setting drop mirror session 0x%x: %s\n",
                   span_session_id, SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_trap_mirror_session_bind_update(_In_ sx_span_session_id_t sx_session, _In_ bool is_enable)
{
    sx_status_t                sx_status;
    sx_span_mirror_bind_key_t  key;
    sx_span_mirror_bind_attr_t attr;
    sx_access_cmd_t            bind_cmd = is_enable ? SX_ACCESS_CMD_BIND : SX_ACCESS_CMD_UNBIND;

    if (!mlnx_chip_is_spc2or3or4()) {
        return SAI_STATUS_SUCCESS;
    }

    memset(&key, 0, sizeof(key));
    memset(&attr, 0, sizeof(attr));

    key.type = SX_SPAN_MIRROR_BIND_ING_WRED_E;
    attr.span_session_id = sx_session;

    sx_status = sx_api_span_mirror_bind_set(gh_sdk, bind_cmd, &key, &attr);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to bind WRED mirroring to mirror session %x - %s\n", sx_session, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

/* This function should be guarded by lock */
static sai_status_t mlnx_trap_mirror_array_drop_set(_In_ uint32_t         trap_db_idx,
                                                    _In_ sai_object_id_t *sai_mirror_oid,
                                                    _In_ uint32_t         sai_mirror_oid_count,
                                                    _In_ bool             is_create)
{
    sai_status_t           sai_status = SAI_STATUS_FAILURE;
    sx_span_session_id_t   sx_span_session_id;
    sai_hostif_trap_type_t trap_type;
    uint32_t               oid_data, ii;

    SX_LOG_ENTER();

    if (NULL == sai_mirror_oid) {
        SX_LOG_ERR("sai mirror oid ptr is NULL\n");
        return SAI_STATUS_FAILURE;
    }

    trap_type = mlnx_traps_info[trap_db_idx].trap_type;

    assert((trap_type == SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED) ||
           (trap_type == SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER));

    for (ii = 0; ii < sai_mirror_oid_count; ii++) {
        sai_status = mlnx_object_to_type(sai_mirror_oid[ii], SAI_OBJECT_TYPE_MIRROR_SESSION, &oid_data, NULL);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error getting span session id from sai mirror id %" PRIx64 "\n", sai_mirror_oid[ii]);
            return sai_status;
        }

        sx_span_session_id = (sx_span_session_id_t)oid_data;

        if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED == trap_type) {
            if (is_create) {
                sai_status = mlnx_trap_mirror_session_bind_update(sx_span_session_id, is_create);
                if (SAI_ERR(sai_status)) {
                    return sai_status;
                }
            }

            sai_status = mlnx_trap_mirror_drop_by_wred_set(sx_span_session_id, is_create);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error setting trap mirror drop by wred for span session id %d\n",
                           sx_span_session_id);
                return sai_status;
            }

            if (!is_create) {
                sai_status = mlnx_trap_mirror_session_bind_update(sx_span_session_id, is_create);
                if (SAI_ERR(sai_status)) {
                    return sai_status;
                }
            }
        } else { /* SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER */
            sai_status = mlnx_trap_mirror_drop_by_router_set(sx_span_session_id, is_create);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error setting trap mirror drop by router for span session id %d\n",
                           sx_span_session_id);
                return sai_status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* This function should be guarded by lock */
static sai_status_t mlnx_trap_mirror_array_drop_clear(_In_ uint32_t trap_db_idx)
{
    sai_status_t           sai_status = SAI_STATUS_FAILURE;
    const bool             is_create = false;
    sai_hostif_trap_type_t trap_type;
    sai_object_id_t       *sai_mirror_oid = NULL;
    uint32_t               sai_mirror_oid_cnt = 0;

    SX_LOG_ENTER();

    trap_type = mlnx_traps_info[trap_db_idx].trap_type;
    if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED == trap_type) {
        sai_mirror_oid = g_sai_db_ptr->trap_mirror_discard_wred_db.mirror_oid;
        sai_mirror_oid_cnt = g_sai_db_ptr->trap_mirror_discard_wred_db.count;
    } else if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER == trap_type) {
        sai_mirror_oid = g_sai_db_ptr->trap_mirror_discard_router_db.mirror_oid;
        sai_mirror_oid_cnt = g_sai_db_ptr->trap_mirror_discard_router_db.count;
    } else {
        SX_LOG_ERR("trap mirror session set is only supported for "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED and "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER, "
                   "current trap type is %d\n", trap_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status = mlnx_trap_mirror_array_drop_set(trap_db_idx,
                                                 sai_mirror_oid,
                                                 sai_mirror_oid_cnt,
                                                 is_create);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error deleting trap mirror array\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED == trap_type) {
        g_sai_db_ptr->trap_mirror_discard_wred_db.count = 0;
    } else if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER == trap_type) {
        g_sai_db_ptr->trap_mirror_discard_router_db.count = 0;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function should be guarded by lock */
static sai_status_t mlnx_trap_mirror_db_fill(_In_ uint32_t                 trap_db_idx,
                                             _In_ const sai_object_list_t *sai_mirror_objlist)
{
    const sai_hostif_trap_type_t trap_type = mlnx_traps_info[trap_db_idx].trap_type;

    SX_LOG_ENTER();

    if (NULL == sai_mirror_objlist) {
        SX_LOG_ERR("sai mirror objlist is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SPAN_SESSION_MAX < sai_mirror_objlist->count) {
        SX_LOG_ERR("mirror objlist count %d is greater than limit %d\n",
                   sai_mirror_objlist->count, SPAN_SESSION_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED == trap_type) {
        g_sai_db_ptr->trap_mirror_discard_wred_db.count = sai_mirror_objlist->count;
        memcpy(g_sai_db_ptr->trap_mirror_discard_wred_db.mirror_oid,
               sai_mirror_objlist->list,
               sai_mirror_objlist->count * sizeof(sai_object_id_t));
    } else if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER == trap_type) {
        g_sai_db_ptr->trap_mirror_discard_router_db.count = sai_mirror_objlist->count;
        memcpy(g_sai_db_ptr->trap_mirror_discard_router_db.mirror_oid,
               sai_mirror_objlist->list,
               sai_mirror_objlist->count * sizeof(sai_object_id_t));
    } else {
        SX_LOG_ERR("trap mirror session set is only supported for "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED and "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER, "
                   "current trap type is %d\n", trap_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* mirror session for the trap [sai_object_id_t] */
static sai_status_t mlnx_trap_mirror_session_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    uint32_t               trap_db_idx = 0;
    bool                   is_create = false;
    sai_hostif_trap_type_t trap_type;
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (!mlnx_is_hostif_trap_valid(key->key.object_id)) {
        SX_LOG_ERR("Invalid trap\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    sai_status = mlnx_object_to_type(key->key.object_id,
                                     SAI_OBJECT_TYPE_HOSTIF_TRAP,
                                     &trap_db_idx,
                                     NULL);
    if (SAI_STATUS_SUCCESS != sai_status) {
        goto out;
    }

    trap_type = mlnx_traps_info[trap_db_idx].trap_type;
    if ((SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED != trap_type)
        && (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER != trap_type)) {
        SX_LOG_ERR("trap mirror session set is only supported for "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED and "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER, "
                   "current trap type is %d\n", trap_type);
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    sai_status = mlnx_trap_mirror_array_drop_clear(trap_db_idx);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error clearing trap mirror array\n");
        goto out;
    }

    is_create = true;
    sai_status = mlnx_trap_mirror_array_drop_set(trap_db_idx,
                                                 value->objlist.list,
                                                 value->objlist.count,
                                                 is_create);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error adding mirror drop trap for trap db idx %d\n", trap_db_idx);
        goto out;
    }

    sai_status = mlnx_trap_mirror_db_fill(trap_db_idx, &value->objlist);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error filling trap mirror db for trap idx %d\n", trap_db_idx);
        goto out;
    }


out:
    sai_db_unlock();
    SX_LOG_EXIT();

    return sai_status;
}

/* mirror session for the trap [sai_object_id_t] */
static sai_status_t mlnx_trap_mirror_session_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t           sai_status = SAI_STATUS_FAILURE;
    uint32_t               trap_db_idx;
    sai_hostif_trap_type_t trap_type;

    SX_LOG_ENTER();

    sai_db_read_lock();

    if (!mlnx_is_hostif_trap_valid(key->key.object_id)) {
        SX_LOG_ERR("Invalid trap\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    sai_status = mlnx_object_to_type(key->key.object_id,
                                     SAI_OBJECT_TYPE_HOSTIF_TRAP,
                                     &trap_db_idx,
                                     NULL);
    if (SAI_STATUS_SUCCESS != sai_status) {
        goto out;
    }

    trap_type = mlnx_traps_info[trap_db_idx].trap_type;
    if ((SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED != trap_type)
        && (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER != trap_type)) {
        SX_LOG_ERR("trap mirror session get is only supported for "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED and "
                   "SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER, "
                   "current trap type is %d\n", trap_type);
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_WRED == trap_type) {
        sai_status = mlnx_fill_objlist(g_sai_db_ptr->trap_mirror_discard_wred_db.mirror_oid,
                                       g_sai_db_ptr->trap_mirror_discard_wred_db.count,
                                       &value->objlist);
    } else if (SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER == trap_type) {
        sai_status = mlnx_fill_objlist(g_sai_db_ptr->trap_mirror_discard_router_db.mirror_oid,
                                       g_sai_db_ptr->trap_mirror_discard_router_db.count,
                                       &value->objlist);
    }

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error filling objlist for trap id %d\n", trap_type);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();

    return sai_status;
}

static sai_status_t mlnx_trap_counter_id_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t status;

    status = mlnx_translate_trap_id_to_sai_counter(key->key.object_id, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get counter id\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_trap_counter_id_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    sai_db_write_lock();

    if (!mlnx_is_hostif_trap_valid(key->key.object_id)) {
        SX_LOG_ERR("Invalid trap oid 0x%" PRIx64 "\n", key->key.object_id);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_update_hostif_trap_counter_unlocked(key->key.object_id, value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update trap counter\n");
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*need sai_db read lock*/
sai_status_t mlnx_get_hostif_packet_data(sx_receive_info_t *receive_info, uint32_t *attr_count, sai_attribute_t *attr)
{
    assert(receive_info);
    assert(attr_count);
    assert(attr);

    sai_status_t status;
    const char  *trap_name;
    bool         is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                          (!g_sai_db_ptr->issu_end_called);

    if (*attr_count < RECV_ATTRIBS_NUM) {
        SX_LOG_ERR("Insufficient attribute count %u %u\n", RECV_ATTRIBS_NUM, *attr_count);
        *attr_count = RECV_ATTRIBS_NUM;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    *attr_count = RECV_ATTRIBS_NUM;
    attr[0].id = SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID;
    attr[1].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT;
    attr[2].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG;
    attr[3].id = SAI_HOSTIF_PACKET_ATTR_TIMESTAMP;

    if (SX_INVALID_PORT == receive_info->source_log_port) {
        SX_LOG_ERR("sx_api_host_ifc_recv returned unknown port\n");
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_translate_sdk_trap_to_sai(receive_info->trap_id, &trap_name, &attr[0].value.oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("unknown sdk trap %u\n", receive_info->trap_id);
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, receive_info->source_log_port, NULL, &attr[1].value.oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create port oid\n");
        return status;
    }

    if (receive_info->is_lag && (!is_warmboot_init_stage)) {
        status = mlnx_log_port_to_object(receive_info->source_lag_port, &attr[2].value.oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create lag oid\n");
            return status;
        }
    } else {
        attr[2].value.oid = SAI_NULL_OBJECT_ID;
    }

    if (receive_info->has_timestamp) {
        attr[3].value.timespec.tv_sec = receive_info->timestamp.tv_sec;
        attr[3].value.timespec.tv_nsec = receive_info->timestamp.tv_nsec;
    } else {
        SX_LOG_DBG("Hostif packet has no timestamp\n");
        memset(&attr[3].value.timespec, 0, sizeof(sai_timespec_t));
    }

    SX_LOG_INF("Received trap %s port %x\n", trap_name, receive_info->source_log_port);

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   hostif receive function
 *
 * Arguments:
 *    [in]  hif_id  - host interface id
 *    [in,out] buffer_size - [in] allocated buffer size. [out] actual packet size in bytes
 *    [out] buffer - packet buffer
 *    [in,out] attr_count - [in] allocated list size. [out] number of attributes
 *    [out] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    SAI_STATUS_BUFFER_OVERFLOW if buffer_size is insufficient,
 *    and buffer_size will be filled with required size. Or
 *    if attr_count is insufficient, and attr_count
 *    will be filled with required count.
 *    Failure status code on error
 */
static sai_status_t mlnx_recv_hostif_packet(_In_ sai_object_id_t   hif_id,
                                            _Inout_ sai_size_t    *buffer_size,
                                            _Out_ void            *buffer,
                                            _Inout_ uint32_t      *attr_count,
                                            _Out_ sai_attribute_t *attr_list)
{
    sx_receive_info_t *receive_info = NULL;
    mlnx_object_id_t   mlnx_hif = {0};
    uint32_t           packet_size;
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_fd_t            fd;

    SX_LOG_ENTER();

    memset(&fd, 0, sizeof(fd));

    receive_info = (sx_receive_info_t*)calloc(1, sizeof(*receive_info));
    if (NULL == receive_info) {
        SX_LOG_ERR("Can't allocate receive_info memory\n");
        status = SX_STATUS_NO_MEMORY;
        goto out;
    }

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hif_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = check_host_if_is_valid(mlnx_hif);
    if (SAI_ERR(status)) {
        goto out;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);

    if (SAI_HOSTIF_OBJECT_TYPE_FD != g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
        SX_LOG_ERR("Can't recv on non FD host interface type %u\n", g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        cl_plock_release(&g_sai_db_ptr->p_lock);
        goto out;
    }

    memcpy(&fd, &g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].fd, sizeof(fd));
    cl_plock_release(&g_sai_db_ptr->p_lock);

    packet_size = (uint32_t)*buffer_size;
    if (SX_STATUS_SUCCESS != (status = sx_lib_host_ifc_recv(&fd, buffer, &packet_size, receive_info))) {
        if (SX_STATUS_NO_MEMORY == status) {
            SX_LOG_ERR("sx_api_host_ifc_recv failed with insufficient buffer %u %zu\n", packet_size, *buffer_size);
            *buffer_size = packet_size;
            status = SAI_STATUS_BUFFER_OVERFLOW;
            goto out;
        }
        SX_LOG_ERR("sx_api_host_ifc_recv failed with error %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }
    *buffer_size = packet_size;

    status = mlnx_get_hostif_packet_data(receive_info, attr_count, attr_list);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to parse host interface packet data\n");
        goto out;
    }

out:
    free(receive_info);
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *   hostif send function
 *
 * Arguments:
 *    [in] hif_id  - host interface id. only valid for send through FD channel. Use SAI_NULL_OBJECT_ID for send through CB channel.
 *    [in] buffer size - packet size in bytes
 *    [In] buffer - packet buffer
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_send_hostif_packet(_In_ sai_object_id_t        hif_id,
                                            _In_ sai_size_t             buffer_size,
                                            _In_ const void            *buffer,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    uint32_t                     type_index, port_index, prio_index;
    const sai_attribute_value_t *type, *port, *prio_attr;
    uint32_t                     port_data;
    sai_status_t                 status;
    sx_fd_t                      fd;
    uint8_t                      prio = 0;

    memset(&fd, 0, sizeof(fd));

    status = check_attribs_on_create_without_oid(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_PACKET);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_PACKET);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_HOSTIF_TX_TYPE_PIPELINE_BYPASS == type->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG, &port,
                                     &port_index))) {
            SX_LOG_ERR("Missing mandatory attribute port or lag for bypass TX\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (SAI_OBJECT_TYPE_PORT == sai_object_type_query(port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(port->oid, SAI_OBJECT_TYPE_PORT, &port_data, NULL))) {
                return status;
            }
        } else {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_log_port(port->oid, &port_data))) {
                return status;
            }
        }
    } else if (SAI_HOSTIF_TX_TYPE_PIPELINE_LOOKUP == type->s32) {
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG, &port,
                                     &port_index))) {
            SX_LOG_ERR("Invalid attribute port or lag for lookup TX\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + port_index;
        }
    } else {
        SX_LOG_ERR("Invalid TX type %u\n", type->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_PACKET_ATTR_EGRESS_QUEUE_INDEX, &prio_attr,
                                 &prio_index);
    if (SAI_OK(status)) {
        prio = prio_attr->u8;
    }

    if (SAI_NULL_OBJECT_ID == hif_id) {
        cl_plock_acquire(&g_sai_db_ptr->p_lock);
        memcpy(&fd, &g_sai_db_ptr->callback_channel.channel.fd, sizeof(fd));
        cl_plock_release(&g_sai_db_ptr->p_lock);
    } else {
        mlnx_object_id_t mlnx_hif = {0};

        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hif_id, &mlnx_hif);
        if (SAI_ERR(status)) {
            return status;
        }

        status = check_host_if_is_valid(mlnx_hif);
        if (SAI_ERR(status)) {
            return status;
        }

        cl_plock_acquire(&g_sai_db_ptr->p_lock);

        if (SAI_HOSTIF_OBJECT_TYPE_FD != g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].sub_type) {
            SX_LOG_ERR("Can't send on non FD host interface type %u\n", mlnx_hif.field.sub_type);
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        memcpy(&fd, &g_sai_db_ptr->hostif_db[mlnx_hif.id.u32].fd, sizeof(fd));
        cl_plock_release(&g_sai_db_ptr->p_lock);
    }

    /* TODO : fill correct cos prio */
    if (SAI_HOSTIF_TX_TYPE_PIPELINE_BYPASS == type->s32) {
        if (SX_STATUS_SUCCESS !=
            (status =
                 sx_lib_host_ifc_unicast_ctrl_send(&fd, buffer, (uint32_t)buffer_size, DEFAULT_ETH_SWID, port_data,
                                                   prio))) {
            SX_LOG_ERR("sx_lib_host_ifc_unicast_ctrl_send failed with error %s\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    } else {
        if (SX_STATUS_SUCCESS !=
            (status = sx_lib_host_ifc_data_send(&fd, buffer, (uint32_t)buffer_size, DEFAULT_ETH_SWID, prio))) {
            SX_LOG_ERR("sx_lib_host_ifc_data_send failed with error %s\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_hostif_trap_group_availability_get(_In_ sai_object_id_t        switch_id,
                                                     _In_ uint32_t               attr_count,
                                                     _In_ const sai_attribute_t *attr_list,
                                                     _Out_ uint64_t             *count)
{
    assert(count);

    *count = (uint64_t)mlnx_hostif_trap_group_db_free_entries_count();
    return SAI_STATUS_SUCCESS;
}

/* require sai_db read lock */
static sai_status_t mlnx_hostif_table_entry_fill_sx_reg_key(sai_hostif_table_entry_type_t table_entry_type,
                                                            sai_object_id_t               port_vlan_lag,
                                                            sx_host_ifc_register_key_t   *register_key)
{
    sai_status_t     status;
    sx_port_log_id_t log_port;
    uint16_t         vlan_id;

    assert(register_key);

    switch (table_entry_type) {
    case SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD:
    case SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID:
        register_key->key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_GLOBAL;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT:
    case SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG:
        status = mlnx_object_to_log_port(port_vlan_lag, &log_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get object 0x%" PRIx64 " log_port\n", port_vlan_lag);
            return status;
        }

        register_key->key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_PORT;
        register_key->key_value.port_id = log_port;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN:
        status = sai_object_to_vlan(port_vlan_lag, &vlan_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get object 0x%" PRIx64 " vlan id\n", port_vlan_lag);
            return status;
        }

        register_key->key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_VLAN;
        register_key->key_value.vlan_id = vlan_id;
        break;

    default:
        SX_LOG_ERR("Invalid hostif table entry type %d\n", table_entry_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

/* requires sai_db read lock*/
static sai_status_t mlnx_hostif_table_entry_fill_sx_reg_key_by_mlnx_oid(const mlnx_object_id_t      mlnx_oid,
                                                                        sx_host_ifc_register_key_t *register_key)
{
    mlnx_port_config_t *port;

    assert(register_key);

    switch (mlnx_oid.field.sub_type) {
    case SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD:
    case SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID:
        register_key->key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_GLOBAL;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT:
    case SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG:
        if (mlnx_oid.id.hostif_table_entry.port_vlan_db_idx > (MAX_PORTS_DB * 2)) {
            SX_LOG_ERR("Invalid oid - port idx %d is larger than max %d\n",
                       mlnx_oid.id.hostif_table_entry.port_vlan_db_idx, MAX_PORTS_DB * 2);
            return SAI_STATUS_FAILURE;
        }

        port = mlnx_port_by_idx(mlnx_oid.id.hostif_table_entry.port_vlan_db_idx);

        if (!port->is_present) {
            SX_LOG_ERR("Port 0x%" PRIx64 " is not present to use for hostif table entry\n", port->saiport);
            return SAI_STATUS_FAILURE;
        }

        register_key->key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_PORT;
        register_key->key_value.port_id = port->logical;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN:
        register_key->key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_VLAN;
        register_key->key_value.vlan_id = mlnx_oid.id.hostif_table_entry.port_vlan_db_idx;
        break;

    default:
        SX_LOG_ERR("Invalid hostif table entry type %d\n", mlnx_oid.field.sub_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

/* requires sai_db read lock */
static sai_status_t mlnx_create_hostif_table_entry_oid(sai_hostif_table_entry_type_t         table_entry_type,
                                                       uint32_t                              trap_db_idx,
                                                       sai_object_id_t                       port_vlan_lag,
                                                       sai_hostif_table_entry_channel_type_t channel_type,
                                                       sai_object_id_t                       hostif,
                                                       sai_object_id_t                      *oid)
{
    mlnx_object_id_t mlnx_hif_table, mlnx_hif;
    sai_status_t     status;
    uint32_t         port_index;
    uint16_t         vlan_id;
    uint32_t         max_hostif_idx;

    memset(&mlnx_hif_table, 0, sizeof(mlnx_hif_table));

    mlnx_hif_table.field.sub_type = table_entry_type;

    if ((table_entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT) ||
        (table_entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG)) {
        status = mlnx_port_idx_by_obj_id(port_vlan_lag, &port_index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get port index for oid 0x%" PRIx64 "\n", port_vlan_lag);
            return status;
        }

        if (port_index > INT16_MAX) {
            SX_LOG_ERR("Failed to create oid, port index %d is larger than max %d\n", port_index, INT16_MAX);
            return SAI_STATUS_FAILURE;
        }

        mlnx_hif_table.id.hostif_table_entry.port_vlan_db_idx = (uint16_t)port_index;
    } else if (table_entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN) {
        status = sai_object_to_vlan(port_vlan_lag, &vlan_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get object vlan id\n");
            return status;
        }
        mlnx_hif_table.id.hostif_table_entry.port_vlan_db_idx = vlan_id;
    }

    if (trap_db_idx > INT16_MAX) {
        SX_LOG_ERR("Failed to create oid, trap index %d is larger than max %d\n", trap_db_idx, INT16_MAX);
        return SAI_STATUS_FAILURE;
    }

    mlnx_hif_table.id.hostif_table_entry.trap_db_idx = (uint16_t)trap_db_idx;
    mlnx_hif_table.ext.hostif_table_entry.channel_type = channel_type;

    if ((channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD) ||
        (channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK)) {
        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hostif, &mlnx_hif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate sai object id to mlnx oid\n");
            return status;
        }

        max_hostif_idx = 1 << (HOSTIF_TABLE_ENTRY_HOSTIF_IDX_BITS - 1);
        if (mlnx_hif.id.u32 > max_hostif_idx) {
            SX_LOG_ERR("Failed to create oid, hostif index %d is larger than max %d\n", mlnx_hif.id.u32,
                       max_hostif_idx);
            return SAI_STATUS_FAILURE;
        }

        mlnx_hif_table.ext.hostif_table_entry.hostif_db_idx = (uint16_t)mlnx_hif.id.u32;
    }

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, &mlnx_hif_table, oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate mlnx_oid to sai_object_id\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* requires sai_db read lock*/
static sai_status_t mlnx_hif_table_entry_fill_user_channel_by_hif_idx(
    sai_hostif_table_entry_channel_type_t channel_type,
    uint32_t                              hostif_idx,
    sx_user_channel_t                    *user_channel)
{
    sai_status_t status;

    assert(user_channel);

    if ((channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD) ||
        (channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK)) {
        status = check_hostif_is_valid_by_idx_unlocked(hostif_idx);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    switch (channel_type) {
    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD:
        if (g_sai_db_ptr->hostif_db[hostif_idx].sub_type != SAI_HOSTIF_OBJECT_TYPE_FD) {
            SX_LOG_ERR("Can't set non FD host interface type %u\n",
                       g_sai_db_ptr->hostif_db[hostif_idx].sub_type);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        user_channel->type = SX_USER_CHANNEL_TYPE_FD;
        memcpy(&user_channel->channel.fd, &g_sai_db_ptr->hostif_db[hostif_idx].fd,
               sizeof(user_channel->channel.fd));
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK:
        if (g_sai_db_ptr->hostif_db[hostif_idx].sub_type != SAI_HOSTIF_OBJECT_TYPE_GENETLINK) {
            SX_LOG_ERR("Can't set non FD host interface type %u\n",
                       g_sai_db_ptr->hostif_db[hostif_idx].sub_type);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        user_channel->type = SX_USER_CHANNEL_TYPE_PSAMPLE;
        user_channel->channel.psample_params.group_id =
            g_sai_db_ptr->hostif_db[hostif_idx].psample_group.group_id;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_CB:
        user_channel->type = SX_USER_CHANNEL_TYPE_FD;
        memcpy(&user_channel->channel.fd, &g_sai_db_ptr->callback_channel.channel.fd,
               sizeof(user_channel->channel.fd));
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_L3:
        user_channel->type = SX_USER_CHANNEL_TYPE_L3_NETDEV;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT:
        user_channel->type = SX_USER_CHANNEL_TYPE_PHY_PORT_NETDEV;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_LOGICAL_PORT:
        user_channel->type = SX_USER_CHANNEL_TYPE_LOG_PORT_NETDEV;
        break;

    default:
        SX_LOG_ERR("Invalid host interface table entry channel type %ds\n", channel_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static bool mlnx_are_register_keys_equal(sx_host_ifc_register_key_t *key1, sx_host_ifc_register_key_t *key2)
{
    assert(key1);
    assert(key2);

    if (key1->key_type != key2->key_type) {
        return false;
    }

    switch (key1->key_type) {
    case SX_HOST_IFC_REGISTER_KEY_TYPE_GLOBAL:
        return true;

    case SX_HOST_IFC_REGISTER_KEY_TYPE_PORT:
        return key1->key_value.port_id == key2->key_value.port_id;

    case SX_HOST_IFC_REGISTER_KEY_TYPE_VLAN:
        return key1->key_value.vlan_id == key2->key_value.vlan_id;

    default:
        SX_LOG_ERR("Invalid key1 type %d\n", key1->key_type);
        break;
    }

    return false;
}

static bool mlnx_are_user_channels_equal(sx_user_channel_t *channel1, sx_user_channel_t *channel2)
{
    assert(channel1);
    assert(channel2);

    if (channel1->type != channel2->type) {
        return false;
    }

    switch (channel1->type) {
    case SX_USER_CHANNEL_TYPE_FD:
        return channel1->channel.fd.fd == channel2->channel.fd.fd;

    case SX_USER_CHANNEL_TYPE_PSAMPLE:
        return channel1->channel.psample_params.group_id == channel2->channel.psample_params.group_id;

    case SX_USER_CHANNEL_TYPE_L3_NETDEV:
    case SX_USER_CHANNEL_TYPE_LOG_PORT_NETDEV:
    case SX_USER_CHANNEL_TYPE_PHY_PORT_NETDEV:
        return true;

    default:
        SX_LOG_ERR("Invalid channel 1 type %d\n", channel1->type);
        break;
    }

    return false;
}

static sai_status_t mlnx_is_hostif_table_key_registered(uint32_t                    trap_db_idx,
                                                        sx_host_ifc_register_key_t *register_key,
                                                        sx_user_channel_t          *user_channel,
                                                        bool                       *is_registered)
{
    sx_status_t                      sx_status;
    const uint32_t                   register_entry_get_count = 20;
    sx_host_ifc_register_get_entry_t register_entries[20];
    uint32_t                         register_entries_count = register_entry_get_count;
    uint32_t                         ii = 0;

    SX_LOG_ENTER();

    assert(register_key);
    assert(is_registered);

    sx_status = sx_api_host_ifc_port_vlan_trap_id_register_get(gh_sdk, SX_ACCESS_CMD_GET_FIRST, DEFAULT_ETH_SWID,
                                                               mlnx_traps_info[trap_db_idx].sdk_trap_ids[0],
                                                               NULL, register_entries, &register_entries_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get register entries - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    while (true) {
        for (ii = 0; ii < register_entries_count; ii++) {
            if (!mlnx_are_register_keys_equal(&register_entries[ii].register_key, register_key)) {
                continue;
            }

            if ((user_channel == NULL) ||
                mlnx_are_user_channels_equal(&register_entries[ii].user_channel, user_channel)) {
                *is_registered = true;
                return SAI_STATUS_SUCCESS;
            }
        }

        if (register_entries_count < register_entry_get_count) {
            *is_registered = false;
            break;
        }

        sx_status = sx_api_host_ifc_port_vlan_trap_id_register_get(gh_sdk, SX_ACCESS_CMD_GETNEXT,
                                                                   DEFAULT_ETH_SWID,
                                                                   mlnx_traps_info[trap_db_idx].sdk_trap_ids[0],
                                                                   &register_entries[register_entries_count - 1],
                                                                   register_entries,
                                                                   &register_entries_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get register entries - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_register_wildcard_channel(sx_access_cmd_t cmd, uint32_t trap_idx)
{
    sx_host_ifc_register_key_t reg_key;
    sai_status_t               status;

    SX_LOG_ENTER();

    status = mlnx_hostif_table_entry_fill_sx_reg_key(SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD, SAI_NULL_OBJECT_ID,
                                                     &reg_key);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill register key for hostif table entry\n");
        return status;
    }

    status = mlnx_register_trap(cmd, trap_idx, &reg_key, &g_sai_db_ptr->wildcard_channel.trap_channel);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update trap hostif table entry sx. Trap index - %d\n", trap_idx);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Create host interface table entry
 *
 * @param[out] hif_table_entry Host interface table entry
 * @param[in] switch_id Switch object id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Aarray of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_create_hostif_table_entry(_Out_ sai_object_id_t      *hif_table_entry,
                                            _In_ sai_object_id_t        switch_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *type, *channel, *obj, *trap, *fd;
    uint32_t                     type_index, channel_index, obj_index, trap_attr_index, fd_index;
    uint32_t                     trap_db_index = 0;
    sx_host_ifc_register_key_t   sx_register_key;
    bool                         is_registered;
    sai_object_id_t              port_lag_vlan_oid = SAI_NULL_OBJECT_ID;
    sai_object_id_t              hostif = SAI_NULL_OBJECT_ID;
    sx_user_channel_t            user_channel;
    mlnx_object_id_t             mlnx_hif_oid;
    uint16_t                     vlan_id;
    uint32_t                     port_db_idx;
    sai_object_type_t            obj_type;

    SX_LOG_ENTER();

    memset(&sx_register_key, 0, sizeof(sx_register_key));

    status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, hif_table_entry);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);

    sai_db_write_lock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID, &trap,
                                 &trap_attr_index);
    if (type->s32 != SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD) {
        assert(SAI_OK(status));

        if (trap->oid == SAI_NULL_OBJECT_ID) {
            SX_LOG_ERR("Trap id is SAI_NULL_OBJECT_ID\n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + trap_attr_index;
            goto out;
        }

        status = mlnx_get_trap_db_index_by_oid(trap->oid, &trap_db_index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get trap DB index\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID, &obj, &obj_index);
        if (type->s32 != SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID) {
            assert(SAI_OK(status));
            if (obj->oid == SAI_NULL_OBJECT_ID) {
                SX_LOG_ERR("Object attribute is SAI_NULL_OBJECT_ID\n");
                status = SAI_STATUS_INVALID_ATTR_VALUE_0 + obj_index;
                goto out;
            }
            port_lag_vlan_oid = obj->oid;
        } else if (SAI_OK(status)) {
            SX_LOG_ERR("Attribute OBJECT is valid only for VLAN/LAG/PORT entries\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + obj_index;
            goto out;
        }

        if (type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN) {
            status = sai_object_to_vlan(port_lag_vlan_oid, &vlan_id);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get object 0x%" PRIx64 " vlan id\n", port_lag_vlan_oid);
                goto out;
            }

            if (!mlnx_vlan_is_created(vlan_id)) {
                SX_LOG_ERR("VLAN %d not created\n", vlan_id);
                status = SAI_STATUS_INVALID_ATTRIBUTE_0 + obj_index;
                goto out;
            }
        }

        obj_type = sai_object_type_query(port_lag_vlan_oid);
        if ((type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT) && (obj_type != SAI_OBJECT_TYPE_PORT)) {
            SX_LOG_ERR("Invalid object type %s for PORT table entry\n", SAI_TYPE_STR(obj_type));
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + obj_index;
            goto out;
        }

        if ((type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG) && (obj_type != SAI_OBJECT_TYPE_LAG)) {
            SX_LOG_ERR("Invalid object type %s for LAG table entry\n", SAI_TYPE_STR(obj_type));
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + obj_index;
            goto out;
        }

        if ((type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT) ||
            (type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG)) {
            status = mlnx_port_idx_by_obj_id(port_lag_vlan_oid, &port_db_idx);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get port db index for port oid 0x%" PRIx64 "\n", port_lag_vlan_oid);
                goto out;
            }
        }
    } else if (SAI_OK(status)) {
        SX_LOG_ERR("Invalid attribute TRAP_ID for wildcard entry\n");
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + trap_attr_index;
        goto out;
    }

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE,
                                 &channel,
                                 &channel_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF, &fd, &fd_index);
    if ((SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD == channel->s32) ||
        (SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK == channel->s32)) {
        assert(SAI_OK(status));

        if (fd->oid == SAI_NULL_OBJECT_ID) {
            SX_LOG_ERR("Host interface attribute is SAI_NULL_OBJECT_ID\n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + fd_index;
            goto out;
        }

        hostif = fd->oid;
    } else {
        if (SAI_OK(status)) {
            SX_LOG_ERR("Redundant host interface attribute provided\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + fd_index;
            goto out;
        }
    }

    status = mlnx_hostif_table_entry_fill_sx_reg_key(type->s32, port_lag_vlan_oid, &sx_register_key);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill register key for hostif table entry\n");
        goto out;
    }

    memset(&mlnx_hif_oid, 0, sizeof(mlnx_hif_oid));

    if ((channel->s32 == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD) ||
        (channel->s32 == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK)) {
        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hostif, &mlnx_hif_oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate sai object id 0x%" PRIx64 " to mlnx oid\n", hostif);
            goto out;
        }
    }

    status = mlnx_hif_table_entry_fill_user_channel_by_hif_idx(channel->s32, mlnx_hif_oid.id.u32, &user_channel);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill sx user channel data\n");
        goto out;
    }

    if (type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD) {
        if (g_sai_db_ptr->wildcard_channel.is_in_use) {
            SX_LOG_ERR("Only one wildcard entry is possible\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        status = mlnx_register_all_traps(SX_ACCESS_CMD_REGISTER, &sx_register_key, &user_channel);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update wildcard hostif table entry sx\n");
            goto out;
        }

        memcpy(&g_sai_db_ptr->wildcard_channel.trap_channel, &user_channel,
               sizeof(g_sai_db_ptr->wildcard_channel.trap_channel));
        g_sai_db_ptr->wildcard_channel.is_in_use = true;
    } else {
        if (type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID) {
            if (g_sai_db_ptr->traps_db[trap_db_index].trap_channel.is_in_use) {
                SX_LOG_ERR("Only one channel registration per trap is possible\n");
                status = SAI_STATUS_NOT_SUPPORTED;
                goto out;
            }

            if (g_sai_db_ptr->wildcard_channel.is_in_use) {
                status = mlnx_register_wildcard_channel(SX_ACCESS_CMD_DEREGISTER, trap_db_index);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to deregister wildcard channel\n");
                    goto out;
                }
            }

            memcpy(&g_sai_db_ptr->traps_db[trap_db_index].trap_channel.trap_channel, &user_channel,
                   sizeof(g_sai_db_ptr->traps_db[trap_db_index].trap_channel.trap_channel));

            g_sai_db_ptr->traps_db[trap_db_index].trap_channel.is_in_use = true;
        } else {
            status = mlnx_is_hostif_table_key_registered(trap_db_index, &sx_register_key, NULL, &is_registered);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to check whether the entry is already registered\n");
                goto out;
            }

            if (is_registered) {
                SX_LOG_ERR("Failed to create host interface table entry - entry already exists\n");
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        }

        status = mlnx_register_trap(SX_ACCESS_CMD_REGISTER, trap_db_index, &sx_register_key, &user_channel);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update trap hostif table entry sx\n");
            goto out;
        }
    }

    status = mlnx_create_hostif_table_entry_oid(type->s32, trap_db_index, port_lag_vlan_oid, channel->s32, hostif,
                                                hif_table_entry);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (type->s32 != SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD) {
        g_sai_db_ptr->traps_db[trap_db_index].refcount++;
    }

    if (type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN) {
        g_sai_db_ptr->vlans_db[vlan_id].hostif_table_refcount++;
    }

    if ((type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT) ||
        (type->s32 == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG)) {
        g_sai_db_ptr->ports_db[port_db_idx].hostif_table_refcount++;
    }

    if ((channel->s32 == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD) ||
        (channel->s32 == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK)) {
        g_sai_db_ptr->hostif_db[mlnx_hif_oid.id.u32].refcount++;
    }

    MLNX_LOG_OID_CREATED(*hif_table_entry);

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove host interface table entry
 *
 * @param[in] hif_table_entry - host interface table entry
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_remove_hostif_table_entry(_In_ sai_object_id_t hif_table_entry)
{
    sai_status_t                  status;
    mlnx_object_id_t              mlnx_hif;
    sai_hostif_table_entry_type_t entry_type;
    sx_host_ifc_register_key_t    sx_register_key;
    sx_user_channel_t             user_channel;
    uint32_t                      trap_db_index;
    bool                          is_registered;

    SX_LOG_ENTER();
    MLNX_LOG_OID_REMOVE(hif_table_entry);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, hif_table_entry, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    entry_type = mlnx_hif.field.sub_type;
    trap_db_index = mlnx_hif.id.hostif_table_entry.trap_db_idx;

    sai_db_write_lock();

    if ((mlnx_hif.ext.hostif_table_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD) ||
        (mlnx_hif.ext.hostif_table_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK)) {
        if (g_sai_db_ptr->hostif_db[mlnx_hif.ext.hostif_table_entry.hostif_db_idx].refcount == 0) {
            SX_LOG_ERR("Invalid hostif index %d in table entry oid\n", mlnx_hif.ext.hostif_table_entry.hostif_db_idx);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    if (entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN) {
        if (g_sai_db_ptr->vlans_db[mlnx_hif.id.hostif_table_entry.port_vlan_db_idx].hostif_table_refcount == 0) {
            SX_LOG_ERR("Invalid vlan index %d in table entry oid\n", mlnx_hif.id.hostif_table_entry.port_vlan_db_idx);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    if ((entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT) ||
        (entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG)) {
        if (g_sai_db_ptr->ports_db[mlnx_hif.id.hostif_table_entry.port_vlan_db_idx].hostif_table_refcount == 0) {
            SX_LOG_ERR("Invalid port or lag index %u in table entry oid\n",
                       mlnx_hif.id.hostif_table_entry.port_vlan_db_idx);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    status = mlnx_hostif_table_entry_fill_sx_reg_key_by_mlnx_oid(mlnx_hif, &sx_register_key);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill trap type hostif table entry sx register key\n");
        goto out;
    }

    if (entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD) {
        if (!g_sai_db_ptr->wildcard_channel.is_in_use) {
            SX_LOG_ERR("No wildcard entry applied\n");
            status = SAI_STATUS_INVALID_OBJECT_ID;
            goto out;
        }

        status = mlnx_register_all_traps(SX_ACCESS_CMD_DEREGISTER, &sx_register_key,
                                         &g_sai_db_ptr->wildcard_channel.trap_channel);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update sx on remove wildcard type hostif table entry\n");
            goto out;
        }

        g_sai_db_ptr->wildcard_channel.is_in_use = false;
    } else {
        if (g_sai_db_ptr->traps_db[trap_db_index].refcount == 0) {
            SX_LOG_ERR("Invalid table entry\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        if (entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID) {
            if (!g_sai_db_ptr->traps_db[trap_db_index].trap_channel.is_in_use) {
                SX_LOG_ERR("No trap entry applied\n");
                status = SAI_STATUS_INVALID_OBJECT_ID;
                goto out;
            }

            status = mlnx_register_trap(SX_ACCESS_CMD_DEREGISTER, trap_db_index, &sx_register_key,
                                        &g_sai_db_ptr->traps_db[trap_db_index].trap_channel.trap_channel);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to deregister channel on remove trap type hostif table entry\n");
                goto out;
            }

            if (g_sai_db_ptr->wildcard_channel.is_in_use) {
                status = mlnx_register_wildcard_channel(SX_ACCESS_CMD_REGISTER, trap_db_index);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to register wildcard channel\n");
                    goto out;
                }
            }

            g_sai_db_ptr->traps_db[trap_db_index].trap_channel.is_in_use = false;
        } else {
            status = mlnx_hif_table_entry_fill_user_channel_by_hif_idx(mlnx_hif.ext.hostif_table_entry.channel_type,
                                                                       mlnx_hif.ext.hostif_table_entry.hostif_db_idx,
                                                                       &user_channel);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get sx user channel\n");
                goto out;
            }

            status = mlnx_is_hostif_table_key_registered(trap_db_index, &sx_register_key, &user_channel,
                                                         &is_registered);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to check whether the entry is already registered for trap idx %d\n", trap_db_index);
                goto out;
            }

            if (!is_registered) {
                SX_LOG_ERR("Failed to remove table entry - entry not present in SDK for trap %d\n", trap_db_index);
                status = SAI_STATUS_FAILURE;
                goto out;
            }

            status = mlnx_register_trap(SX_ACCESS_CMD_DEREGISTER, trap_db_index, &sx_register_key, &user_channel);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to deregister channel on remove hostif table entry\n");
                goto out;
            }
        }

        g_sai_db_ptr->traps_db[trap_db_index].refcount--;
    }

    if ((mlnx_hif.ext.hostif_table_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD) ||
        (mlnx_hif.ext.hostif_table_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK)) {
        g_sai_db_ptr->hostif_db[mlnx_hif.ext.hostif_table_entry.hostif_db_idx].refcount--;
    }

    if (entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN) {
        g_sai_db_ptr->vlans_db[mlnx_hif.id.hostif_table_entry.port_vlan_db_idx].hostif_table_refcount--;
    }

    if ((entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT) ||
        (entry_type == SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG)) {
        g_sai_db_ptr->ports_db[mlnx_hif.id.hostif_table_entry.port_vlan_db_idx].hostif_table_refcount--;
    }

out:
    sai_db_unlock();

    return status;
}

/**
 * @brief Set host interface table entry attribute
 *
 * @param[in] hif_table_entry - host interface table entry
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_set_hostif_table_entry_attribute(_In_ sai_object_id_t        hif_table_entry,
                                                   _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = hif_table_entry };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, attr);
}

/**
 * @brief Get host interface table entry attribute
 *
 * @param[in] hif_table_entry - host interface table entry
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_get_hostif_table_entry_attribute(_In_ sai_object_id_t     hif_table_entry,
                                                   _In_ uint32_t            attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = hif_table_entry };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, attr_count, attr_list);
}

/* Host interface table entry type (sai_hostif_table_entry_type_t)
 *  Host interface table entry match field object-id (sai_object_id_t)
 *  Host interface table entry match field trap-id (sai_object_id_t)
 */
static sai_status_t mlnx_table_entry_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_hif = { 0 }, vlan_obj_id = { 0 };
    uint32_t         port_lag_vlan_idx;

    SX_LOG_ENTER();

    assert((SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE == (long)arg) || (SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID == (long)arg) ||
           (SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID == (long)arg));

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();

    switch ((long)arg) {
    case SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE:
        value->s32 = mlnx_hif.field.sub_type;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID:
        port_lag_vlan_idx = mlnx_hif.id.hostif_table_entry.port_vlan_db_idx;

        switch (mlnx_hif.field.sub_type) {
        case SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT:
        case SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG:
            if (port_lag_vlan_idx >= (MAX_PORTS_DB * 2)) {
                SX_LOG_ERR("Invalid table entry oid, port or lag index %d is larger than max %d\n", port_lag_vlan_idx,
                           (MAX_PORTS_DB * 2) - 1);
                status = SAI_STATUS_INVALID_OBJECT_ID;
                goto out;
            }

            if (g_sai_db_ptr->ports_db[port_lag_vlan_idx].hostif_table_refcount == 0) {
                SX_LOG_ERR("Invalid table entry oid, port or LAG index %d is not used for table entry\n",
                           port_lag_vlan_idx);
                status = SAI_STATUS_INVALID_OBJECT_ID;
                goto out;
            }

            value->oid = g_sai_db_ptr->ports_db[port_lag_vlan_idx].saiport;
            break;

        case SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN:
            if (port_lag_vlan_idx >= SXD_VID_MAX) {
                SX_LOG_ERR("Invalid table entry oid, vlan index %u is larger than max %u\n", port_lag_vlan_idx,
                           SXD_VID_MAX - 1);
                status = SAI_STATUS_INVALID_OBJECT_ID;
                goto out;
            }

            if (g_sai_db_ptr->vlans_db[port_lag_vlan_idx].hostif_table_refcount == 0) {
                SX_LOG_ERR("Invalid table entry oid, VLAN %d is not used for table entry\n", port_lag_vlan_idx);
                status = SAI_STATUS_INVALID_OBJECT_ID;
                goto out;
            }

            vlan_obj_id.id.vlan_id = port_lag_vlan_idx;
            status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_VLAN, &vlan_obj_id, &value->oid);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to create VLAN oid for vlan idx %d\n", port_lag_vlan_idx);
                goto out;
            }
            break;

        default:
            SX_LOG_ERR("Host table entry object ID invalid for type trap/wildcard %u\n", mlnx_hif.field.sub_type);
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }
        break;

    case SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID:
        if (SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD == mlnx_hif.field.sub_type) {
            SX_LOG_ERR("Host table entry trap ID invalid for type wildcard\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        } else {
            status = mlnx_create_object((mlnx_traps_info[mlnx_hif.id.hostif_table_entry.trap_db_idx].object_type),
                                        mlnx_hif.id.hostif_table_entry.trap_db_idx, NULL, &value->oid);
        }
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_table_entry_channel_type_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_hif = { 0 };

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    value->s32 = mlnx_hif.ext.hostif_table_entry.channel_type;

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_table_entry_hostif_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_hif_table = { 0 }, mlnx_hif = { 0 };

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, key->key.object_id, &mlnx_hif_table);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();
    if ((mlnx_hif_table.ext.hostif_table_entry.channel_type != SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD) &&
        (mlnx_hif_table.ext.hostif_table_entry.channel_type != SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK)) {
        SX_LOG_ERR("Hostif get is valid only for FD and genetlink channel types\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if ((mlnx_hif_table.ext.hostif_table_entry.hostif_db_idx >= MAX_HOSTIFS)) {
        SX_LOG_ERR("Invalid hostif object id - hostif db index %d\n",
                   mlnx_hif_table.ext.hostif_table_entry.hostif_db_idx);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (g_sai_db_ptr->hostif_db[mlnx_hif_table.ext.hostif_table_entry.hostif_db_idx].refcount == 0) {
        SX_LOG_ERR("Hostif idx %d is not used for table entry\n", mlnx_hif_table.ext.hostif_table_entry.hostif_db_idx);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    mlnx_hif.id.u32 = mlnx_hif_table.ext.hostif_table_entry.hostif_db_idx;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_HOSTIF, &mlnx_hif, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create hostif object id\n");
        goto out;
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_host_interface_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_host_ifc_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_hostif_api_t mlnx_host_interface_api = {
    mlnx_create_host_interface,
    mlnx_remove_host_interface,
    mlnx_set_host_interface_attribute,
    mlnx_get_host_interface_attribute,
    mlnx_create_hostif_table_entry,
    mlnx_remove_hostif_table_entry,
    mlnx_set_hostif_table_entry_attribute,
    mlnx_get_hostif_table_entry_attribute,
    mlnx_create_hostif_trap_group,
    mlnx_remove_hostif_trap_group,
    mlnx_set_hostif_trap_group_attribute,
    mlnx_get_hostif_trap_group_attribute,
    mlnx_create_hostif_trap,
    mlnx_remove_hostif_trap,
    mlnx_set_hostif_trap_attribute,
    mlnx_get_hostif_trap_attribute,
    mlnx_create_hostif_user_defined_trap,
    mlnx_remove_hostif_user_defined_trap,
    mlnx_set_hostif_user_defined_trap_attribute,
    mlnx_get_hostif_user_defined_trap_attribute,
    mlnx_recv_hostif_packet,
    mlnx_send_hostif_packet,
    NULL,
    NULL,
};
