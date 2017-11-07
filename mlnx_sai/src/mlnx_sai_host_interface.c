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
#ifndef _WIN32
#include <net/if.h>
#endif

#undef  __MODULE__
#define __MODULE__ SAI_HOST_INTERFACE

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
static sai_status_t mlnx_host_interface_name_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_host_interface_oper_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_host_interface_vlan_tag_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
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
static sai_status_t mlnx_user_defined_trap_group_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_trap_type_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg);
static sai_status_t mlnx_user_defined_trap_type_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_trap_action_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_user_defined_trap_group_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_trap_action_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
sai_status_t mlnx_trap_filter_set(uint32_t index, sai_object_list_t ports);
static sai_status_t mlnx_table_entry_get(_In_ const sai_object_key_t   *key,
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
      { true, false, true, true },
      { true, false, true, true },
      mlnx_host_interface_name_get, NULL,
      mlnx_host_interface_name_set, NULL },
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
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const sai_vendor_attribute_entry_t user_defined_trap_vendor_attribs[] = {
    { SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_user_defined_trap_type_get, NULL,
      NULL, NULL },
    { SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TRAP_PRIORITY,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TRAP_GROUP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_user_defined_trap_group_get, NULL,
      mlnx_user_defined_trap_group_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const sai_vendor_attribute_entry_t host_interface_packet_vendor_attribs[] = {
    { SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG,
      { false, false, false, false },
      { false, false, false, false },
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
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
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
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_trap_info_t                    mlnx_traps_info[] = {
    { SAI_HOSTIF_TRAP_TYPE_STP, 1, { SX_TRAP_ID_ETH_L2_STP }, SAI_PACKET_ACTION_DROP, "STP", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_LACP, 1, { SX_TRAP_ID_ETH_L2_LACP }, SAI_PACKET_ACTION_DROP, "LACP",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_EAPOL, 1, { SX_TRAP_ID_ETH_L2_EAPOL }, SAI_PACKET_ACTION_DROP, "EAPOL",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_LLDP, 1, { SX_TRAP_ID_ETH_L2_LLDP }, SAI_PACKET_ACTION_DROP, "LLDP",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_PVRST, 1, { SX_TRAP_ID_ETH_L2_RPVST }, SAI_PACKET_ACTION_DROP, "PVRST",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_QUERY, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_QUERY }, SAI_PACKET_ACTION_FORWARD,
      "IGMP query", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_LEAVE, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V2_LEAVE }, SAI_PACKET_ACTION_FORWARD,
      "IGMP leave", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V1_REPORT, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V1_REPORT },
      SAI_PACKET_ACTION_FORWARD,
      "IGMP V1 report", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V2_REPORT, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V2_REPORT },
      SAI_PACKET_ACTION_FORWARD,
      "IGMP V2 report", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V3_REPORT, 1, { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V3_REPORT },
      SAI_PACKET_ACTION_FORWARD,
      "IGMP V3 report", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET, 1, { SX_TRAP_ID_ETH_L2_PACKET_SAMPLING }, SAI_PACKET_ACTION_TRAP,
      "Sample packet", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_UDLD, 1, { SX_TRAP_ID_ETH_L2_UDLD }, SAI_PACKET_ACTION_DROP, "UDLD",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, 1, { SX_TRAP_ID_ARP_REQUEST }, SAI_PACKET_ACTION_FORWARD, "ARP request",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE, 1, { SX_TRAP_ID_ARP_RESPONSE }, SAI_PACKET_ACTION_FORWARD, "ARP response",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_DHCP, 1, { SX_TRAP_ID_ETH_L2_DHCP }, SAI_PACKET_ACTION_FORWARD, "DHCP",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_OSPF, 1, { SX_TRAP_ID_OSPF }, SAI_PACKET_ACTION_FORWARD, "OSPF", MLNX_TRAP_TYPE_REGULAR },
    /* TODO : Allow forward on PIM */
    { SAI_HOSTIF_TRAP_TYPE_PIM, 1, { SX_TRAP_ID_PIM }, SAI_PACKET_ACTION_DROP, "PIM", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_VRRP, 1, { SX_TRAP_ID_VRRP }, SAI_PACKET_ACTION_FORWARD, "VRRP", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_BGP, 1, { SX_TRAP_ID_IPV4_BGP }, SAI_PACKET_ACTION_FORWARD, "BGP", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_DHCPV6, 1, { SX_TRAP_ID_IPV6_DHCP }, SAI_PACKET_ACTION_FORWARD, "DHCPv6",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_OSPFV6, 1, { SX_TRAP_ID_IPV6_OSPF }, SAI_PACKET_ACTION_FORWARD, "OSPFv6",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_VRRPV6, 0, { 0 }, SAI_PACKET_ACTION_FORWARD, "VRRPv6", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_BGPV6, 1, { SX_TRAP_ID_IPV6_BGP }, SAI_PACKET_ACTION_FORWARD, "BGPv6",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, 5,
      { SX_TRAP_ID_IPV6_ROUTER_SOLICIATION, SX_TRAP_ID_IPV6_ROUTER_ADVERTISEMENT, SX_TRAP_ID_IPV6_NEIGHBOR_SOLICIATION,
        SX_TRAP_ID_IPV6_NEIGHBOR_ADVERTISEMENT, SX_TRAP_ID_IPV6_NEIGHBOR_DIRECTION },
      SAI_PACKET_ACTION_FORWARD, "IPv6 neighbor discovery", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_V2, 1, { SX_TRAP_ID_IPV6_MLD_V1_V2 }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD V1 V2",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_REPORT, 1, { SX_TRAP_ID_IPV6_MLD_V1_REPORT }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD V1 report", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_DONE, 1, { SX_TRAP_ID_IPV6_MLD_V1_DONE }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD done", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_MLD_V2_REPORT, 1, { SX_TRAP_ID_IPV6_MLD_V2_REPORT }, SAI_PACKET_ACTION_FORWARD,
      "IPv6 MLD V2 report", MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_IP2ME, 1, { SX_TRAP_ID_IP2ME }, SAI_PACKET_ACTION_TRAP, "IP2ME",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_SSH, 2, { SX_TRAP_ID_SSH_IPV4, SX_TRAP_ID_SSH_IPV6 }, SAI_PACKET_ACTION_TRAP, "SSH",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_SNMP, 2, { SX_TRAP_ID_SNMP_IPV4, SX_TRAP_ID_SNMP_IPV6 }, SAI_PACKET_ACTION_TRAP, "SNMP",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR, 1, { SX_TRAP_ID_ETH_L3_MTUERROR }, SAI_PACKET_ACTION_TRAP, "MTU error",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_TRAP_TYPE_TTL_ERROR, 1, { SX_TRAP_ID_ETH_L3_TTLERROR }, SAI_PACKET_ACTION_TRAP, "TTL error",
      MLNX_TRAP_TYPE_REGULAR },
    { SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ACL, 1, { SX_TRAP_ID_ACL_MIN }, SAI_PACKET_ACTION_TRAP, "ACL",
      MLNX_TRAP_TYPE_USER_DEFINED },
    { SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_ROUTER, 4,
      { SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_BEST_EFFORT, SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_LOW,
        SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_MED, SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_HIGH },
      SAI_PACKET_ACTION_TRAP, "Router", MLNX_TRAP_TYPE_USER_DEFINED },
    { SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_NEIGH, 6,
      { SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_BEST_EFFORT, SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_LOW,
        SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_MED, SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_HIGH,
        SX_TRAP_ID_HOST_MISS_IPV4, SX_TRAP_ID_HOST_MISS_IPV6 },
      SAI_PACKET_ACTION_TRAP, "Neigh", MLNX_TRAP_TYPE_USER_DEFINED },
    { SAI_HOSTIF_USER_DEFINED_TRAP_TYPE_FDB, 1, {SX_TRAP_ID_FDB_EVENT}, SAI_PACKET_ACTION_TRAP, "FDB EVENT",
      MLNX_TRAP_TYPE_USER_DEFINED },
    { END_TRAP_INFO_ID, 1, { END_TRAP_INFO_ID }, 0, "", 0 }
};
static sai_status_t find_sai_trap_index(_In_ uint32_t         trap_id,
                                        _In_ mlnx_trap_type_t trap_type,
                                        _Out_ uint32_t       *index)
{
    uint32_t curr_index;

    SX_LOG_ENTER();

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (curr_index = 0; END_TRAP_INFO_ID != mlnx_traps_info[curr_index].trap_id; curr_index++) {
        if ((trap_id == mlnx_traps_info[curr_index].trap_id) && (trap_type == mlnx_traps_info[curr_index].trap_type)) {
            *index = curr_index;
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

sai_status_t mlnx_translate_sdk_trap_to_sai(_In_ sx_trap_id_t             sdk_trap_id,
                                            _Out_ sai_hostif_trap_type_t *trap_id,
                                            _Out_ const char            **trap_name,
                                            _Out_ mlnx_trap_type_t       *trap_type)
{
    uint32_t curr_index, curr_trap;

    SX_LOG_ENTER();

    if (NULL == trap_id) {
        SX_LOG_ERR("NULL value trap id\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (NULL == trap_name) {
        SX_LOG_ERR("NULL value trap name\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (NULL == trap_type) {
        SX_LOG_ERR("NULL value trap type\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (curr_index = 0; END_TRAP_INFO_ID != mlnx_traps_info[curr_index].trap_id; curr_index++) {
        for (curr_trap = 0; curr_trap < mlnx_traps_info[curr_index].sdk_traps_num; curr_trap++) {
            if (sdk_trap_id == mlnx_traps_info[curr_index].sdk_trap_ids[curr_trap]) {
                *trap_id   = mlnx_traps_info[curr_index].trap_id;
                *trap_name = mlnx_traps_info[curr_index].trap_name;
                *trap_type = mlnx_traps_info[curr_index].trap_type;
                SX_LOG_EXIT();
                return SAI_STATUS_SUCCESS;
            }
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

static void host_interface_key_to_str(_In_ sai_object_id_t hif_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_hif = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hif_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid host interface");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "host interface %u", mlnx_hif.id.u32);
    }
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
    const sai_attribute_value_t *type, *rif_port, *name;
    uint32_t                     type_index, rif_port_index, name_index, rif_port_data, hif_data;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         command[100];
    sx_router_interface_param_t  intf_params;
    sx_interface_attributes_t    intf_attribs;
    sx_router_id_t               vrid;
    int                          system_err;
    sx_router_interface_t        rif_id;
    sx_port_log_id_t             port_id;
    uint32_t                     ii;
    mlnx_object_id_t             mlnx_hif = {0};

    SX_LOG_ENTER();

    if (NULL == hif_id) {
        SX_LOG_ERR("NULL host interface ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF, host_interface_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create host interface, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_HOSTIF_TYPE_NETDEV == type->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_OBJ_ID, &rif_port,
                                     &rif_port_index))) {
            SX_LOG_ERR("Missing mandatory attribute rif port id on create of host if netdev type\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_NAME, &name, &name_index))) {
            SX_LOG_ERR("Missing mandatory attribute name on create of host if netdev type\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (SAI_OBJECT_TYPE_ROUTER_INTERFACE == sai_object_type_query(rif_port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(rif_port->oid, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &rif_port_data, NULL))) {
                return status;
            }

            rif_id              = (sx_router_interface_t)rif_port_data;
            mlnx_hif.ext.rif.id = rif_id;

            if (SX_STATUS_SUCCESS !=
                (status = sx_api_router_interface_get(gh_sdk, rif_id, &vrid, &intf_params, &intf_attribs))) {
                SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
                return sdk_to_sai(status);
            }

            if (SX_L2_INTERFACE_TYPE_VLAN == intf_params.type) {
                snprintf(command, sizeof(command), "ip link add link swid%u_eth name %s type vlan id %u",
                         intf_params.ifc.vlan.swid, name->chardata, intf_params.ifc.vlan.vlan);

                mlnx_hif.field.sub_type = SAI_HOSTIF_OBJECT_TYPE_VLAN;
            } else if (SX_L2_INTERFACE_TYPE_PORT_VLAN == intf_params.type) {
                snprintf(command, sizeof(command), "ip link add %s type sx_netdev swid %u port 0x%x type l3",
                         name->chardata, intf_params.ifc.vlan.swid, intf_params.ifc.port_vlan.port);

                mlnx_hif.field.sub_type = SAI_HOSTIF_OBJECT_TYPE_ROUTER_PORT;
            } else {
                SX_LOG_ERR("RIF type %s not implemented\n", SX_ROUTER_RIF_TYPE_STR(intf_params.type));
                return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + rif_port_index;
            }
        } else if (SAI_OBJECT_TYPE_PORT == sai_object_type_query(rif_port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(rif_port->oid, SAI_OBJECT_TYPE_PORT, &rif_port_data, NULL))) {
                return status;
            }

            port_id = (sx_port_log_id_t)rif_port_data;

            snprintf(command, sizeof(command), "ip link add %s type sx_netdev swid %u port 0x%x type l2",
                     name->chardata, DEFAULT_ETH_SWID, port_id);

            mlnx_hif.field.sub_type  = SAI_HOSTIF_OBJECT_TYPE_L2_PORT;
            mlnx_hif.ext.port.dev_id = SX_PORT_DEV_ID_GET(port_id);
            mlnx_hif.ext.port.phy_id = SX_PORT_PHY_ID_GET(port_id);
        } else if (SAI_OBJECT_TYPE_LAG == sai_object_type_query(rif_port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(rif_port->oid, SAI_OBJECT_TYPE_LAG, &rif_port_data, NULL))) {
                return status;
            }

            port_id = (sx_port_log_id_t)rif_port_data;

            snprintf(command, sizeof(command), "ip link add %s type sx_netdev swid %u port 0x%x type l2",
                     name->chardata, DEFAULT_ETH_SWID, port_id);

            mlnx_hif.field.sub_type = SAI_HOSTIF_OBJECT_TYPE_LAG;
            mlnx_hif.ext.lag.lag_id = SX_PORT_LAG_ID_GET(port_id);
            mlnx_hif.ext.lag.sub_id = SX_PORT_SUB_ID_GET(port_id);
        } else {
            SX_LOG_ERR("Invalid rif port object type %s", SAI_TYPE_STR(sai_object_type_query(rif_port->oid)));
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + rif_port_index;
        }

        system_err = system(command);
        if (0 != system_err) {
            SX_LOG_ERR("Command \"%s\" failed\n", command);
            return SAI_STATUS_FAILURE;
        }

        /* TODO : temporary WA for SwitchX. L2 and Router port are created with port MAC. But since we want to use them for
         * routing, we set them with the router MAC to avoid mismatch of the MAC value.
         */
        cl_plock_acquire(&g_sai_db_ptr->p_lock);
        snprintf(command,
                 sizeof(command),
                 "ip link set dev %s address %s > /dev/null 2>&1",
                 name->chardata,
                 g_sai_db_ptr->dev_mac);
        cl_plock_release(&g_sai_db_ptr->p_lock);

        system_err = system(command);
        if (0 != system_err) {
            SX_LOG_ERR("Failed running \"%s\".\n", command);
            return SAI_STATUS_FAILURE;
        }

        hif_data = if_nametoindex(name->chardata);
        if (hif_data == 0) {
            SX_LOG_ERR("Cannot find device \"%s\"\n", name->chardata);
            return SAI_STATUS_FAILURE;
        }
    } else if (SAI_HOSTIF_TYPE_FD == type->s32) {
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_OBJ_ID, &rif_port,
                                     &rif_port_index))) {
            SX_LOG_ERR("Invalid attribute rif port id for fd channel host if on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + rif_port_index;
        }

        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_ATTR_NAME, &name, &name_index))) {
            SX_LOG_ERR("Invalid attribute name for fd channel host if on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + name_index;
        }

        cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

        for (ii = 0; ii < MAX_FDS; ii++) {
            if (false == g_sai_db_ptr->fd_db[ii].valid) {
                break;
            }
        }

        if (MAX_FDS == ii) {
            SX_LOG_ERR("FDs table full\n");
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return SAI_STATUS_TABLE_FULL;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_open(gh_sdk, &g_sai_db_ptr->fd_db[ii]))) {
            SX_LOG_ERR("host ifc open fd failed - %s.\n", SX_STATUS_MSG(status));
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }

        msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
        cl_plock_release(&g_sai_db_ptr->p_lock);
        hif_data                = ii;
        mlnx_hif.field.sub_type = SAI_HOSTIF_OBJECT_TYPE_FD;
    } else {
        SX_LOG_ERR("Invalid host interface type %d\n", type->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    mlnx_hif.id.u32 = hif_data;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_HOSTIF, &mlnx_hif, hif_id);
    if (SAI_ERR(status)) {
        return status;
    }

    host_interface_key_to_str(*hif_id, key_str);
    SX_LOG_NTC("Created host interface %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    char             key_str[MAX_KEY_STR_LEN];
    char             ifname[IF_NAMESIZE];
    int              system_err;
    char             command[100];
    mlnx_object_id_t mlnx_hif;
    sai_status_t     status;

    SX_LOG_ENTER();

    host_interface_key_to_str(hif_id, key_str);
    SX_LOG_NTC("Remove host interface %s\n", key_str);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hif_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_HOSTIF_OBJECT_TYPE_FD == mlnx_hif.field.sub_type) {
        if (mlnx_hif.id.u32 >= MAX_FDS) {
            SX_LOG_ERR("Invalid FD ID %u\n", mlnx_hif.id.u32);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

        if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_close(gh_sdk, &g_sai_db_ptr->fd_db[mlnx_hif.id.u32]))) {
            SX_LOG_ERR("host ifc close fd failed - %s.\n", SX_STATUS_MSG(status));
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }

        msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
        cl_plock_release(&g_sai_db_ptr->p_lock);
    } else {
        if (NULL == if_indextoname(mlnx_hif.id.u32, ifname)) {
            SX_LOG_ERR("Cannot find ifindex %u\n", mlnx_hif.id.u32);
            return SAI_STATUS_FAILURE;
        }

        snprintf(command, sizeof(command), "ip link delete %s", ifname);
        system_err = system(command);
        if (0 != system_err) {
            SX_LOG_ERR("Command \"%s\" failed\n", command);
            return SAI_STATUS_FAILURE;
        }
    }

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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    host_interface_key_to_str(hif_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_HOSTIF, host_interface_vendor_attribs, attr);
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    host_interface_key_to_str(hif_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_HOSTIF,
                              host_interface_vendor_attribs,
                              attr_count,
                              attr_list);
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

    if (SAI_HOSTIF_OBJECT_TYPE_FD == mlnx_hif.field.sub_type) {
        value->s32 = SAI_HOSTIF_TYPE_FD;
    } else {
        value->s32 = SAI_HOSTIF_TYPE_NETDEV;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Assosiated port or router interface [sai_object_id_t] */
static sai_status_t mlnx_host_interface_rif_port_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    mlnx_object_id_t  mlnx_port = {0};
    mlnx_object_id_t  mlnx_hif  = {0};
    sai_object_type_t object_type;
    sai_status_t      status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_HOSTIF_OBJECT_TYPE_FD == mlnx_hif.field.sub_type) {
        SX_LOG_ERR("Rif_port can not be retreived for host interface channel type FD\n");
        return SAI_STATUS_INVALID_PARAMETER;
    } else if (SAI_HOSTIF_OBJECT_TYPE_L2_PORT == mlnx_hif.field.sub_type) {
        SX_PORT_DEV_ID_SET(mlnx_port.id.log_port_id, mlnx_hif.ext.port.dev_id);
        SX_PORT_PHY_ID_SET(mlnx_port.id.log_port_id, mlnx_hif.ext.port.phy_id);
        object_type = SAI_OBJECT_TYPE_PORT;
    } else if (SAI_HOSTIF_OBJECT_TYPE_LAG == mlnx_hif.field.sub_type) {
        SX_PORT_TYPE_ID_SET(mlnx_port.id.log_port_id, SX_PORT_TYPE_LAG);
        SX_PORT_LAG_ID_SET(mlnx_port.id.log_port_id, mlnx_hif.ext.lag.lag_id);
        SX_PORT_SUB_ID_SET(mlnx_port.id.log_port_id, mlnx_hif.ext.lag.sub_id);
        object_type = SAI_OBJECT_TYPE_LAG;
    } else {
        mlnx_port.id.log_port_id = mlnx_hif.ext.rif.id;
        object_type              = SAI_OBJECT_TYPE_ROUTER_INTERFACE;
    }

    status = mlnx_object_id_to_sai(object_type, &mlnx_port, &value->oid);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Name [char[HOST_INTERFACE_NAME_SIZE]] (MANDATORY_ON_CREATE)
 * The maximum number of charactars for the name is HOST_INTERFACE_NAME_SIZE - 1 since
 * it needs the terminating null byte ('\0') at the end.  */
static sai_status_t mlnx_host_interface_name_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    char             ifname[IF_NAMESIZE];
    mlnx_object_id_t mlnx_hif = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_HOSTIF_OBJECT_TYPE_FD == mlnx_hif.field.sub_type) {
        SX_LOG_ERR("Name can not be retreived for host interface channel type FD\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == if_indextoname(mlnx_hif.id.u32, ifname)) {
        SX_LOG_ERR("Cannot find ifindex %u\n", mlnx_hif.id.u32);
        return SAI_STATUS_FAILURE;
    }

    strncpy(value->chardata, ifname, HOSTIF_NAME_SIZE);

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

/* Name [char[HOST_INTERFACE_NAME_SIZE]]
 * The maximum number of charactars for the name is HOST_INTERFACE_NAME_SIZE - 1 since
 * it needs the terminating null byte ('\0') at the end.  */
static sai_status_t mlnx_host_interface_name_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    char             ifname[IF_NAMESIZE];
    mlnx_object_id_t mlnx_hif = {0};
    char             command[100];
    int              system_err;
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_HOSTIF_OBJECT_TYPE_FD == mlnx_hif.field.sub_type) {
        SX_LOG_ERR("Name can not be set for host interface channel type FD\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == if_indextoname(mlnx_hif.id.u32, ifname)) {
        SX_LOG_ERR("Cannot find ifindex %u\n", mlnx_hif.id.u32);
        return SAI_STATUS_FAILURE;
    }

    snprintf(command, sizeof(command), "ip link set dev %s name %s", ifname, value->chardata);
    system_err = system(command);
    if (0 != system_err) {
        SX_LOG_ERR("Command \"%s\" failed.\n", command);
        return SAI_STATUS_FAILURE;
    }

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

    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_group_set(gh_sdk, DEFAULT_ETH_SWID,
                                                                       group_id, &trap_group_attributes))) {
        SX_LOG_ERR("Failed to sx_api_host_ifc_trap_group_set %s\n", SX_STATUS_MSG(status));
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

        SX_LOG_ERR("Failed to obtain sx_policer for trap group:%d. err:%s. line:%d\n", group_id,
                   SX_STATUS_MSG(sx_status), __LINE__);
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

        SX_LOG_ERR("Failed to obtain sx_policer for trap group:%d. err:%s. line:%d\n", group_id,
                   SX_STATUS_MSG(sx_status), __LINE__);
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
        SX_LOG_ERR("Policer unbind failed - %s. line:%d\n", SX_STATUS_MSG(sx_status), __LINE__);
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }

    SX_LOG_NTC("Sai trap goup :0x%" PRIx64 ". sx_policer_id:0x%" PRIx64 ". group prio:%u\n",
               sai_trap_group_id,
               sx_policer,
               group_id);


    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static void trap_group_key_to_str(_In_ sai_object_id_t group_id, _Out_ char *key_str)
{
    uint32_t group_data;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(group_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_data, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid trap group");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "Trap group %u", group_data);
    }
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
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    sx_trap_group_attributes_t   trap_group_attributes;
    uint32_t                     policer_attr_index = 0;
    const sai_attribute_value_t *policer_id_attr    = NULL;
    uint32_t                     group_id;

    SX_LOG_ENTER();

    memset(&trap_group_attributes, 0, sizeof(trap_group_attributes));

    if (NULL == hostif_trap_group_id) {
        SX_LOG_ERR("NULL host interface trap group ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP,
                                    trap_group_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create trap group, %s\n", list_str);

    trap_group_attributes.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
    trap_group_attributes.truncate_size = 0;
    trap_group_attributes.prio          = 0;

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE, &prio, &prio_index)) {
        trap_group_attributes.prio = (prio->u32 > SX_TRAP_PRIORITY_HIGH) ? SX_TRAP_PRIORITY_HIGH : prio->u32;
    }

    sai_db_write_lock();

    for (group_id = 0; group_id < MAX_TRAP_GROUPS; group_id++) {
        if (!g_sai_db_ptr->trap_group_valid[group_id]) {
            g_sai_db_ptr->trap_group_valid[group_id] = true;
            break;
        }
    }

    if (MAX_TRAP_GROUPS == group_id) {
        SX_LOG_ERR("All trap groups are already used\n");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_group_set(gh_sdk, DEFAULT_ETH_SWID,
                                                                       group_id, &trap_group_attributes))) {
        SX_LOG_ERR("Failed to sx_api_host_ifc_trap_group_set %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, group_id, NULL, hostif_trap_group_id))) {
        goto out;
    }

    trap_group_key_to_str(*hostif_trap_group_id, key_str);

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


    SX_LOG_NTC("Created trap group %s\n", key_str);

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
    char         key_str[MAX_KEY_STR_LEN];
    uint32_t     group_id;
    sai_status_t status;

    SX_LOG_ENTER();
    trap_group_key_to_str(hostif_trap_group_id, key_str);
    SX_LOG_NTC("Remove trap group %s\n", key_str);
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

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (false == g_sai_db_ptr->trap_group_valid[group_id]) {
        SX_LOG_ERR("Invalid group id %u\n", group_id);
        status = SAI_STATUS_INVALID_PARAMETER;
    } else {
        if (SAI_STATUS_SUCCESS != (status = mlnx_sai_unbind_policer_from_trap_group(hostif_trap_group_id))) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            SX_LOG_EXIT();
            return status;
        }
        g_sai_db_ptr->trap_group_valid[group_id] = false;
    }
    cl_plock_release(&g_sai_db_ptr->p_lock);
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    trap_group_key_to_str(hostif_trap_group_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, trap_group_vendor_attribs, attr);
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    trap_group_key_to_str(hostif_trap_group_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP,
                              trap_group_vendor_attribs,
                              attr_count,
                              attr_list);
}

static void trap_key_to_str(_In_ sai_object_id_t hostif_trapid, _Out_ char *key_str)
{
    uint32_t trap_data, index;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hostif_trapid, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_data, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid trap");
    } else {
        if (SAI_STATUS_SUCCESS == find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_REGULAR, &index)) {
            snprintf(key_str, MAX_KEY_STR_LEN, "trap %x %s", trap_data, mlnx_traps_info[index].trap_name);
        } else {
            snprintf(key_str, MAX_KEY_STR_LEN, "Invalid trap %x", trap_data);
        }
    }
}

static void user_defined_trap_key_to_str(_In_ sai_object_id_t hostif_user_defined_trapid, _Out_ char          *key_str)
{
    uint32_t trap_data, index;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hostif_user_defined_trapid, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                                                  &trap_data, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid user defined trap");
    } else {
        if (SAI_STATUS_SUCCESS == find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_USER_DEFINED, &index)) {
            snprintf(key_str, MAX_KEY_STR_LEN, "user defined trap %x %s", trap_data, mlnx_traps_info[index].trap_name);
        } else {
            snprintf(key_str, MAX_KEY_STR_LEN, "Invalid user defined trap %x", trap_data);
        }
    }
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
    const sai_attribute_value_t *trap_id, *action, *exclude, *group = NULL;
    uint32_t                     trap_id_index, action_index, exclude_index, group_index;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    uint32_t                     index, prio;
    sx_trap_action_t             sx_action;

    SX_LOG_ENTER();

    if (NULL == hostif_trap_id) {
        SX_LOG_ERR("NULL host interface trap ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP, trap_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    /* In Mellanox platform, trap group queue defines the trap priority */

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TRAP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create trap, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, &trap_id, &trap_id_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_id->s32, MLNX_TRAP_TYPE_REGULAR, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_id->s32);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, &action, &action_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_trap_action_to_sdk(action->s32, &sx_action, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP, &group, &group_index)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(group->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
            return status;
        }
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(index, action->s32, (group) ? group->oid :
                                                      g_sai_db_ptr->default_trap_group))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return status;
    }

    g_sai_db_ptr->traps_db[index].action     = action->s32;
    g_sai_db_ptr->traps_db[index].trap_group = (group) ? group->oid : g_sai_db_ptr->default_trap_group;

    cl_plock_release(&g_sai_db_ptr->p_lock);

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TRAP_ATTR_EXCLUDE_PORT_LIST, &exclude, &exclude_index)) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_trap_filter_set(index, exclude->objlist))) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HOSTIF_TRAP, trap_id->s32, NULL, hostif_trap_id))) {
        SX_LOG_EXIT();
        return status;
    }

    trap_key_to_str(*hostif_trap_id, key_str);

    SX_LOG_NTC("Created trap %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    char              key_str[MAX_KEY_STR_LEN];
    uint32_t          trap_id, index;
    sai_status_t      status;
    sai_object_list_t exclude;

    SX_LOG_ENTER();
    trap_key_to_str(hostif_trap_id, key_str);
    SX_LOG_NTC("Remove trap %s\n", key_str);
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(hostif_trap_id, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_id, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_id, MLNX_TRAP_TYPE_REGULAR, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    g_sai_db_ptr->traps_db[index].action     = mlnx_traps_info[index].action;
    g_sai_db_ptr->traps_db[index].trap_group = g_sai_db_ptr->default_trap_group;

    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(index, mlnx_traps_info[index].action,
                                                      g_sai_db_ptr->default_trap_group))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return status;
    }

    exclude.count = 0;
    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_filter_set(index, exclude))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return status;
    }

    cl_plock_release(&g_sai_db_ptr->p_lock);

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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    trap_key_to_str(hostif_trap_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_HOSTIF_TRAP, trap_vendor_attribs, attr);
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    trap_key_to_str(hostif_trap_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_HOSTIF_TRAP,
                              trap_vendor_attribs,
                              attr_count,
                              attr_list);
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
    const sai_attribute_value_t *trap_id, *group = NULL;
    uint32_t                     trap_id_index, group_index;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    uint32_t                     index, prio;

    SX_LOG_ENTER();

    if (NULL == hostif_user_defined_trap_id) {
        SX_LOG_ERR("NULL host interface user defined trap ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                                    user_defined_trap_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count,
                         attr_list,
                         SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                         MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create user defined trap, %s\n", list_str);

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TYPE,
                                 &trap_id,
                                 &trap_id_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_id->s32, MLNX_TRAP_TYPE_USER_DEFINED, &index))) {
        SX_LOG_ERR("Invalid user defined trap %x\n", trap_id->s32);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_USER_DEFINED_TRAP_ATTR_TRAP_GROUP, &group,
                            &group_index)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(group->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
            return status;
        }
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    if (0 < mlnx_traps_info[index].sdk_traps_num) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_trap_set(index, g_sai_db_ptr->traps_db[index].action, (group) ? group->oid :
                                    g_sai_db_ptr->default_trap_group))) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }
    }

    g_sai_db_ptr->traps_db[index].trap_group = (group) ? group->oid : g_sai_db_ptr->default_trap_group;

    cl_plock_release(&g_sai_db_ptr->p_lock);

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_create_object(SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, trap_id->s32, NULL,
                                hostif_user_defined_trap_id))) {
        SX_LOG_EXIT();
        return status;
    }

    user_defined_trap_key_to_str(*hostif_user_defined_trap_id, key_str);

    SX_LOG_NTC("Created user defined trap %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    char         key_str[MAX_KEY_STR_LEN];
    uint32_t     trap_id, index;
    sai_status_t status;

    SX_LOG_ENTER();
    user_defined_trap_key_to_str(hostif_user_defined_trap_id, key_str);
    SX_LOG_NTC("Remove user defined trap %s\n", key_str);
    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(hostif_user_defined_trap_id, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, &trap_id,
                                 NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_id, MLNX_TRAP_TYPE_USER_DEFINED, &index))) {
        SX_LOG_ERR("Invalid user defined trap %x\n", trap_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    g_sai_db_ptr->traps_db[index].action     = mlnx_traps_info[index].action;
    g_sai_db_ptr->traps_db[index].trap_group = g_sai_db_ptr->default_trap_group;

    if (0 < mlnx_traps_info[index].sdk_traps_num) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(index, mlnx_traps_info[index].action,
                                                          g_sai_db_ptr->default_trap_group))) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            return status;
        }
    }

    cl_plock_release(&g_sai_db_ptr->p_lock);

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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    user_defined_trap_key_to_str(hostif_user_defined_trap_id, key_str);
    return sai_set_attribute(&key,
                             key_str,
                             SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                             user_defined_trap_vendor_attribs,
                             attr);
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    user_defined_trap_key_to_str(hostif_user_defined_trap_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                              user_defined_trap_vendor_attribs,
                              attr_count,
                              attr_list);
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_trap_record_get(_In_ uint32_t         trap_id,
                                         _In_ mlnx_trap_type_t trap_type,
                                         _Out_ mlnx_trap_t    *trap_record)
{
    sai_status_t status;
    uint32_t     index;

    if (NULL == trap_record) {
        SX_LOG_ERR("NULL value trap record\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_id, trap_type, &index))) {
        SX_LOG_ERR("Invalid %strap %x\n", (trap_type == MLNX_TRAP_TYPE_REGULAR) ? "" : "user defined ", trap_id);
        return status;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    memcpy(trap_record, &g_sai_db_ptr->traps_db[index], sizeof(*trap_record));
    cl_plock_release(&g_sai_db_ptr->p_lock);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_trap_set(uint32_t index, sai_packet_action_t sai_action, sai_object_id_t trap_group)
{
    sx_trap_action_t action;
    sai_status_t     status;
    uint32_t         prio, trap_index;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_trap_action_to_sdk(sai_action, &action, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(trap_group,
                                                            SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
        return status;
    }

    if (0 == mlnx_traps_info[index].sdk_traps_num) {
        SX_LOG_ERR("trap %s %x not supported\n", mlnx_traps_info[index].trap_name, mlnx_traps_info[index].trap_id);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    for (trap_index = 0; trap_index < mlnx_traps_info[index].sdk_traps_num; trap_index++) {
        if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_set(gh_sdk, DEFAULT_ETH_SWID,
                                                                        mlnx_traps_info[index].sdk_trap_ids[trap_index],
                                                                        prio, action))) {
            SX_LOG_ERR("Failed to set for index %u trap %u/%u=%u, error is %s\n",
                       index, trap_index + 1, mlnx_traps_info[index].sdk_traps_num,
                       mlnx_traps_info[index].sdk_trap_ids[trap_index], SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_register_trap(const sx_access_cmd_t                 cmd,
                                uint32_t                              index,
                                sai_hostif_table_entry_channel_type_t channel,
                                sx_fd_t                               fd,
                                sx_host_ifc_register_key_t           *reg)
{
    sai_status_t      status;
    sx_user_channel_t user_channel;
    uint32_t          trap_index;

    memset(&user_channel, 0, sizeof(user_channel));

    if (0 == mlnx_traps_info[index].sdk_traps_num) {
        SX_LOG_ERR("trap %s %x not supported\n", mlnx_traps_info[index].trap_name, mlnx_traps_info[index].trap_id);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    switch (channel) {
    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD:
    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_CB:
        user_channel.type = SX_USER_CHANNEL_TYPE_FD;
        memcpy(&user_channel.channel.fd, &fd, sizeof(user_channel.channel.fd));
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_L3:
        user_channel.type = SX_USER_CHANNEL_TYPE_L3_NETDEV;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT:
        user_channel.type = SX_USER_CHANNEL_TYPE_PHY_PORT_NETDEV;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_LOGICAL_PORT:
        user_channel.type = SX_USER_CHANNEL_TYPE_LOG_PORT_NETDEV;
        break;

    default:
        SX_LOG_ERR("Invalid channel type %u\n", channel);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    for (trap_index = 0; trap_index < mlnx_traps_info[index].sdk_traps_num; trap_index++) {
        if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_register_set(gh_sdk, cmd,
                                                                                 DEFAULT_ETH_SWID,
                                                                                 mlnx_traps_info[index].sdk_trap_ids[
                                                                                     trap_index], &user_channel))) {
            SX_LOG_ERR("Failed to %s for index %u trap %u/%u=%u, error is %s\n",
                       (SX_ACCESS_CMD_DEREGISTER == cmd) ? "deregister" : "register",
                       index, trap_index + 1, mlnx_traps_info[index].sdk_traps_num,
                       mlnx_traps_info[index].sdk_trap_ids[trap_index], SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_trap_filter_set(uint32_t index, sai_object_list_t ports)
{
    sai_status_t      status;
    uint32_t          trap_index, ii, count;
    sx_port_log_id_t *filter_list;

    SX_LOG_ENTER();

    if (0 == mlnx_traps_info[index].sdk_traps_num) {
        SX_LOG_ERR("trap %s %x not supported\n", mlnx_traps_info[index].trap_name, mlnx_traps_info[index].trap_id);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    count       = ports.count;
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
    uint32_t         index, trap_data;
    sx_trap_action_t action;

    SX_LOG_ENTER();


    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_trap_action_to_sdk(value->s32, &action, 0))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_REGULAR, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_data);
        return status;
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(index, value->s32, g_sai_db_ptr->traps_db[index].trap_group))) {
        goto out;
    }
    g_sai_db_ptr->traps_db[index].action = value->s32;

out:
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    return status;
}

/* trap type [sai_hostif_trap_type_t] */
static sai_status_t mlnx_trap_type_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    uint32_t     trap_data, index;
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_REGULAR, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_data);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    value->s32 = trap_data;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* trap type [sai_hostif_user_defined_trap_type_t] */
static sai_status_t mlnx_user_defined_trap_type_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    uint32_t     trap_data, index;
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_USER_DEFINED, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_data);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    value->s32 = trap_data;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* trap action [sai_packet_action_t] */
static sai_status_t mlnx_trap_action_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    uint32_t     trap_data;
    sai_status_t status;
    mlnx_trap_t  trap_record;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_record_get(trap_data, MLNX_TRAP_TYPE_REGULAR, &trap_record))) {
        return status;
    }

    value->s32 = trap_record.action;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* trap-group ID for the trap [sai_object_id_t] */
static sai_status_t mlnx_trap_group_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t status;
    uint32_t     index, prio, trap_data;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(value->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_REGULAR, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_data);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(index, g_sai_db_ptr->traps_db[index].action, value->oid))) {
        goto out;
    }
    g_sai_db_ptr->traps_db[index].trap_group = value->oid;

out:
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    return status;
}

/* trap-group ID for the trap [sai_object_id_t] */
static sai_status_t mlnx_trap_group_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t status;
    mlnx_trap_t  trap_record;
    uint32_t     trap_data;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_record_get(trap_data, MLNX_TRAP_TYPE_REGULAR, &trap_record))) {
        return status;
    }

    value->oid = trap_record.trap_group;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* List of SAI ports to be excluded (disabled) from the trap generation [sai_object_list_t] */
static sai_status_t mlnx_trap_exclude_port_list_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    sai_status_t status;
    uint32_t     index, trap_data;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_REGULAR, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_data);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return mlnx_trap_filter_set(index, value->objlist);
}

/* trap-group ID for the trap [sai_object_id_t] */
static sai_status_t mlnx_user_defined_trap_group_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t status;
    uint32_t     index, prio, trap_data;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(value->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &prio, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_data, MLNX_TRAP_TYPE_USER_DEFINED, &index))) {
        SX_LOG_ERR("Invalid trap %x\n", trap_data);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(index, g_sai_db_ptr->traps_db[index].action, value->oid))) {
        goto out;
    }
    g_sai_db_ptr->traps_db[index].trap_group = value->oid;

out:
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    return status;
}

/* trap-group ID for the trap [sai_object_id_t] */
static sai_status_t mlnx_user_defined_trap_group_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t status;
    mlnx_trap_t  trap_record;
    uint32_t     trap_data;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP, &trap_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_trap_record_get(trap_data, MLNX_TRAP_TYPE_USER_DEFINED, &trap_record))) {
        return status;
    }

    value->oid = trap_record.trap_group;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   hostif receive function
 *
 * Arguments:
 *    [in]  hif_id  - host interface id
 *    [out] buffer - packet buffer
 *    [in,out] buffer_size - [in] allocated buffer size. [out] actual packet size in bytes
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
                                            _Out_ void            *buffer,
                                            _Inout_ sai_size_t    *buffer_size,
                                            _Inout_ uint32_t      *attr_count,
                                            _Out_ sai_attribute_t *attr_list)
{
    sx_receive_info_t      receive_info;
    mlnx_object_id_t       mlnx_hif = {0};
    uint32_t               packet_size;
    const char            *trap_name;
    sai_hostif_trap_type_t trap_id;
    sai_status_t           status;
    sx_fd_t                fd;
    mlnx_trap_type_t       trap_type;

    SX_LOG_ENTER();

    memset(&fd, 0, sizeof(fd));

    if (*attr_count < RECV_ATTRIBS_NUM) {
        SX_LOG_ERR("Insufficient attribute count %u %u\n", RECV_ATTRIBS_NUM, *attr_count);
        *attr_count = RECV_ATTRIBS_NUM;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, hif_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_HOSTIF_OBJECT_TYPE_FD != mlnx_hif.field.sub_type) {
        SX_LOG_ERR("Can't recv on non FD host interface type %u\n", mlnx_hif.field.sub_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    memcpy(&fd, &g_sai_db_ptr->fd_db[mlnx_hif.id.u32], sizeof(fd));
    cl_plock_release(&g_sai_db_ptr->p_lock);

    packet_size = (uint32_t)*buffer_size;
    if (SX_STATUS_SUCCESS != (status = sx_lib_host_ifc_recv(&fd, buffer, &packet_size, &receive_info))) {
        if (SX_STATUS_NO_MEMORY == status) {
            SX_LOG_ERR("sx_api_host_ifc_recv failed with insufficient buffer %u %zu\n", packet_size, *buffer_size);
            *buffer_size = packet_size;
            return SAI_STATUS_BUFFER_OVERFLOW;
        }
        SX_LOG_ERR("sx_api_host_ifc_recv failed with error %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    *buffer_size = packet_size;

    *attr_count     = RECV_ATTRIBS_NUM;
    attr_list[0].id = SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID;
    attr_list[1].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT;
    attr_list[2].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG;

    if (SX_INVALID_PORT == receive_info.source_log_port) {
        SX_LOG_ERR("sx_api_host_ifc_recv returned unknown port\n");
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sdk_trap_to_sai(receive_info.trap_id, &trap_id, &trap_name, &trap_type))) {
        SX_LOG_ERR("unknown sdk trap %u\n", receive_info.trap_id);
        return SAI_STATUS_FAILURE;
    }
    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_create_object((trap_type ==
                                 MLNX_TRAP_TYPE_REGULAR) ? SAI_OBJECT_TYPE_HOSTIF_TRAP :
                                SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                                trap_id, NULL, &attr_list[0].value.oid))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, receive_info.source_log_port, NULL,
                                                           &attr_list[1].value.oid))) {
        return status;
    }

    if (receive_info.is_lag) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, receive_info.source_lag_port, NULL,
                                                               &attr_list[2].value.oid))) {
            return status;
        }
    } else {
        attr_list[2].value.oid = SAI_NULL_OBJECT_ID;
    }

    SX_LOG_INF("Received trap %s port %x\n", trap_name, receive_info.source_log_port);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   hostif send function
 *
 * Arguments:
 *    [in] hif_id  - host interface id. only valid for send through FD channel. Use SAI_NULL_OBJECT_ID for send through CB channel.
 *    [In] buffer - packet buffer
 *    [in] buffer size - packet size in bytes
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_send_hostif_packet(_In_ sai_object_id_t  hif_id,
                                            _In_ void            *buffer,
                                            _In_ sai_size_t       buffer_size,
                                            _In_ uint32_t         attr_count,
                                            _In_ sai_attribute_t *attr_list)
{
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    uint32_t                     type_index, port_index;
    const sai_attribute_value_t *type, *port;
    uint32_t                     port_data;
    sai_status_t                 status;
    sx_fd_t                      fd;

    memset(&fd, 0, sizeof(fd));

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_PACKET,
                                    host_interface_packet_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_PACKET, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("send packet, %s\n", list_str);

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
                (status = mlnx_object_to_type(port->oid, SAI_OBJECT_TYPE_LAG, &port_data, NULL))) {
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

        if (SAI_HOSTIF_OBJECT_TYPE_FD != mlnx_hif.field.sub_type) {
            SX_LOG_ERR("Can't send on non FD host interface type %u\n", mlnx_hif.field.sub_type);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        cl_plock_acquire(&g_sai_db_ptr->p_lock);
        memcpy(&fd, &g_sai_db_ptr->fd_db[mlnx_hif.id.u32], sizeof(fd));
        cl_plock_release(&g_sai_db_ptr->p_lock);
    }

    /* TODO : fill correct cos prio */
    if (SAI_HOSTIF_TX_TYPE_PIPELINE_BYPASS == type->s32) {
        if (SX_STATUS_SUCCESS !=
            (status =
                 sx_lib_host_ifc_unicast_ctrl_send(&fd, buffer, (uint32_t)buffer_size, DEFAULT_ETH_SWID, port_data,
                                                   0))) {
            SX_LOG_ERR("sx_lib_host_ifc_unicast_ctrl_send failed with error %s\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    } else {
        if (SX_STATUS_SUCCESS !=
            (status = sx_lib_host_ifc_data_send(&fd, buffer, (uint32_t)buffer_size, DEFAULT_ETH_SWID, 0))) {
            SX_LOG_ERR("sx_lib_host_ifc_data_send failed with error %s\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static void host_table_entry_key_to_str(_In_ sai_object_id_t hif_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_hif = { 0 };
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, hif_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid host table entry");
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "host table entry %x,ind %u,%u",
                 mlnx_hif.id.u32,
                 mlnx_hif.ext.trap.id,
                 mlnx_hif.field.sub_type);
    }
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
    uint32_t                     type_index, channel_index, obj_index, trap_index, fd_index;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    mlnx_object_id_t             mlnx_hif = { 0 }, mlnx_fd = { 0 };
    uint32_t                     obj_data, trap_id, trap_db_index;
    uint16_t                     vlan_id;
    sx_host_ifc_register_key_t   reg;
    sai_object_type_t            trap_type;
    sx_fd_t                      fd_val = { 0 };
    uint32_t                     ii;

    SX_LOG_ENTER();

    memset(&reg, 0, sizeof(reg));

    if (NULL == hif_table_entry) {
        SX_LOG_ERR("NULL host interface table entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY,
                                    host_table_entry_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create host table entry, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);
    mlnx_hif.field.sub_type = type->s32;

    if ((SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT == type->s32) || (SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG == type->s32) ||
        (SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN == type->s32)) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID, &obj,
                                     &obj_index))) {
            SX_LOG_ERR("Missing mandatory attribute obj ID on create of host table entry type port/lag/vlan\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if ((SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT == type->s32) || (SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG == type->s32)) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(obj->oid,
                                         (SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT ==
                                          type->s32) ? SAI_OBJECT_TYPE_PORT : SAI_OBJECT_TYPE_LAG,
                                         &obj_data, NULL))) {
                return status;
            }
            mlnx_hif.id.u32       = obj_data;
            reg.key_type          = SX_HOST_IFC_REGISTER_KEY_TYPE_PORT;
            reg.key_value.port_id = obj_data;
        } else {
            status = sai_object_to_vlan(obj->oid, &vlan_id);
            if (SAI_ERR(status)) {
                return status;
            }
            mlnx_hif.id.u32       = vlan_id;
            reg.key_type          = SX_HOST_IFC_REGISTER_KEY_TYPE_VLAN;
            reg.key_value.vlan_id = vlan_id;
        }
    } else {
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID, &obj,
                                     &obj_index))) {
            SX_LOG_ERR("Invalid attribute obj ID for trap/wildcard host table entry on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + obj_index;
        }

        if ((SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID == type->s32) ||
            (SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD == type->s32)) {
            reg.key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_GLOBAL;
        } else {
            SX_LOG_ERR("Invalid host table entry type %d", type->s32);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
        }
    }

    if (SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD == type->s32) {
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID, &trap,
                                     &trap_index))) {
            SX_LOG_ERR("Invalid attribute trap ID for wildcard host table entry on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + obj_index;
        }
    } else {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID, &trap,
                                     &trap_index))) {
            SX_LOG_ERR("Missing mandatory attribute trap ID on create of host table entry type port/lag/vlan/trap\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        trap_type = sai_object_type_query(trap->oid);

        if ((trap_type != SAI_OBJECT_TYPE_HOSTIF_TRAP) && (trap_type != SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP)) {
            SX_LOG_ERR("Trap ID type %s is not trap nor user defined trap\n", SAI_TYPE_STR(trap_type));
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + trap_index;
        }

        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(trap->oid, trap_type, &trap_id, NULL))) {
            SX_LOG_EXIT();
            return status;
        }

        if (SAI_STATUS_SUCCESS != (status = find_sai_trap_index(trap_id,
                                                                (SAI_OBJECT_TYPE_HOSTIF_TRAP ==
                                                                 trap_type) ? MLNX_TRAP_TYPE_REGULAR :
                                                                MLNX_TRAP_TYPE_USER_DEFINED, &trap_db_index))) {
            SX_LOG_ERR("Invalid %strap %x\n",
                       (SAI_OBJECT_TYPE_HOSTIF_TRAP == trap_type) ? "" : "user defined ",
                       trap_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        mlnx_hif.ext.trap.id = trap_db_index;
    }

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE,
                                 &channel,
                                 &channel_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_FD == channel->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF, &fd,
                                     &fd_index))) {
            SX_LOG_ERR("Missing mandatory attribute host if on create of host table entry channel FD\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF, fd->oid, &mlnx_fd);
        if (SAI_ERR(status)) {
            return status;
        }
        if (SAI_HOSTIF_OBJECT_TYPE_FD != mlnx_fd.field.sub_type) {
            SX_LOG_ERR("Can't set non FD host interface type %u\n", mlnx_fd.field.sub_type);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + fd_index;
        }
        cl_plock_acquire(&g_sai_db_ptr->p_lock);
        fd_val = g_sai_db_ptr->fd_db[mlnx_fd.id.u32];
        cl_plock_release(&g_sai_db_ptr->p_lock);
    } else {
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF, &fd,
                                     &fd_index))) {
            SX_LOG_ERR("Invalid attribute host IF for host table entry channel non FD on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + fd_index;
        }

        if (SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_CB == channel->s32) {
            fd_val = g_sai_db_ptr->callback_channel.channel.fd;
        }
    }

    if (SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD == type->s32) {
        for (ii = 0; END_TRAP_INFO_ID != mlnx_traps_info[ii].trap_id; ii++) {
            if (0 == mlnx_traps_info[ii].sdk_traps_num) {
                continue;
            }

            if (SAI_STATUS_SUCCESS != (status = mlnx_register_trap(SX_ACCESS_CMD_REGISTER, ii,
                                                                   channel->s32, fd_val, &reg))) {
                return status;
            }
        }
    } else {
        if (SAI_STATUS_SUCCESS != (status = mlnx_register_trap(SX_ACCESS_CMD_REGISTER, trap_db_index,
                                                               channel->s32, fd_val, &reg))) {
            return status;
        }
    }

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, &mlnx_hif, hif_table_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    host_table_entry_key_to_str(*hif_table_entry, key_str);

    SX_LOG_NTC("Created host table entry %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    char                       key_str[MAX_KEY_STR_LEN];
    sai_status_t               status;
    mlnx_object_id_t           mlnx_hif = { 0 };
    sx_host_ifc_register_key_t reg;
    sx_fd_t                    fd_val = { 0 };

    SX_LOG_ENTER();
    host_table_entry_key_to_str(hif_table_entry, key_str);
    SX_LOG_NTC("Remove host table entry %s\n", key_str);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, hif_table_entry, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    if ((SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT == mlnx_hif.field.sub_type) ||
        (SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG == mlnx_hif.field.sub_type)) {
        reg.key_type          = SX_HOST_IFC_REGISTER_KEY_TYPE_PORT;
        reg.key_value.port_id = mlnx_hif.id.u32;
    } else if (SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN == mlnx_hif.field.sub_type) {
        reg.key_type          = SX_HOST_IFC_REGISTER_KEY_TYPE_VLAN;
        reg.key_value.vlan_id = mlnx_hif.id.u32;
    } else {
        reg.key_type = SX_HOST_IFC_REGISTER_KEY_TYPE_GLOBAL;
    }

    return SAI_STATUS_NOT_IMPLEMENTED;

    /* TODO : Store channel in DB for registration */
    if (SAI_STATUS_SUCCESS != (status = mlnx_register_trap(SX_ACCESS_CMD_DEREGISTER, mlnx_hif.ext.trap.id,
                                                           0, fd_val, &reg))) {
        return status;
    }

    SX_LOG_EXIT();
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    host_table_entry_key_to_str(hif_table_entry, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, host_table_entry_vendor_attribs, attr);
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    host_table_entry_key_to_str(hif_table_entry, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY,
                              host_table_entry_vendor_attribs,
                              attr_count,
                              attr_list);
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

    SX_LOG_ENTER();

    assert((SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE == (long)arg) || (SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID == (long)arg) ||
           (SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID == (long)arg));

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, key->key.object_id, &mlnx_hif);
    if (SAI_ERR(status)) {
        return status;
    }

    switch ((long)arg) {
    case SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE:
        value->s32 = mlnx_hif.field.sub_type;
        break;

    case SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID:
        switch (mlnx_hif.field.sub_type) {
        case SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT:
            return mlnx_create_object(SAI_OBJECT_TYPE_PORT, mlnx_hif.id.u32, NULL, &value->oid);

        case SAI_HOSTIF_TABLE_ENTRY_TYPE_LAG:
            return mlnx_create_object(SAI_OBJECT_TYPE_LAG, mlnx_hif.id.u32, NULL, &value->oid);

        case SAI_HOSTIF_TABLE_ENTRY_TYPE_VLAN:
            vlan_obj_id.id.vlan_id = mlnx_hif.id.u32;
            return mlnx_object_id_to_sai(SAI_OBJECT_TYPE_VLAN, &vlan_obj_id, &value->oid);

        default:
            SX_LOG_ERR("Host table entry object ID invalid for type trap/wildcard %u\n", mlnx_hif.field.sub_type);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        break;

    case SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID:
        if (SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD == mlnx_hif.field.sub_type) {
            SX_LOG_ERR("Host table entry trap ID invalid for type wildcard\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        } else {
            return mlnx_create_object((MLNX_TRAP_TYPE_REGULAR == mlnx_traps_info[mlnx_hif.ext.trap.id].trap_type) ?
                                      SAI_OBJECT_TYPE_HOSTIF_TRAP : SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                                      mlnx_traps_info[mlnx_hif.ext.trap.id].trap_id, NULL, &value->oid);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    mlnx_send_hostif_packet
};
