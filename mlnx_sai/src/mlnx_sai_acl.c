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
#define __MODULE__ SAI_ACL


#define INDEX_ZERO                    0
#define INDEX_ONE                     1
#define MAX_ACL_LIMIT_IN_GROUP        16
#define IP_TYPE_KEY_SIZE              3 /* TODO: Change value to 4 when is_ip_v6 key is available */
#define IP_FRAG_KEY_TYPE_SIZE         2
#define SX_FLEX_ACL_MAX_FIELDS_IN_KEY RM_API_ACL_MAX_FIELDS_IN_KEY
#define MAX_NUM_OF_ACTIONS            20

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t mlnx_acl_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        sx_api_flow_counter_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level);
        return sdk_to_sai(sx_api_acl_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

/*..... Function Prototypes ..................*/

static sai_status_t acl_db_bind_acl_to_ports(sx_acl_direction_t direction,
                                             sx_access_cmd_t    cmd,
                                             sx_acl_id_t        acl_id,
                                             sx_port_log_id_t  *port_arr,
                                             uint32_t           port_num);
static sai_status_t delete_acl_group(_In_ uint32_t stage);
static sai_status_t mlnx_set_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ const sai_attribute_t *attr);
static sai_status_t mlnx_get_acl_entry_attribute(_In_ sai_object_id_t   acl_entry_id,
                                                 _In_ uint32_t          attr_count,
                                                 _Out_ sai_attribute_t *attr_list);
static sai_status_t mlnx_delete_acl_counter(_In_ sai_object_id_t acl_counter_id);
static sai_status_t mlnx_delete_acl_table(_In_ sai_object_id_t acl_table_id);
static sai_status_t mlnx_delete_acl_entry(_In_ sai_object_id_t acl_entry_id);
static sai_status_t sort_tables_in_group(_In_ uint32_t        stage,
                                         _In_ uint32_t        priority,
                                         _In_ uint32_t        acl_id,
                                         _Inout_ sx_acl_id_t *acl_table_ids,
                                         _In_ uint32_t        acl_count);
static sai_status_t mlnx_acl_entry_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_table_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_table_ip_and_tos_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_acl_table_fields_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_entry_tos_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_acl_entry_fields_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_entry_action_mac_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_acl_entry_packet_action_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_acl_entry_priority_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_acl_entry_mac_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static sai_status_t mlnx_acl_entry_ip_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
static sai_status_t mlnx_acl_entry_vlan_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);
static sai_status_t mlnx_acl_entry_port_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);
static sai_status_t mlnx_acl_entry_tos_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static sai_status_t mlnx_acl_entry_action_counter_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg);
static sai_status_t mlnx_acl_entry_action_mac_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg);
static sai_status_t mlnx_acl_counter_flag_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_counter_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_acl_entry_action_mirror_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_acl_entry_action_mirror_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_acl_entry_ip_frag_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_acl_entry_packet_action_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_acl_counter_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
static sai_status_t acl_db_port_bind_set(sx_access_cmd_t    cmd,
                                         sx_acl_direction_t direction,
                                         sx_acl_id_t        acl_id,
                                         sx_port_log_id_t  *port_arr,
                                         uint32_t          *port_num);
static sai_status_t mlnx_acl_entry_ports_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_acl_entry_mac_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_acl_entry_ip_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_acl_entry_ip_fields_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_acl_entry_vlan_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_acl_entry_port_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_acl_entry_action_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_entry_action_vlan_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_acl_entry_ip_fields_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_acl_entry_ports_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg);
static sai_status_t mlnx_acl_entry_fields_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_acl_entry_action_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_acl_entry_action_vlan_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg);
static sai_status_t fetch_flex_acl_rule_params_to_get(_In_ const sai_object_key_t     *key,
                                                      _Inout_ sx_flex_acl_flex_rule_t *flex_acl_rule_p);
static sai_status_t fetch_flex_acl_rule_params_to_set(_In_ const sai_object_key_t      *key,
                                                      _Inout_ sx_flex_acl_flex_rule_t **flex_acl_rule_p,
                                                      _Inout_ sx_acl_rule_offset_t    **offsets_list_p,
                                                      _Inout_ sx_acl_region_id_t       *region_id,
                                                      _Inout_ uint32_t                 *rules_num);
static sai_status_t mlnx_acl_packet_actions_handler(_In_ sai_packet_action_t         packet_action_type,
                                                    _In_ uint16_t                    trap_id,
                                                    _Inout_ sx_flex_acl_flex_rule_t *flex_rule,
                                                    _Inout_ uint8_t                 *flex_action_index);
static void acl_table_key_to_str(_In_ sai_object_id_t acl_table_id, _Out_ char *key_str);
static void acl_entry_key_to_str(_In_ sai_object_id_t acl_entry_id, _Out_ char *key_str);


/* ACL TABLE ATTRIBUTES */
static const sai_attribute_entry_t acl_table_attribs[] = {
    { SAI_ACL_TABLE_ATTR_STAGE, true, true, false, true,
      "ACL Table Stage", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ACL_TABLE_ATTR_PRIORITY, true, true, false, true,
      "ACL Table Priority", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ACL_TABLE_ATTR_SIZE, false, true, false, true,
      "ACL Table Size", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ACL_TABLE_ATTR_GROUP_ID, false, true, false, true,
      "ACL Table Priority", SAI_ATTR_VAL_TYPE_OID },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6, false, true, false, true,
      "Src IPv6 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6, false, true, false, true,
      "Dst IPv6 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC, false, true, false, true,
      "Src MAC Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_MAC, false, true, false, true,
      "Dst MAC Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IP, false, true, false, true,
      "Src IPv4 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IP, false, true, false, true,
      "Dst IPv4 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS, false, true, false, true,
      "In-Ports", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS, false, true, false, true,
      "Out-Ports", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IN_PORT, false, true, false, true,
      "In-Port", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT, false, true, false, true,
      "Out-Port", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_PORT, false, true, false, true,
      "Src-Port", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID, false, true, false, true,
      "Outer Vlan-Id", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_PRI, false, true, false, true,
      "Outer Vlan-Priority", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_CFI, false, true, false, true,
      "Outer Vlan-CFI", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID, false, true, false, true,
      "Inner Vlan-Id", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI, false, true, false, true,
      "Inner Vlan-Priority", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI, false, true, false, true,
      "Inner Vlan-CFI", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT, false, true, false, true,
      "L4 Src Port", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT, false, true, false, true,
      "L4 Dst Port", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE, false, true, false, true,
      "EtherType", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL, false, true, false, true,
      "IP Protocol", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_DSCP, false, true, false, true,
      "Ip Dscp", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ECN, false, true, false, true,
      "Ip Ecn", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_TTL, false, true, false, true,
      "Ip Ttl", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_TOS, false, true, false, true,
      "Ip Tos", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS, false, true, false, true,
      "Ip Flags", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS, false, true, false, false,
      "Tcp Flags", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_TYPE, false, true, false, true,
      "Ip Type", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_FRAG, false, true, false, true,
      "Ip Frag", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IPv6_FLOW_LABEL, false, false, false, false,
      "IPv6 Flow Label", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_TC, false, true, false, true,
      "Class-of-Service", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE, false, true, false, true,
      "ICMP Type", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE, false, true, false, true,
      "ICMP Code", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_VLAN_TAGS, false, true, false, true,
      "Vlan tags", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META, false, false, false, false,
      "FDB DST user meta data", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META, false, false, false, false,
      "ROUTE DST User Meta data", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META, false, false, false, false,
      "Neighbor DST User Meta Data", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_PORT_USER_META, false, false, false, false,
      "Port User Meta Data", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_VLAN_USER_META, false, false, false, false,
      "Vlan User Meta Data", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META, false, true, false, true,
      "Meta Data carried from previous ACL Stage", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_FDB_NPU_META_DST_HIT, false, true, false, false,
      "DST MAC address match in FDB", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_NPU_META_DST_HIT, false, true, false, false,
      "DST IP address match in neighbor table", SAI_ATTR_VAL_TYPE_BOOL },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

/* ACL ENTRY ATTRIBUTES */
static const sai_attribute_entry_t acl_entry_attribs[] = {
    { SAI_ACL_ENTRY_ATTR_TABLE_ID, true, true, false, true,
      "ACL Entry Table Id", SAI_ATTR_VAL_TYPE_OID },
    { SAI_ACL_ENTRY_ATTR_PRIORITY, false, true, true, true,
      "ACL Entry Priority ", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_ACL_ENTRY_ATTR_ADMIN_STATE, false, true, true, true,
      "ACL Entry Admin State", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6, false, true, true, true,
      "Src IPv6 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6, false, true, true, true,
      "Dst IPv6 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC, false, true, true, true,
      "Src MAC Address", SAI_ATTR_VAL_TYPE_ACLFIELD_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC, false, true, true, true,
      "Dst MAC Address", SAI_ATTR_VAL_TYPE_ACLFIELD_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP, false, true, true, true,
      "Src IPv4 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4 },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IP, false, true, true, true,
      "Dst IPv4 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4 },
    { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS, false, true, true, true,
      "In-Ports",  SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS, false, true, true, true,
      "Out-Ports", SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST},
    { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT, false, true, true, true,
      "In-Port", SAI_ATTR_VAL_TYPE_ACLFIELD_OID },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT, false, true, true, true,
      "Out-Port", SAI_ATTR_VAL_TYPE_ACLFIELD_OID },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_PORT, false, true, true, true,
      "Src-Port", SAI_ATTR_VAL_TYPE_ACLFIELD_OID },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID, false, true, true, true,
      "Outer Vlan-Id", SAI_ATTR_VAL_TYPE_ACLFIELD_U16 },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI, false, true, true, true,
      "Outer Vlan-Priority", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI, false, true, true, true,
      "Outer Vlan-CFI", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID, false, true, true, true,
      "Inner Vlan-Id", SAI_ATTR_VAL_TYPE_ACLFIELD_U16 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI, false, true, true, true,
      "Inner Vlan-Priority", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI, false, true, true, true,
      "Inner Vlan-CFI", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT, false, true, true, true,
      "L4 Src Port", SAI_ATTR_VAL_TYPE_ACLFIELD_U16 },
    { SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT, false, true, true, true,
      "L4 Dst Port", SAI_ATTR_VAL_TYPE_ACLFIELD_U16 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE, false, true, true, true,
      "EtherType", SAI_ATTR_VAL_TYPE_ACLFIELD_U16 },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL, false, true, true, true,
      "IP Protocol", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_DSCP, false, true, true, true,
      "Ip Dscp", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ECN, false, true, true, true,
      "Ip Ecn", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_TTL, false, true, true, true,
      "Ip Ttl", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_TOS, false, true, true, true,
      "Ip Tos", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS, false, true, true, true,
      "Ip Flags", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS, false, true, true, true,
      "Tcp Flags", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE, false, true, true, true,
      "Ip Type",  SAI_ATTR_VAL_TYPE_ACLFIELD_S32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_FRAG, false, true, true, true,
      "Ip Frag", SAI_ATTR_VAL_TYPE_ACLFIELD_S32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_IPv6_FLOW_LABEL, false, false, false, false,
      "IPv6 Flow Label",  SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_TC, false, true, true, true,
      "Class-of-Service (Traffic Class)", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE, false, true, true, true,
      "ICMP Type", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE, false, true, true, true,
      "ICMP Code", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS, false, true, true, true,
      "Vlan tags", SAI_ATTR_VAL_TYPE_ACLFIELD_S32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META, false, false, false, false,
      "FDB DST user meta data", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META, false, false, false, false,
      "ROUTE DST User Meta data", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_USER_META, false, false, false, false,
      "Neighbor DST User Meta Data", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_PORT_USER_META, false, false, false, false,
      "Port User Meta Data", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_VLAN_USER_META, false, false, false, false,
      "Vlan User Meta Data", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META, false, true, true, true,
      "Meta Data carried from previous ACL Stage", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_FDB_NPU_META_DST_HIT, false, false, false, false,
      "DST MAC address match in FDB", SAI_ATTR_VAL_TYPE_ACLFIELD_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_NPU_META_DST_HIT, false, false, false, false,
      "DST IP address match in neighbor table", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4 },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT, false, true, true, true,
      "Redirect Packet to a destination", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST, false, true, true, true,
      "Redirect Packet to a destination list", SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST },
    { SAI_ACL_ENTRY_ATTR_PACKET_ACTION, false, true, true, true,
      "Drop Packet", SAI_ATTR_VAL_TYPE_ACLACTION_S32 },
    { SAI_ACL_ENTRY_ATTR_ACTION_FLOOD, false, true, true, false,
      "Flood Packet on Vlan domain", SAI_ATTR_VAL_TYPE_ACLACTION_NONE },
    { SAI_ACL_ENTRY_ATTR_ACTION_COUNTER, false, true, true, true,
      "Attach/detach counter id to the entry", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, false, true, true, true,
      "Ingress Mirror", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS, false, true, true, true,
      "Egress Mirror", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER, false, true, true, true,
      "Associate with policer", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL, false, true, true, false,
      "Decrement TTL", SAI_ATTR_VAL_TYPE_ACLACTION_NONE },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_TC, false, true, true, true,
      "Set Class-of-Service",  SAI_ATTR_VAL_TYPE_ACLACTION_U8 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR, false, true, true, true,
      "Set packet color",  SAI_ATTR_VAL_TYPE_ACLACTION_U8 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID, false, true, true, true,
      "Set Packet Inner Vlan-Id", SAI_ATTR_VAL_TYPE_ACLACTION_U16 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI, false, true, true, true,
      "Set Packet Inner Vlan-Priority", SAI_ATTR_VAL_TYPE_ACLACTION_U8 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID, false, true, true, true,
      "Set Packet Outer Vlan-Id", SAI_ATTR_VAL_TYPE_ACLACTION_U16 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI, false, true, true, true,
      "Set Packet Outer Vlan-Priority", SAI_ATTR_VAL_TYPE_ACLACTION_U8 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC, false, true, true, true,
      "Set Packet Src MAC Address", SAI_ATTR_VAL_TYPE_ACLACTION_MAC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC, false, true, true, true,
      "Set Packet Dst MAC Address", SAI_ATTR_VAL_TYPE_ACLACTION_MAC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP, false, false, false, false,
      "Set Packet Src IPv4 Address", SAI_ATTR_VAL_TYPE_ACLACTION_IPV4 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP, false, false, false, false,
      "Set Packet Dst IPv4 Address", SAI_ATTR_VAL_TYPE_ACLACTION_IPV4 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPv6, false, false, false, false,
      "Set Packet Src IPv6 Address", SAI_ATTR_VAL_TYPE_ACLACTION_IPV6 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPv6, false, false, false, false,
      "Set Packet Dst IPv6 Address", SAI_ATTR_VAL_TYPE_ACLACTION_IPV6 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP, false, true, true, true,
      "Set Packet DSCP", SAI_ATTR_VAL_TYPE_ACLACTION_U8 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN, false, true, true, true,
      "Set Packet ECN", SAI_ATTR_VAL_TYPE_ACLACTION_U8 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT, false, false, false, false,
      "Set Packet L4 Src Port", SAI_ATTR_VAL_TYPE_ACLACTION_U16 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT, false, false, false, false,
      "Set Packet L4 Dst Port", SAI_ATTR_VAL_TYPE_ACLACTION_U16 },
    { SAI_ACL_ENTRY_ATTR_ACTION_INGRESS_SAMPLEPACKET_ENABLE, false, false, false, false,
      "Set ingress packet sampling", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_SAMPLEPACKET_ENABLE, false, false, false, false,
      "Set egress packet sampling", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_CPU_QUEUE, false, false, false, false,
      "Set CPU Queue", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA, false, true, true, true,
      "Set Meta Data", SAI_ATTR_VAL_TYPE_ACLACTION_U32 },
    { SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_BLOCK_PORT_LIST, false, true, true, true,
      "Egress block port list", SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_USER_TRAP_ID, false, true, true, true,
      "Set user def trap ID", SAI_ATTR_VAL_TYPE_ACLACTION_U32 },
    { END_FUNCTIONALITY_ATTRIBS_ID,  false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_attribute_entry_t acl_range_attribs[] = {
    { SAI_ACL_RANGE_ATTR_TYPE, true, true, false, true,
      "ACL range type", SAI_ATTR_VAL_TYPE_S32},
    { SAI_ACL_RANGE_ATTR_LIMIT, true, true, false, true,
      "ACL range limit", SAI_ATTR_VAL_TYPE_U32RANGE },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

/* ACL TABLE VENDOR ATTRIBUTES */
static const sai_vendor_attribute_entry_t acl_table_vendor_attribs[] = {
    { SAI_ACL_TABLE_ATTR_STAGE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_STAGE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_PRIORITY,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_PRIORITY,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_SIZE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_SIZE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_GROUP_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_GROUP_ID,
      NULL, NULL },
#ifdef ACL_TODO
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6,
      NULL, NULL },
#else /* ACL_TODO */
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
#endif /* ACL_TODO */
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_ip_and_tos_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_ip_and_tos_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IN_PORT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IN_PORT,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_PORT,
      { false, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_PRI,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_PRI,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_CFI,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_CFI,
      NULL, NULL },
#ifdef ACL_TODO
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI,
      NULL, NULL },
#else /* ACL_TODO */
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
#endif /* ACL_TODO */
    { SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_DSCP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_DSCP,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ECN,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ECN,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_TTL,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_TTL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_TOS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_ip_and_tos_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_TOS,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_ip_and_tos_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IP_TYPE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_FRAG,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_ip_and_tos_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IP_FRAG,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IPv6_FLOW_LABEL,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_TC,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_TC,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE,
      { false, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE,
      { false, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_VLAN_TAGS,
      { false, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_PORT_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_VLAN_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_FDB_NPU_META_DST_HIT,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_NPU_META_DST_HIT,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};

/* ACL ENTRY VENDOR ATTRIBUTES */
static const sai_vendor_attribute_entry_t acl_entry_vendor_attribs[] = {
    { SAI_ACL_ENTRY_ATTR_TABLE_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_entry_attrib_get, (void*)SAI_ACL_ENTRY_ATTR_TABLE_ID,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_PRIORITY,
      {true, false, true, true},
      {true, false, true, true},
      mlnx_acl_entry_attrib_get, (void*)SAI_ACL_ENTRY_ATTR_PRIORITY,
      mlnx_acl_entry_priority_set, NULL },
    { SAI_ACL_ENTRY_ATTR_ADMIN_STATE,
      {true, false, true, true},
      {true, false, true, true},
      mlnx_acl_entry_fields_get, (void*)SAI_ACL_ENTRY_ATTR_ADMIN_STATE,
      mlnx_acl_entry_fields_set, (void*)SAI_ACL_ENTRY_ATTR_ADMIN_STATE },
#ifdef ACL_TODO
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6,
      mlnx_acl_entry_ip_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6,
      mlnx_acl_entry_ip_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6 },
#else
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
#endif /* ACL_TODO */
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_mac_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC,
      mlnx_acl_entry_mac_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_mac_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC,
      mlnx_acl_entry_mac_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
      mlnx_acl_entry_ip_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IP,
      mlnx_acl_entry_ip_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IP },
    { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ports_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
      mlnx_acl_entry_ports_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ports_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
      mlnx_acl_entry_ports_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS },
    { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_port_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
      mlnx_acl_entry_port_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_port_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
      mlnx_acl_entry_port_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_PORT,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID,
      mlnx_acl_entry_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI,
      mlnx_acl_entry_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI,
      mlnx_acl_entry_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI },
#ifdef ACL_TODO
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID,
      mlnx_acl_entry_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI,
      mlnx_acl_entry_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI,
      mlnx_acl_entry_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI },
#else /* ACL_TODO */
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
#endif /* ACL_TODO */
    { SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_port_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT,
      mlnx_acl_entry_port_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_port_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT,
      mlnx_acl_entry_port_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE,
      mlnx_acl_entry_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
      mlnx_acl_entry_ip_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL },
    { SAI_ACL_ENTRY_ATTR_FIELD_DSCP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_tos_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DSCP,
      mlnx_acl_entry_tos_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DSCP },
    { SAI_ACL_ENTRY_ATTR_FIELD_ECN,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_tos_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ECN,
      mlnx_acl_entry_tos_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ECN },
    { SAI_ACL_ENTRY_ATTR_FIELD_TTL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TTL,
      mlnx_acl_entry_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TTL },
    { SAI_ACL_ENTRY_ATTR_FIELD_TOS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_tos_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TOS,
      mlnx_acl_entry_tos_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TOS },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS,
      mlnx_acl_entry_ip_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS },
    { SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS,
      mlnx_acl_entry_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE,
      mlnx_acl_entry_ip_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_FRAG,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_FRAG,
      mlnx_acl_entry_ip_frag_set, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_IPv6_FLOW_LABEL,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_TC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TC,
      mlnx_acl_entry_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TC },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_PORT_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_VLAN_USER_META,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META,
      mlnx_acl_entry_fields_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META },
    { SAI_ACL_ENTRY_ATTR_FIELD_FDB_NPU_META_DST_HIT,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_NPU_META_DST_HIT,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_packet_action_get, (void*)SAI_ACL_ENTRY_ATTR_PACKET_ACTION,
      mlnx_acl_entry_packet_action_set, (void*)SAI_ACL_ENTRY_ATTR_PACKET_ACTION },
    { SAI_ACL_ENTRY_ATTR_ACTION_FLOOD,
      { true, false, true, false },
      { true, false, true, false },
      NULL, NULL,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_FLOOD },
    { SAI_ACL_ENTRY_ATTR_ACTION_COUNTER,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_COUNTER,
      mlnx_acl_entry_action_counter_set, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_mirror_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS,
      mlnx_acl_entry_action_mirror_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS },
    {  SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS,
       { true, false, true, true },
       { true, false, true, true },
       mlnx_acl_entry_action_mirror_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS,
       mlnx_acl_entry_action_mirror_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER },
    { SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL,
      { true, false, true, false },
      { true, false, true, false },
      NULL, NULL,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_TC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_TC,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_TC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_vlan_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC,
      { true, false, true, true},
      { true, false, true, true},
      mlnx_acl_entry_action_mac_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC,
      mlnx_acl_entry_action_mac_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC,
      { true, false, false, true},
      { true, false, false, true},
      mlnx_acl_entry_action_mac_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC,
      mlnx_acl_entry_action_mac_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPv6,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPv6,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP,
      { true, false, true, true},
      { true, false, true, true},
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN,
      { true, false, true, true},
      { true, false, true, true},
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_INGRESS_SAMPLEPACKET_ENABLE,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_SAMPLEPACKET_ENABLE,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_CPU_QUEUE,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA,
      { true, false, true, true},
      { true, false, true, true},
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA },
    { SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_BLOCK_PORT_LIST,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_USER_TRAP_ID,
      { false, false, false, false},
      { true, false, true, true},
      NULL, NULL,
      NULL, NULL },
};
static const sai_vendor_attribute_entry_t acl_range_vendor_attribs[] = {
    { SAI_ACL_RANGE_ATTR_TYPE,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_RANGE_ATTR_LIMIT,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL }
};
static const sai_attribute_entry_t        acl_counter_attribs[] = {
    { SAI_ACL_COUNTER_ATTR_TABLE_ID, true, true, false, false,
      "Counter Table Id", SAI_ATTR_VAL_TYPE_OID },
    { SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT, false, true, false, true,
      "ACL Packet Count enable", SAI_ATTR_VAL_TYPE_BOOL},
    { SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT, false, true, false, true,
      "ACL Byte Count enable", SAI_ATTR_VAL_TYPE_BOOL},
    { SAI_ACL_COUNTER_ATTR_PACKETS, false, true, true, true,
      "Packet Counter Value", SAI_ATTR_VAL_TYPE_U64 },
    { SAI_ACL_COUNTER_ATTR_BYTES, false, true, true, true,
      "Packet Counter Value", SAI_ATTR_VAL_TYPE_U64 },
    { END_FUNCTIONALITY_ATTRIBS_ID,  false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t acl_counter_vendor_attribs[] = {
    { SAI_ACL_COUNTER_ATTR_TABLE_ID,
      {true, true, false, true },
      {true, true, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_counter_flag_get, (void*)SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
      NULL, NULL },
    { SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_counter_flag_get, (void*)SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
      NULL, NULL },
    { SAI_ACL_COUNTER_ATTR_PACKETS,
      {false, false, true, true},
      {false, false, true, true},
      mlnx_acl_counter_get, (void*)SAI_ACL_COUNTER_ATTR_PACKETS,
      mlnx_acl_counter_set, (void*)SAI_ACL_COUNTER_ATTR_PACKETS },
    { SAI_ACL_COUNTER_ATTR_BYTES,
      {false, false, true, true},
      {false, false, true, true},
      mlnx_acl_counter_get, (void*)SAI_ACL_COUNTER_ATTR_BYTES,
      mlnx_acl_counter_set, (void*)SAI_ACL_COUNTER_ATTR_BYTES }
};
static sai_status_t delete_acl_group(_In_ uint32_t stage)
{
    sx_status_t     ret_status;
    sai_status_t    status = SAI_STATUS_SUCCESS;
    sx_acl_id_t     acl_table_ids[MAX_INGRESS_TABLE_SIZE], group_id;
    uint32_t        acl_index, acl_count;
    sai_object_id_t table_id;

    SX_LOG_ENTER();

    sai_db_read_lock();
    group_id = g_sai_db_ptr->acl_db.acl_group_db[stage].group_id;

    memset(acl_table_ids, 0, sizeof(sx_acl_id_t) * MAX_INGRESS_TABLE_SIZE);
    acl_count = g_sai_db_ptr->acl_db.acl_group_db[stage].acl_table_count;
    if (SX_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_get(gh_sdk, group_id, (sx_acl_direction_t*)&stage, acl_table_ids, &acl_count))) {
        SX_LOG_ERR("Failed to retrieve ACL List in %s ACL group - %s.\n",
                   stage == SAI_ACL_STAGE_INGRESS ? "Ingress" : "Egress",
                   SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    for (acl_index = 0; acl_index < acl_count; acl_index++) {
        sai_db_unlock();

        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, acl_table_ids[acl_index], NULL, &table_id))) {
            sai_db_read_lock();
            goto out;
        }

        if (SAI_STATUS_SUCCESS != (status = mlnx_delete_acl_table(table_id))) {
            SX_LOG_ERR(" Failed to delete ACL Table - [%d] \n", acl_index);
            sai_db_read_lock();
            goto out;
        }
        sai_db_read_lock();
    }

    if (SX_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, SAI_ACL_STAGE_INGRESS, NULL, 0, &group_id))) {
        SX_LOG_ERR("Unable to delete acl group [%d] - %s.\n", group_id, SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    } else {
        SX_LOG_NTC("ACl Group deleted with group id[%d] \n", group_id);
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}
/*
 *   Routine Description:
 *       Unitialize ACL D.B
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */

sai_status_t acl_db_deinit()
{
    sai_status_t    status = SAI_STATUS_SUCCESS;
    sai_object_id_t acl_counter_id;
    uint32_t        ii = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = delete_acl_group(SAI_ACL_STAGE_INGRESS))) {
        SX_LOG_ERR(" Failed to delete Ingress ACL Group. \n");
        sai_db_read_lock();
        goto out;
    }
    if (SAI_STATUS_SUCCESS != (status = delete_acl_group(SAI_ACL_STAGE_EGRESS))) {
        SX_LOG_ERR(" Failed to delete Egress ACL Group. \n");
        sai_db_read_lock();
        goto out;
    }
    sai_db_write_lock();

    for (ii = 0; ii < MAX_ACL_COUNTER_NUM; ii++) {
        if (g_sai_db_ptr->acl_db.acl_counter_db[ii].is_valid == true) {
            sai_db_unlock();
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_COUNTER, ii, NULL, &acl_counter_id))) {
                sai_db_read_lock();
                goto out;
            }
            if (SAI_STATUS_SUCCESS != (status = mlnx_delete_acl_counter(acl_counter_id))) {
                SX_LOG_ERR(" Failed to delete ACL Counter \n");
                sai_db_read_lock();
                goto out;
            }
            sai_db_read_lock();
        }
    }

    memset(&(g_sai_db_ptr->acl_db), 0, sizeof(g_sai_db_ptr->acl_db));

out:
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}


/*
 *   Routine Description:
 *       Initialize ACL D.B
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */

sai_status_t acl_db_init()
{
    sx_status_t  ret_status;
    sai_status_t status = SAI_STATUS_SUCCESS;
    sx_acl_id_t  ingress_acl_group_id;
    sx_acl_id_t  egress_acl_group_id;

    SX_LOG_ENTER();

    sai_db_write_lock();
    /* Initialise the D.B with Zero Values */
    memset(&(g_sai_db_ptr->acl_db), 0, sizeof(g_sai_db_ptr->acl_db));

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, SX_ACL_DIRECTION_INGRESS, NULL, 0,
                                  &ingress_acl_group_id))) {
        SX_LOG_ERR("Unable to create ingress acl group - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    } else {
        g_sai_db_ptr->acl_db.acl_group_db[SAI_ACL_STAGE_INGRESS].acl_table_count = 0;
        g_sai_db_ptr->acl_db.acl_group_db[SAI_ACL_STAGE_INGRESS].group_id        = ingress_acl_group_id;
        SX_LOG_NTC("Ingress ACl Group created with group id[%d] \n", ingress_acl_group_id);
    }
    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, SX_ACL_DIRECTION_EGRESS, NULL, 0,
                                  &egress_acl_group_id))) {
        SX_LOG_ERR("Unable to create egress acl group - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    } else {
        g_sai_db_ptr->acl_db.acl_group_db[SAI_ACL_STAGE_EGRESS].acl_table_count = 0;
        g_sai_db_ptr->acl_db.acl_group_db[SAI_ACL_STAGE_EGRESS].group_id        = egress_acl_group_id;
        SX_LOG_NTC("Egress ACl Group created with group id[%d] \n", egress_acl_group_id);
    }

out:
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

/*
 *   Routine Description:
 *       Get Table Attributes
 *
 *      Arguments:
 *          [in] key - ACL Table Object Key
 *             [inout] value - Attribute Value
 *             [in] attr_index - Attribute Index in Attr List
 *             [inout] - Cache
 *             [in] arg - ACL Table Attribute
 *
 *         Return Values:
 *         SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */

static sai_status_t mlnx_acl_table_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t       status;
    sx_acl_id_t        acl_table_id;
    uint32_t           acl_table_index = 0;
    sx_acl_direction_t stage;

    SX_LOG_ENTER();

    assert((SAI_ACL_TABLE_ATTR_STAGE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_PRIORITY == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_SIZE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_GROUP_ID == (int64_t)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_TABLE, &acl_table_id, NULL))) {
        return status;
    }
    acl_table_index = acl_table_id;

    sai_db_read_lock();
    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_ATTR_STAGE:
        value->s32 = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].stage;
        break;

    case SAI_ACL_TABLE_ATTR_PRIORITY:
        value->u32 = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].priority;
        break;

    case SAI_ACL_TABLE_ATTR_SIZE:
        value->u32 = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].table_size;
        break;

    case SAI_ACL_TABLE_ATTR_GROUP_ID:
        stage = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].stage;
        if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP,
                                                               g_sai_db_ptr->acl_db.acl_group_db[stage].group_id, NULL,
                                                               &value->oid))) {
            goto out;
        }
        break;
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

/*
 *     Routine Description:
 *          Get Table Attributes
 *
 *           Arguments:
 *            [in] key - ACL Table Object Key
 *            [inout] value - Attribute Value
 *            [in] attr_index - Attribute Index in Attr List
 *            [inout] - Cache
 *            [in] arg - ACL Table Attribute
 *
 *           Return Values:
 *            SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */

static sai_status_t mlnx_acl_table_fields_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sx_status_t       ret_status;
    sai_status_t      status;
    sx_acl_key_t      keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    uint32_t          key_count = 0, key_id = 0;
    sx_acl_key_type_t key_handle;
    uint32_t          key_desc_index;
    uint32_t          acl_table_index, acl_table_id;

    SX_LOG_ENTER();

    assert((SAI_ACL_TABLE_ATTR_FIELD_START < (int64_t)arg) && ((int64_t)arg < SAI_ACL_TABLE_ATTR_FIELD_END));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_TABLE, &acl_table_id, NULL))) {
        return status;
    }
    acl_table_index = acl_table_id;

    sai_db_read_lock();
    key_handle = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type;

    switch ((int64_t)arg) {
#ifdef ACL_TODO
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6:
        key_id = FLEX_ACL_KEY_SIP_PART2;  /* key name more likely will be changed */
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6:
        key_id = FLEX_ACL_KEY_DIP_PART2;  /* key name more likely will be changed */
        break;

#endif /* ACL_TODO */
    case SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_DEI;
        break;

#ifdef ACL_TODO
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_INNER_DEI;
        break;
#endif

    case SAI_ACL_TABLE_ATTR_FIELD_DSCP:
        key_id = FLEX_ACL_KEY_DSCP;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_ECN:
        key_id = FLEX_ACL_KEY_ECN;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_TTL:
        key_id = FLEX_ACL_KEY_TTL;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS:
        key_id = FLEX_ACL_KEY_TCP_CONTROL;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS:
        SX_LOG_ERR(" Not supported in present phase \n");
        status = SAI_STATUS_NOT_SUPPORTED;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_TC:
        key_id = FLEX_ACL_KEY_SWITCH_PRIO;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC:
        key_id = FLEX_ACL_KEY_SMAC;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_DST_MAC:
        key_id = FLEX_ACL_KEY_DMAC;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IP:
        key_id = FLEX_ACL_KEY_SIP;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_DST_IP:
        key_id = FLEX_ACL_KEY_DIP;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IN_PORT:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID:
        key_id = FLEX_ACL_KEY_VLAN_ID;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_PCP;
        break;

#ifdef ACL_TODO
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID:
        key_id = FLEX_ACL_KEY_INNER_VLAN_ID;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_INNER_PCP;
        break;
#endif

    case SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT:
        key_id = FLEX_ACL_KEY_L4_SOURCE_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT:
        key_id = FLEX_ACL_KEY_L4_DESTINATION_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE:
        key_id = FLEX_ACL_KEY_ETHERTYPE;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL:
        key_id = FLEX_ACL_KEY_IP_PROTO;
        break;

#ifdef ACL_TODO
    case SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META:
        key_id = FLEX_ACL_KEY_USER_TOKEN;
        break;
#endif

    default:
        SX_LOG_ERR(" Invalid attribute to get\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (SX_STATUS_SUCCESS != (ret_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, keys, &key_count))) {
        SX_LOG_ERR(" Failed to get flex acl key in SDK - %s \n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    value->booldata = false;
    for (key_desc_index = 0; key_desc_index < key_count; key_desc_index++) {
        if (key_id == keys[key_desc_index]) {
            value->booldata = true;
            break;
        }
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_table_ip_and_tos_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sx_status_t       ret_status;
    sai_status_t      status;
    sx_acl_key_t      keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    uint32_t          key_count = 0, index = 0;
    sx_acl_key_type_t key_handle;
    uint32_t          key_desc_index;
    uint32_t          acl_table_index, acl_table_id;
    sx_acl_key_t      ip_type_keys[IP_TYPE_KEY_SIZE];
    sx_acl_key_t      ip_frag_keys[IP_FRAG_KEY_TYPE_SIZE];
    bool              is_key_type_present = false;
    bool              is_dscp_key_present = false, is_ecn_key_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TOS == (int64_t)arg));

    /* TODO: Uncomment ; when is_ip_v6 key is available */
    ip_type_keys[0] = FLEX_ACL_KEY_IP_OK;
    ip_type_keys[1] = FLEX_ACL_KEY_IS_IP_V4;
    ip_type_keys[2] = FLEX_ACL_KEY_IS_ARP;
    /* ip_type_keys[3] = FLEX_ACL_KEY_IS_IP_V6; */


    ip_frag_keys[0] = FLEX_ACL_KEY_IP_FRAGMENTED;
    ip_frag_keys[1] = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;


    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_TABLE, &acl_table_id, NULL))) {
        return status;
    }
    acl_table_index = acl_table_id;

    sai_db_read_lock();
    key_handle = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type;

    if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, keys, &key_count))) {
        SX_LOG_ERR(" Failed to get flex acl key in SDK - %s \n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IP:
        value->booldata = false;
        for (key_desc_index = 0; key_desc_index < key_count; key_desc_index++) {
            if (FLEX_ACL_KEY_SIP == keys[key_desc_index]) {
                value->booldata = true;
                break;
            }
        }
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_DST_IP:
        value->booldata = false;
        for (key_desc_index = 0; key_desc_index < key_count; key_desc_index++) {
            if (FLEX_ACL_KEY_DIP == keys[key_desc_index]) {
                value->booldata = true;
                break;
            }
        }

        break;

    case SAI_ACL_TABLE_ATTR_FIELD_TOS:
        for (key_desc_index = 0; key_desc_index < key_count; key_desc_index++) {
            if (FLEX_ACL_KEY_DSCP == keys[key_desc_index]) {
                is_dscp_key_present = true;
            }
            if (FLEX_ACL_KEY_ECN == keys[key_desc_index]) {
                is_ecn_key_present = true;
            }
        }
        if (is_ecn_key_present && is_dscp_key_present) {
            value->booldata = true;
        } else {
            value->booldata = false;
        }
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IP_TYPE:
        value->booldata = false;
        for (index = 0; index < IP_TYPE_KEY_SIZE; index++) {
            for (key_desc_index = 0; key_desc_index < key_count; key_desc_index++) {
                if (ip_type_keys[index] == keys[key_desc_index]) {
                    is_key_type_present = true;
                    break;
                }
            }
            if (is_key_type_present) {
                value->booldata = true;
                break;
            }
        }
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IP_FRAG:
        value->booldata = false;
        for (index = 0; index < IP_FRAG_KEY_TYPE_SIZE; index++) {
            for (key_desc_index = 0; key_desc_index < key_count; key_desc_index++) {
                if (ip_frag_keys[index] == keys[key_desc_index]) {
                    is_key_type_present = true;
                    break;
                }
            }
            if (is_key_type_present) {
                value->booldata = true;
                break;
            }
        }
        break;

    default:
        SX_LOG_ERR(" Invalid attribute to get\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}


static sai_status_t db_find_acl_entry_free_index(_Out_ uint32_t *free_index, _In_ uint32_t table_id)
{
    sai_status_t status;
    uint32_t     ii;
    bool         is_entry_index_free = false;

    if (NULL == free_index) {
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_ENTER();
    sai_db_write_lock();

    for (ii = 0; ii < MAX_ACL_ENTRY_NUM; ii++) {
        if (false == g_sai_db_ptr->acl_db.acl_table_db[table_id].acl_entry_db[ii].is_entry_allocated) {
            *free_index                                                                     = ii;
            g_sai_db_ptr->acl_db.acl_table_db[table_id].acl_entry_db[ii].is_entry_allocated = true;
            is_entry_index_free                                                             = true;
            status                                                                          = SAI_STATUS_SUCCESS;
            break;
        }
    }
    sai_db_sync();
    sai_db_unlock();

    if (!is_entry_index_free) {
        SX_LOG_ERR("ACL Entry Max Limit in ACL Table Reached\n");
        status = SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return status;
}


/*
 *     Routine Description:
 *         Get ACL Table Id and ACL Entry Index in ACL Table
 *
 *         Arguments:
 *           [in] acl_entry_id - ACL Entry Id
 *           [out] acl_table_id - ACL Table Id
 *             [in] attr_index - ACL Entry Index
 *
 *         Return Values:
 *          SAI_STATUS_SUCCESS on success
 *          SAI_STATUS_FAILURE on error
 */

static sai_status_t extract_acl_table_index_and_entry_index(_In_ uint32_t   acl_entry_id,
                                                            _Out_ uint32_t *acl_table_id,
                                                            _Out_ uint32_t *acl_entry_index)
{
    SX_LOG_ENTER();

    if ((NULL == acl_table_id) || (NULL == acl_entry_index)) {
        return SAI_STATUS_FAILURE;
    }

    *acl_table_id    = acl_entry_id >> 0x10;
    *acl_entry_index = acl_entry_id & 0xFFFF;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_acl_entry_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     acl_table_index, acl_entry_id, acl_entry_index;
    uint32_t     acl_table_size;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_TABLE_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_PRIORITY == (int64_t)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        return status;
    }

    sai_db_read_lock();
    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_TABLE_ID:
        if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE,
                                                               g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].
                                                               table_id, NULL, &value->oid))) {
            goto out;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_PRIORITY:
        acl_table_size = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].table_size;
        value->u32     = acl_table_size -
                         g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset;
        break;
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t fetch_flex_acl_rule_params_to_get(_In_ const sai_object_key_t     *key,
                                                      _Inout_ sx_flex_acl_flex_rule_t *flex_acl_rule_p)
{
    sx_status_t          ret_status;
    sai_status_t         status;
    sx_acl_region_id_t   region_id = 0;
    sx_acl_rule_offset_t rule_offset;
    sx_acl_key_type_t    key_handle;
    uint32_t             acl_entry_id, acl_entry_index;
    uint32_t             acl_table_index, flex_acl_rules_num = 1;

    if (NULL == flex_acl_rule_p) {
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_ENTER();
    memset(flex_acl_rule_p, 0, flex_acl_rules_num * sizeof(sx_flex_acl_flex_rule_t));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        return status;
    }

    sai_db_read_lock();

    rule_offset = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset;
    region_id   = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id;
    key_handle  = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type;
    if (SAI_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_init(key_handle,
                                                                      MAX_NUM_OF_ACTIONS, flex_acl_rule_p))) {
        SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(status));
        sai_db_unlock();
        return sdk_to_sai(ret_status);
    }

    if (SAI_STATUS_SUCCESS ==
        (ret_status =
             sx_api_acl_flex_rules_get(gh_sdk, region_id, &rule_offset, flex_acl_rule_p, &flex_acl_rules_num))) {
        if (flex_acl_rules_num == 0) {
            SX_LOG_ERR("The number of rules for region [%u] in SDK is zero - %s \n", region_id,
                       SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
    } else {
        SX_LOG_ERR("Failed to retrieve rules from region [%u] in SDK - %s\n", region_id, SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (SAI_STATUS_SUCCESS != status) {
        /* in case of error should deinit rule here */
        if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(flex_acl_rule_p))) {
            SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
        }
    }
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_mac_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                key_desc_index;
    bool                    is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == (int64_t)arg));

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        SX_LOG_EXIT();
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC:
        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_SMAC) {
                is_key_type_present = true;
                break;
            }
        }
        if (is_key_type_present) {
            memcpy(value->aclfield.data.mac,
                   &flex_acl_rule.key_desc_list_p[key_desc_index].key.smac,
                   sizeof(value->mac));
            memcpy(value->aclfield.mask.mac, &flex_acl_rule.key_desc_list_p[key_desc_index].mask.smac,
                   sizeof(value->mac));
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : SRC MAC \n");
        }

        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC:
        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_DMAC) {
                is_key_type_present = true;
                break;
            }
        }

        if (is_key_type_present) {
            memcpy(value->aclfield.data.mac,
                   &flex_acl_rule.key_desc_list_p[key_desc_index].key.dmac,
                   sizeof(value->mac));
            memcpy(value->aclfield.mask.mac, &flex_acl_rule.key_desc_list_p[key_desc_index].mask.dmac,
                   sizeof(value->mac));
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : DST MAC \n");
        }
        break;
    }

    if (SX_STATUS_SUCCESS != (status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return status;
}


static sai_status_t mlnx_acl_entry_ip_fields_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                key_id = 0, index, key_desc_index = 0;
    uint32_t                ip_frag_key_desc_index[IP_FRAG_KEY_TYPE_SIZE];
    bool                    is_key_type_present = false;
    bool                    is_ip_frag_key_id_present[IP_FRAG_KEY_TYPE_SIZE];
    sx_acl_key_t            ip_type_keys[IP_TYPE_KEY_SIZE];
    sx_acl_key_t            ip_frag_keys[IP_FRAG_KEY_TYPE_SIZE];
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_FRAG == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS == (int64_t)arg));

    memset(ip_frag_key_desc_index, 0, sizeof(ip_frag_key_desc_index));
    memset(is_ip_frag_key_id_present, 0, sizeof(is_ip_frag_key_id_present));

    /* TODO: Uncomment, ip_type_keys[3], when is_ip_v6 key is available */
    ip_type_keys[0] = FLEX_ACL_KEY_IP_OK;
    ip_type_keys[1] = FLEX_ACL_KEY_IS_IP_V4;
    ip_type_keys[2] = FLEX_ACL_KEY_IS_ARP;
    /* ip_type_keys[3] = FLEX_ACL_KEY_IS_IP_V6; */

    ip_frag_keys[0] = FLEX_ACL_KEY_IP_FRAGMENTED;
    ip_frag_keys[1] = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL:
        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_IP_PROTO) {
                is_key_type_present = true;
                break;
            }
        }
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_proto;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_proto;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : IP_PROTOCOL \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE:
        for (index = 0; index < IP_TYPE_KEY_SIZE; index++) {
            for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
                if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == ip_type_keys[index]) {
                    is_key_type_present = true;
                    key_id              = ip_type_keys[index];
                    break;
                }
            }
            if (is_key_type_present) {
                break;
            }
        }

        if (!is_key_type_present) {
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_ANY;
        } else {
            switch (key_id) {
            case FLEX_ACL_KEY_IP_OK:
                if (flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_ok) {
                    value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IP;
                } else {
                    value->aclfield.data.s32 = SAI_ACL_IP_TYPE_NON_IP;
                }
                break;

            case FLEX_ACL_KEY_IS_IP_V4:
                if (flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v4) {
                    value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IPv4ANY;
                } else {
                    value->aclfield.data.s32 = SAI_ACL_IP_TYPE_NON_IPv4;
                }
                break;

            /*
             *         case FLEX_ACL_KEY_IS_IP_V6:
             *         if ( flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v6 ){
             *         value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IPv6ANY;
             *         }
             *         else {
             *         value->aclfield.data.s32 = SAI_ACL_IP_TYPE_NON_IPv6;
             *         }
             *         break;
             */
            case FLEX_ACL_KEY_IS_ARP:
                if (flex_acl_rule.key_desc_list_p[key_desc_index].key.is_arp) {
                    value->aclfield.data.s32 = SAI_ACL_IP_TYPE_ARP;
                }
                break;
            }
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_IP_FRAG:
        for (index = 0; index < IP_FRAG_KEY_TYPE_SIZE; index++) {
            for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
                if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == ip_frag_keys[index]) {
                    is_ip_frag_key_id_present[index] = true;
                    ip_frag_key_desc_index[index]    = key_desc_index;
                    break;
                }
            }
        }

        if (is_ip_frag_key_id_present[INDEX_ZERO]) {
            if (is_ip_frag_key_id_present[INDEX_ONE]) {
                if (flex_acl_rule.key_desc_list_p[ip_frag_key_desc_index[INDEX_ZERO]].key.ip_fragmented) {
                    if (flex_acl_rule.key_desc_list_p[ip_frag_key_desc_index[INDEX_ONE]].key.ip_fragment_not_first) {
                        value->aclfield.data.s32 = SAI_ACL_IP_FRAG_NON_HEAD;
                    } else {
                        value->aclfield.data.s32 = SAI_ACL_IP_FRAG_HEAD;
                    }
                }
            } else {
                if (flex_acl_rule.key_desc_list_p[ip_frag_key_desc_index[INDEX_ZERO]].key.ip_fragmented) {
                    value->aclfield.data.s32 = SAI_ACL_IP_FRAG_ANY;
                } else {
                    value->aclfield.data.s32 = SAI_ACL_IP_FRAG_NON_FRAG;
                }
            }
        } else if (!is_ip_frag_key_id_present[INDEX_ZERO]) {
            if (is_ip_frag_key_id_present[INDEX_ONE]) {
                if (!flex_acl_rule.key_desc_list_p[ip_frag_key_desc_index[INDEX_ONE]].key.ip_fragment_not_first) {
                    value->aclfield.data.s32 = SAI_ACL_IP_FRAG_NON_FRAG_OR_HEAD;
                }
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : IP_FRAG \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS:
        SX_LOG_ERR(" IP Flags Getter Not Supported in this phase \n");
        status = SAI_STATUS_NOT_SUPPORTED;
        break;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                key_id         = 0;
    uint32_t                key_desc_index = 0;
    sx_ip_addr_t            ipaddr_data, ipaddr_mask;
    sai_ip_address_t        ip_address_data, ip_address_mask;
    bool                    is_key_type_present = true;
    sx_status_t             sx_status;

    SX_LOG_ENTER();


    memset(&ipaddr_data, 0, sizeof(ipaddr_data));
    memset(&ip_address_data, 0, sizeof(ip_address_data));
    memset(&ipaddr_mask, 0, sizeof(ipaddr_mask));
    memset(&ip_address_mask, 0, sizeof(ip_address_mask));

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == (int64_t)arg));

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
#ifdef ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
        key_id = FLEX_ACL_KEY_SIP_PART2;     /* key name more likely will be changed */
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
        key_id = FLEX_ACL_KEY_DIP_PART2
#endif /* ACL_TODO */
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
        key_id = FLEX_ACL_KEY_SIP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
        key_id = FLEX_ACL_KEY_DIP;
        break;
    }
    for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    switch ((int64_t)arg) {
#ifdef ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
        /* Searched key was SIP_PART2. Prev key is SIP */
        if (is_key_type_present) {
            key_desc_index--;
            ipaddr_data.version                = SX_IP_VERSION_IPV6;
            ipaddr_mask.version                = SX_IP_VERSION_IPV6;
            ipaddr_data.addr.ipv6.s6_addr32[0] = flex_acl_rule.key_desc_list_p[key_desc_index].key.sip;
            ipaddr_mask.addr.ipv6.s6_addr32[0] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip;
            key_desc_index++;
            ipaddr_data.addr.ipv6.s6_addr32[1] = flex_acl_rule.key_desc_list_p[key_desc_index].key.sip_part2;
            ipaddr_mask.addr.ipv6.s6_addr32[1] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip_part2;
            key_desc_index++;
            ipaddr_data.addr.ipv6.s6_addr32[2] = flex_acl_rule.key_desc_list_p[key_desc_index].key.sip_part3;
            ipaddr_mask.addr.ipv6.s6_addr32[2] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip_part3;
            key_desc_index++;
            ipaddr_data.addr.ipv6.s6_addr32[3] = flex_acl_rule.key_desc_list_p[key_desc_index].key.sip_part4;
            ipaddr_mask.addr.ipv6.s6_addr32[3] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip_part4;

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&ipaddr_data, &ip_address_data))) {
                return status;
            }
            memcpy(&value->aclfield.data.ip6, &(ip_address_data.addr.ip6), sizeof(value->aclfield.data.ip6));

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&ipaddr_mask, &ip_address_mask))) {
                return status;
            }
            memcpy(&value->aclfield.mask.ip6, &(ip_address_mask.addr.ip6), sizeof(value->aclfield.data.ip6));
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : SRC_IPv6 \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
        if (is_key_type_present) {
            key_desc_index--;
            ipaddr_data.version                = SX_IP_VERSION_IPV6;
            ipaddr_mask.version                = SX_IP_VERSION_IPV6;
            ipaddr_data.addr.ipv6.s6_addr32[0] = flex_acl_rule.key_desc_list_p[key_desc_index].key.dip;
            ipaddr_mask.addr.ipv6.s6_addr32[0] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip;
            key_desc_index++;
            ipaddr_data.addr.ipv6.s6_addr32[1] = flex_acl_rule.key_desc_list_p[key_desc_index].key.dip_part2;
            ipaddr_mask.addr.ipv6.s6_addr32[1] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip_part2;
            key_desc_index++;
            ipaddr_data.addr.ipv6.s6_addr32[2] = flex_acl_rule.key_desc_list_p[key_desc_index].key.dip_part3;
            ipaddr_mask.addr.ipv6.s6_addr32[2] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip_part3;
            key_desc_index++;
            ipaddr_data.addr.ipv6.s6_addr32[3] = flex_acl_rule.key_desc_list_p[key_desc_index].key.dip_part4;
            ipaddr_mask.addr.ipv6.s6_addr32[3] = flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip_part4;

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&ipaddr_data, &ip_address_data))) {
                return status;
            }
            memcpy(&value->aclfield.data.ip6, &(ip_address_data.addr.ip6), sizeof(value->aclfield.data.ip6));

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&ipaddr_mask, &ip_address_mask))) {
                return status;
            }
            memcpy(&value->aclfield.mask.ip6, &(ip_address_mask.addr.ip6), sizeof(value->aclfield.mask.ip6));
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : DST_IPv6 \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

#endif /* ACL_TODO */
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
        if (is_key_type_present) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sip,
                                                               &ip_address_data))) {
                return status;
            }

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip,
                                                               &ip_address_mask))) {
                return status;
            }
            memcpy(&value->aclfield.data.ip4, &ip_address_data.addr.ip4, \
                   sizeof(value->ipaddr.addr.ip4));
            memcpy(&value->aclfield.mask.ip4, &ip_address_mask.addr.ip4, \
                   sizeof(value->ipaddr.addr.ip4));
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : SRC_IP \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
        if (is_key_type_present) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dip,
                                                               &ip_address_data))) {
                return status;
            }

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip,
                                                               &ip_address_mask))) {
                return status;
            }

            memcpy(&value->aclfield.data.ip4, &ip_address_data.addr.ip4, \
                   sizeof(value->ipaddr.addr.ip4));
            memcpy(&value->aclfield.mask.ip4, &ip_address_mask.addr.ip4, \
                   sizeof(value->ipaddr.addr.ip4));
        } else {
            SX_LOG_ERR("Invalid Attribute to Get : DST_IP \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

    SX_LOG_EXIT();
    return status;
}


static sai_status_t mlnx_acl_entry_vlan_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_acl_key_t            key_id              = 0;
    uint8_t                 key_desc_index      = 0;
    bool                    is_key_type_present = false;
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == (int64_t)arg) ||
/*#ifdef ACL_TODO
 *          (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID == (int64_t)arg) ||
 *          (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == (int64_t)arg) ||
 *          (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == (int64_t)arg) ||
 #endif*/
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == (int64_t)arg));

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
        key_id = FLEX_ACL_KEY_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_DEI;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_PCP;
        break;

#ifdef ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
        key_id = FLEX_ACL_KEY_INNER_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_INNER_DEI;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_INNER_PCP;
        break;
#endif
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
        if (is_key_type_present) {
            value->aclfield.data.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].key.vlan_id;
            value->aclfield.mask.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.vlan_id;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : OUTER VID \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

#ifdef ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
        if (is_key_type_present) {
            value->aclfield.data.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_vlan_id;
            value->aclfield.mask.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_vlan_id;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : INNER VID \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI:
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_pcp;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_pcp;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : INNER VLAN PRIORITY \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI:
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_dei;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_dei;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : INNER VLAN CFI \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
#endif /* ACL_TODO */

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI:
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.pcp;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.pcp;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : OUTER VLAN PRIORITY \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI:
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.dei;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.dei;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : OUTER VLAN CFI \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ports_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sx_status_t              ret_status;
    sai_status_t             status;
    sx_acl_region_id_t       region_id       = 0;
    sx_acl_rule_offset_t    *offsets_list_p  = NULL;
    sx_flex_acl_flex_rule_t *flex_acl_rule_p = NULL;
    sx_acl_key_t             key_id          = 0;
    uint32_t                 offsets_list_index;
    uint32_t                 flex_acl_rules_num = 1, flex_rule_index;
    uint32_t                 acl_entry_id, acl_entry_index;
    uint32_t                 rule_offset, acl_table_index;
    bool                     is_key_type_present = false;
    uint8_t                  key_desc_index      = 0;
    uint32_t                 ii                  = 0;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg));


    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        return status;
    }

    sai_db_read_lock();

    rule_offset        = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset;
    region_id          = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id;
    flex_acl_rules_num = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules;


    if (value->aclfield.data.objlist.count < flex_acl_rules_num) {
        value->aclfield.data.objlist.count = flex_acl_rules_num;
        status                             = SAI_STATUS_BUFFER_OVERFLOW;
        SX_LOG_ERR(" Re-allocate list size as list size is not large enough \n");
        goto out;
    } else if (value->aclfield.data.objlist.count > flex_acl_rules_num) {
        value->aclfield.data.objlist.count = flex_acl_rules_num;
    }

    flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);
    if (flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for flex_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(flex_acl_rule_p, 0, sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);

    offsets_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for flex_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    memset(offsets_list_p, 0, sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);

    for (offsets_list_index = 0; offsets_list_index < flex_acl_rules_num; offsets_list_index++) {
        offsets_list_p[offsets_list_index] = rule_offset + offsets_list_index;
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        ret_status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                               MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[ii]);
        if (SX_STATUS_SUCCESS != ret_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(ret_status));
            status             = sdk_to_sai(ret_status);
            flex_acl_rules_num = ii;
            goto out_deinit;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        (ret_status =
             sx_api_acl_flex_rules_get(gh_sdk, region_id, offsets_list_p, flex_acl_rule_p, &flex_acl_rules_num))) {
        if (flex_acl_rules_num == 0) {
            SX_LOG_ERR("Number of rules at start offset [%d] from region [%u] in SDK is zero - %s\n",
                       rule_offset,
                       region_id,
                       SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out_deinit;
        }
    } else {
        SX_LOG_ERR("Failed to retrieve rules from region [%u] in SDK - %s\n", region_id, SX_STATUS_MSG(status));
        status = sdk_to_sai(ret_status);
        goto out_deinit;
    }


    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
        if (!is_key_type_present) {
            SX_LOG_ERR(" Invalid Attribute to get : IN_PORTS \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out_deinit;
        }

        for (flex_rule_index = 0; flex_rule_index < flex_acl_rules_num; flex_rule_index++) {
            if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                                                   flex_acl_rule_p[flex_rule_index].key_desc_list_p[
                                                                       key_desc_index].key.src_port, NULL,
                                                                   &value->aclfield.data.objlist.list[flex_rule_index])))
            {
                goto out_deinit;
            }
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
        if (!is_key_type_present) {
            SX_LOG_ERR(" Invalid Attribute to get : OUT_PORTS \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out_deinit;
        }
        for (flex_rule_index = 0; flex_rule_index < flex_acl_rules_num; flex_rule_index++) {
            if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                                                   flex_acl_rule_p[flex_rule_index].key_desc_list_p[
                                                                       key_desc_index].key.dst_port, NULL,
                                                                   &value->aclfield.data.objlist.list[flex_rule_index])))
            {
                goto out_deinit;
            }
        }
        break;
    }

out_deinit:
    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
            SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
        }
    }

out:
    if (flex_acl_rule_p) {
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}


static sai_status_t mlnx_acl_entry_port_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_acl_key_t            key_id = 0;
    uint32_t                key_desc_index;
    bool                    is_key_type_present = false;
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == (int64_t)arg));

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT:
        key_id = FLEX_ACL_KEY_L4_SOURCE_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT:
        key_id = FLEX_ACL_KEY_L4_DESTINATION_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT:
        if (is_key_type_present) {
            value->aclfield.data.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].key.l4_source_port;
            value->aclfield.mask.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.l4_source_port;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : L4 SRC PORT \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT:
        if (is_key_type_present) {
            value->aclfield.data.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].key.l4_destination_port;
            value->aclfield.mask.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.l4_destination_port;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : L4 DST PORT \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        if (is_key_type_present) {
            if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                                                   flex_acl_rule.key_desc_list_p[key_desc_index].key.
                                                                   src_port, NULL, &value->aclfield.data.oid))) {
                goto out;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get :  IN PORT \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        if (is_key_type_present) {
            if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                                                   flex_acl_rule.key_desc_list_p[key_desc_index].key.
                                                                   dst_port, NULL, &value->aclfield.data.oid))) {
                goto out;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : OUT PORT \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

out:
    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_fields_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                key_desc_index, key_id = 0;
    bool                    is_key_type_present = false;
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ADMIN_STATE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == (int64_t)arg) ||
/*#ifdef ACL_TODO
 *           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == (int64_t)arg)||
 #endif*/
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == (int64_t)arg));

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    if (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == (int64_t)arg) {
        key_id = FLEX_ACL_KEY_ETHERTYPE;
    } else if (SAI_ACL_ENTRY_ATTR_FIELD_TTL == (int64_t)arg) {
        key_id = FLEX_ACL_KEY_TTL;
    } else if (SAI_ACL_ENTRY_ATTR_FIELD_TC == (int64_t)arg) {
        key_id = FLEX_ACL_KEY_SWITCH_PRIO;
    }
#ifdef ACL_TODO
    else if (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == (int64_t)arg) {
        key_id = FLEX_ACL_KEY_USER_TOKEN;
    }
#endif
    else if (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == (int64_t)arg) {
        key_id = FLEX_ACL_KEY_TCP_CONTROL;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ADMIN_STATE:
        value->booldata = flex_acl_rule.valid;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE:
        if (is_key_type_present) {
            value->aclfield.data.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].key.ethertype;
            value->aclfield.mask.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.ethertype;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : ETHER TYPE \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.ttl;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.ttl;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : TTL \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

#ifdef ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
        if (is_key_type_present) {
            value->aclfield.data.u32 = flex_acl_rule.key_desc_list_p[key_desc_index].key.user_token;
            value->aclfield.mask.u32 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.user_token;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : ACL User Meta \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
#endif

    case SAI_ACL_ENTRY_ATTR_FIELD_TC:
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.switch_prio;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.switch_prio;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : TC \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS:
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.tcp_control;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.tcp_control;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : TCP FLAGS \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_packet_action_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t                 status;
    sx_flex_acl_flex_rule_t      flex_acl_rule;
    uint32_t                     flex_action_index;
    uint32_t                     forward_action_index = 0, trap_action_index = 0;
    uint32_t                     action_type;
    sx_flex_acl_forward_action_t forward_action;
    sx_flex_acl_trap_action_t    trap_action;
    bool                         is_trap_action_present    = false;
    bool                         is_forward_action_present = false;
    sx_status_t                  sx_status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule.action_count - 1; flex_action_index++) {
        action_type = flex_acl_rule.action_list_p[flex_action_index].type;
        if (action_type == SX_FLEX_ACL_ACTION_TRAP) {
            is_trap_action_present = true;
            trap_action_index      = flex_action_index;
        }
        if (action_type == SX_FLEX_ACL_ACTION_FORWARD) {
            is_forward_action_present = true;
            forward_action_index      = flex_action_index;
            break;
        }
    }

    if (!is_trap_action_present && !is_forward_action_present) {
        SX_LOG_ERR(" Invalid Attribute to Get : PACKET ACTION \n");
        goto out;
    } else if (is_forward_action_present && !is_trap_action_present) {
        forward_action = flex_acl_rule.action_list_p[forward_action_index].fields.action_forward.action;
        if (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_DROP;
        } else if (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_FORWARD;
        }
    } else if (!is_forward_action_present && is_trap_action_present) {
        trap_action = flex_acl_rule.action_list_p[trap_action_index].fields.action_trap.action;
        if (trap_action == SX_ACL_TRAP_ACTION_TYPE_TRAP) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_COPY;
        } else if (trap_action == SX_ACL_TRAP_ACTION_TYPE_DISCARD) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_COPY_CANCEL;
        }
    }
    /* if trap action and forward action both are present */
    else {
        trap_action    = flex_acl_rule.action_list_p[trap_action_index].fields.action_trap.action;
        forward_action = flex_acl_rule.action_list_p[forward_action_index].fields.action_forward.action;

        if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_TRAP) &&
            (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD)) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_LOG;
        } else if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_TRAP) &&
                   (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD)) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_TRAP;
        } else if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_DISCARD) &&
                   (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD)) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_DENY;
        } else if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_DISCARD) &&
                   (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD)) {
            value->aclaction.parameter.s32 = SAI_PACKET_ACTION_TRANSIT;
        }
    }

out:
    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sx_status_t             ret_status;
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                acl_entry_id;
    uint32_t                acl_table_index, acl_entry_index, counter_id;
    sx_acl_pbs_entry_t      pbs_entry;
    sx_swid_t               swid_id                = 0;
    bool                    is_action_type_present = false;
    sx_acl_pbs_id_t         action_id              = 0, action_index, pbs_index = 0;
    sx_port_id_t            redirect_port;
    uint32_t                policer_db_entry_index;
    sai_object_id_t         sai_policer;
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_COUNTER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == (int64_t)arg));


    memset(&pbs_entry, 0, sizeof(sx_acl_pbs_entry_t));
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }
    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        action_id = SX_FLEX_ACL_ACTION_PBS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
        action_id = SX_FLEX_ACL_ACTION_POLICER;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC:
        action_id = SX_FLEX_ACL_ACTION_SET_PRIO;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_COUNTER:
        action_id = SX_FLEX_ACL_ACTION_COUNTER;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP:
        action_id = SX_FLEX_ACL_ACTION_SET_DSCP;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR:
        action_id = SX_FLEX_ACL_ACTION_SET_COLOR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN:
        action_id = SX_FLEX_ACL_ACTION_SET_ECN;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA:
        action_id = SX_FLEX_ACL_ACTION_SET_USER_TOKEN;
        break;

    default:
        SX_LOG_ERR(" Invalid Attrib to get /n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }


    for (action_index = 0; action_index < flex_acl_rule.action_count; action_index++) {
        if (flex_acl_rule.action_list_p[action_index].type == action_id) {
            is_action_type_present = true;
            break;
        }
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        if (is_action_type_present) {
            pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_UNICAST;
            pbs_entry.log_ports  = &redirect_port;
            pbs_entry.port_num   = 1;
            pbs_index            = flex_acl_rule.action_list_p[action_index].fields.action_pbs.pbs_id;

            if (SAI_STATUS_SUCCESS !=
                (ret_status =
                     sx_api_acl_policy_based_switching_get(gh_sdk, SX_ACCESS_CMD_GET, swid_id, pbs_index,
                                                           &pbs_entry))) {
                SX_LOG_ERR("failed to get UC PBS in SDK  %s.\n", SX_STATUS_MSG(ret_status));
                status = sdk_to_sai(ret_status);
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_create_object(SAI_OBJECT_TYPE_PORT, redirect_port, NULL, &value->aclaction.parameter.oid))) {
                goto out;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Redirect \n");
        }
        break;


    case SAI_ACL_ENTRY_ATTR_ACTION_COUNTER:
        sai_db_read_lock();
        if (is_action_type_present) {
            counter_id = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].counter_id;
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_id, NULL,
                                        &value->aclaction.parameter.oid))) {
                sai_db_unlock();
                goto out;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Counter \n");
        }
        sai_db_unlock();
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
        if (is_action_type_present) {
            sai_db_read_lock();
            if (SAI_STATUS_SUCCESS !=
                (status =
                     db_find_sai_policer_entry_ind(flex_acl_rule.action_list_p[action_index].fields.action_policer.
                                                   policer_id,
                                                   &policer_db_entry_index))) {
                SX_LOG_ERR("Failed to obtain sai_policer from sx_policer:0x%" PRIx64 "for acl. err:%d.\n",
                           flex_acl_rule.action_list_p[action_index].fields.action_policer.policer_id,
                           status);
            } else if (SAI_STATUS_SUCCESS !=
                       (status =
                            mlnx_create_object(SAI_OBJECT_TYPE_POLICER, policer_db_entry_index, NULL, &sai_policer))) {
                SX_LOG_ERR("Internal error while creating the policer.\n");
            }
            sai_db_unlock();
            value->aclaction.parameter.oid = sai_policer;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Set Policer \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC:
        if (is_action_type_present) {
            value->aclaction.parameter.u8 = flex_acl_rule.action_list_p[action_index].fields.action_set_prio.prio_val;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Set TC \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP:
        if (is_action_type_present) {
            value->aclaction.parameter.u8 = flex_acl_rule.action_list_p[action_index].fields.action_set_dscp.dscp_val;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Set DSCP \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR:
        if (is_action_type_present) {
            value->aclaction.parameter.s32 =
                flex_acl_rule.action_list_p[action_index].fields.action_set_color.color_val;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Set Color \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN:
        if (is_action_type_present) {
            value->aclaction.parameter.u8 = flex_acl_rule.action_list_p[action_index].fields.action_set_ecn.ecn_val;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Set Ecn \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA:
        if (is_action_type_present) {
            value->aclaction.parameter.u32 =
                flex_acl_rule.action_list_p[action_index].fields.action_set_user_token.user_token;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Set Acl Meta Data \n");
        }
        break;
    }
out:
    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_tos_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint8_t                 key_desc_index;
    bool                    is_key_type_present = false, is_key_id_two_present = false;
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TOS == (int64_t)arg));

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_DSCP:
        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_DSCP) {
                is_key_type_present = true;
                break;
            }
        }
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.dscp;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.dscp;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : DSCP \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ECN:
        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_ECN) {
                is_key_type_present = true;
                break;
            }
        }
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.ecn;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.ecn;
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : ECN \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TOS:
        value->aclfield.data.u8 = 0;      /* Initialise the value */

        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_ECN) {
                is_key_type_present = true;
                break;
            }
        }
        if (is_key_type_present) {
            value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.ecn;
            value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.ecn;
        }

        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_DSCP) {
                is_key_id_two_present = true;
                break;
            }
        }
        if (is_key_id_two_present) {
            value->aclfield.data.u8 = value->aclfield.data.u8 +
                                      (flex_acl_rule.key_desc_list_p[key_desc_index].key.dscp << 0x02);
            value->aclfield.mask.u8 = value->aclfield.mask.u8 +
                                      (flex_acl_rule.key_desc_list_p[key_desc_index].mask.dscp << 0x02);
        }

        if (!is_key_type_present && !is_key_id_two_present) {
            SX_LOG_ERR(" Invalid Attribute to get : TOS \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_vlan_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    sai_status_t                   status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t        flex_acl_rule;
    sx_flex_acl_flex_action_type_t action_type            = 0;
    uint8_t                        flex_action_index      = 0;
    bool                           is_action_type_present = false;
    sx_status_t                    sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI == (int64_t)arg));

    memset(&flex_acl_rule, 0, sizeof(sx_flex_acl_flex_rule_t));
    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID:
        action_type = SX_FLEX_ACL_ACTION_SET_INNER_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID:
        action_type = SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI:
        action_type = SX_FLEX_ACL_ACTION_SET_INNER_VLAN_PRI;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI:
        action_type = SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_PRI;
        break;
    }
    for (flex_action_index = 0; flex_action_index < flex_acl_rule.action_count; flex_action_index++) {
        if (flex_acl_rule.action_list_p[flex_action_index].type == action_type) {
            is_action_type_present = true;
            break;
        }
    }


    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID:
        if (is_action_type_present) {
            value->aclaction.parameter.u16 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_id.vlan_id;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Inner Vlan Id\n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI:
        if (is_action_type_present) {
            value->aclaction.parameter.u8 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_prio.pcp;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Inner Vlan Pri\n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID:
        if (is_action_type_present) {
            value->aclaction.parameter.u16 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_id.vlan_id;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Outer Vlan Id\n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI:
        if (is_action_type_present) {
            value->aclaction.parameter.u8 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_prio.pcp;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Outer Vlan Pri\n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mirror_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                acl_entry_id, acl_table_index;
    uint8_t                 acl_direction          = SAI_ACL_STAGE_INGRESS;
    uint8_t                 flex_action_index      = 0;
    bool                    is_action_type_present = false;
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == (int64_t)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
        acl_direction = SAI_ACL_STAGE_INGRESS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
        acl_direction = SAI_ACL_STAGE_EGRESS;
        break;
    }

    /* Only 1 session ID is returned through getter */
    if (value->aclfield.data.objlist.count > 1) {
        value->aclfield.data.objlist.count = 1;
    }
    sai_db_read_lock();
    acl_table_index = acl_entry_id >> 0x10;
    if (g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].stage != acl_direction) {
        SX_LOG_ERR(" Invalid Attribute to Get : Action Mirror \n");
        status = SAI_STATUS_FAILURE;
        sai_db_unlock();
        goto out;
    }

    sai_db_unlock();
    for (flex_action_index = 0; flex_action_index < flex_acl_rule.action_count; flex_action_index++) {
        if (flex_acl_rule.action_list_p[flex_action_index].type == SX_FLEX_ACL_ACTION_MIRROR) {
            is_action_type_present = true;
            break;
        }
    }

    if (is_action_type_present) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_MIRROR,
                                                               flex_acl_rule.action_list_p[flex_action_index].fields.
                                                               action_mirror.session_id, NULL,
                                                               &value->aclaction.parameter.objlist.list[0]))) {
            goto out;
        }
    } else {
        SX_LOG_ERR(" Invalid Attribute to Get :  ACTION MIRROR \n");
        status = SAI_STATUS_NOT_SUPPORTED;
    }

out:
    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mac_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t                   status;
    sx_flex_acl_flex_rule_t        flex_acl_rule;
    sx_flex_acl_flex_action_type_t action_type            = 0;
    uint8_t                        flex_action_index      = 0;
    bool                           is_action_type_present = false;
    sx_status_t                    sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC == (int64_t)arg));

    if (SAI_STATUS_SUCCESS != (status = fetch_flex_acl_rule_params_to_get(key, &flex_acl_rule))) {
        return status;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC:
        action_type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC:
        action_type = SX_FLEX_ACL_ACTION_SET_DST_MAC;
        break;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule.action_count; flex_action_index++) {
        if (flex_acl_rule.action_list_p[flex_action_index].type == action_type) {
            is_action_type_present = true;
            break;
        }
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC:
        if (is_action_type_present) {
            memcpy(value->aclaction.parameter.mac,
                   &flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac, \
                   sizeof(value->aclaction.parameter.mac));
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Set SRC MAC\n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC:
        if (is_action_type_present) {
            memcpy(value->aclaction.parameter.mac,
                   &flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dst_mac.mac, \
                   sizeof(value->aclaction.parameter.mac));
        } else {
            SX_LOG_ERR(" Invalid Action to Get :DST MAC\n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t fetch_flex_acl_rule_params_to_set(_In_ const sai_object_key_t      *key,
                                                      _Inout_ sx_flex_acl_flex_rule_t **flex_acl_rule_p,
                                                      _Inout_ sx_acl_rule_offset_t    **offsets_list_p,
                                                      _Inout_ sx_acl_region_id_t       *region_id,
                                                      _Inout_ uint32_t                 *rules_num)
{
    sx_status_t               ret_status;
    sai_status_t              status;
    sx_flex_acl_rule_offset_t rule_offset;
    uint32_t                  acl_entry_id, acl_entry_index;
    uint32_t                  acl_table_index, offset_index;
    uint32_t                  flex_acl_rules_num;
    uint32_t                  ii = 0;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        return status;
    }
    flex_acl_rules_num = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules;
    rule_offset        = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset;
    *region_id         = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id;
    *rules_num         = flex_acl_rules_num;

    *flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);
    if (*flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(*flex_acl_rule_p, 0, sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        ret_status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                               MAX_NUM_OF_ACTIONS, (*flex_acl_rule_p) + ii);
        if (SX_STATUS_SUCCESS != ret_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(ret_status));
            status             = sdk_to_sai(ret_status);
            flex_acl_rules_num = ii;
            goto out;
        }
    }


    *offsets_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);
    if (*offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(*offsets_list_p, 0, sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);

    for (offset_index = 0; offset_index < flex_acl_rules_num; offset_index++) {
        (*offsets_list_p)[offset_index] = rule_offset + offset_index;
    }

    if (SAI_STATUS_SUCCESS ==
        (ret_status =
             sx_api_acl_flex_rules_get(gh_sdk, *region_id, *offsets_list_p, *flex_acl_rule_p, &flex_acl_rules_num))) {
        if (0 == flex_acl_rules_num) {
            SX_LOG_ERR("Number of rules at start offset [%d] from region [%u] in SDK - %s\n",
                       rule_offset,
                       *region_id,
                       SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
    } else {
        SX_LOG_ERR("Failed to retrieve rules from region [%u] in SDK - %s\n", *region_id, SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (SAI_STATUS_SUCCESS != status) {
        if (*flex_acl_rule_p) {
            for (ii = 0; ii < flex_acl_rules_num; ii++) {
                if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(*flex_acl_rule_p + ii))) {
                    SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
                }
            }
            free(*flex_acl_rule_p);
        }
        if (*offsets_list_p) {
            free(*offsets_list_p);
        }
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_priority_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sx_status_t              ret_status;
    sai_status_t             status;
    sx_acl_region_id_t       region_id           = 0;
    sx_acl_rule_offset_t    *offsets_list_p      = NULL;
    sx_flex_acl_flex_rule_t *delete_rules_list_p = NULL, *rules_list_p = NULL;
    uint32_t                 flex_acl_rules_num  = 0,  acl_entry_id, acl_table_size = 0;
    uint32_t                 offset_index, acl_entry_index, acl_table_index;
    uint32_t                 ii = 0;

    SX_LOG_ENTER();

    sai_db_write_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &rules_list_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rules params \n");
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        goto out;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        goto out;
    }
    acl_table_size = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].table_size;

    if ((value->u32 <= 0) || (value->u32 > acl_table_size)) {
        SX_LOG_ERR(" priority %u out of range (%u,%u)\n", value->u32, 1, acl_table_size);
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    delete_rules_list_p = (sx_flex_acl_flex_rule_t*)malloc(flex_acl_rules_num * sizeof(sx_flex_acl_flex_rule_t));
    if (delete_rules_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    memcpy(delete_rules_list_p, rules_list_p, sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);

    /* Delete the rules at previous start offset */
    for (offset_index = 0; offset_index < flex_acl_rules_num; offset_index++) {
        offsets_list_p[offset_index] = offsets_list_p[0] + offset_index;
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_DELETE, region_id, offsets_list_p, delete_rules_list_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to delete rules from region [%u] in SDK - %s.\n", region_id, SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    for (offset_index = 0; offset_index < flex_acl_rules_num; offset_index++) {
        offsets_list_p[offset_index] = acl_table_size - value->u32 + offset_index;
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, rules_list_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }
    /* Update New value offset in D.B */
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset = acl_table_size -
                                                                                              value->u32;

out:
    if (delete_rules_list_p) {
        free(delete_rules_list_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    if (rules_list_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&rules_list_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(rules_list_p);
    }

    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_mac_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    uint32_t                   ii, flex_acl_rules_num = 0;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    sx_acl_key_t               key_id              = 0;
    bool                       is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == (int64_t)arg));

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params\n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC:
        key_id = FLEX_ACL_KEY_SMAC;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC:
        key_id = FLEX_ACL_KEY_DMAC;
        break;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC:
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.smac, value->aclfield.data.mac, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.smac));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.smac, value->aclfield.mask.mac, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.smac));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SMAC;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC:
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dmac, value->aclfield.data.mac, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dmac));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dmac, value->aclfield.mask.mac, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dmac));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DMAC;
            break;
        }
        if (!is_key_type_present) {
            flex_acl_rule_p[ii].key_desc_count++;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }
out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }

        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_fields_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0;
    uint32_t                   index, ii, key_desc_index;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    bool                       is_key_type_present = false;
    sx_acl_key_t               ip_type_keys[IP_TYPE_KEY_SIZE];

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS == (int64_t)arg));

    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    /* TODO: Uncomment; when is_ip_v6 key is available */
    ip_type_keys[0] = FLEX_ACL_KEY_IP_OK;
    ip_type_keys[1] = FLEX_ACL_KEY_IS_IP_V4;
    ip_type_keys[2] = FLEX_ACL_KEY_IS_ARP;
    /* ip_type_keys[3] = FLEX_ACL_KEY_IS_IP_V6;*/

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS:
            SX_LOG_ERR(" Not supported in present phase \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        /*
         *        flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_flags = value->aclfield.data.u8;
         *              flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_flags = value->aclfield.data.u8;
         *              flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_IP_FLAGS;
         *              break;
         *                                                                                                      */

        case SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL:
            for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
                if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_IP_PROTO) {
                    is_key_type_present = true;
                    break;
                }
            }
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_proto  = value->aclfield.data.u8;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_proto = value->aclfield.mask.u8;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_IP_PROTO;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE:
            for (index = 0; index < IP_TYPE_KEY_SIZE; index++) {
                for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
                    if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == ip_type_keys[index]) {
                        is_key_type_present = true;
                        break;
                    }
                }
                if (is_key_type_present) {
                    break;
                }
            }
            /* Remove the key from SDK if ip type is set to ANY */
            if (SAI_ACL_IP_TYPE_ANY == value->aclfield.data.s32) {
                if (is_key_type_present) {
                    for (; key_desc_index < flex_acl_rule_p[ii].key_desc_count - 1; key_desc_index++) {
                        memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index],
                               &flex_acl_rule_p[ii].key_desc_list_p[key_desc_index + 1], \
                               sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index]));
                    }
                    flex_acl_rule_p[ii].key_desc_count--;
                }
            } else if (SAI_ACL_IP_TYPE_IP == value->aclfield.data.s32) {
                if (!is_key_type_present) {
                    flex_acl_rule_p[ii].key_desc_count++;
                }
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_ok  = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_ok = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id     = FLEX_ACL_KEY_IP_OK;
            } else if (SAI_ACL_IP_TYPE_NON_IP == value->aclfield.data.s32) {
                if (!is_key_type_present) {
                    flex_acl_rule_p[ii].key_desc_count++;
                }
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_ok  = false;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_ok = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id     = FLEX_ACL_KEY_IP_OK;
            } else if (SAI_ACL_IP_TYPE_IPv4ANY == value->aclfield.data.s32) {
                if (!is_key_type_present) {
                    flex_acl_rule_p[ii].key_desc_count++;
                }
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.is_ip_v4  = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.is_ip_v4 = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_IS_IP_V4;
            } else if (SAI_ACL_IP_TYPE_NON_IPv4 == value->aclfield.data.s32) {
                if (!is_key_type_present) {
                    flex_acl_rule_p[ii].key_desc_count++;
                }
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.is_ip_v4  = false;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.is_ip_v4 = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_IS_IP_V4;
            } else if (SAI_ACL_IP_TYPE_IPv6ANY == value->aclfield.data.s32) {
                SX_LOG_ERR(" Not supported in present phase \n");
                status = SAI_STATUS_NOT_SUPPORTED;
                goto out;

                /*
                 *  if( !is_key_type_present){
                 *  flex_acl_rule_p[ii].key_desc_count++;
                 *  }
                 *
                 *  flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.is_ip_v6 = 1;
                 *  flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.is_ip_v6 = 0xFF;
                 *  flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_IS_IP_V6;
                 */
            } else if (SAI_ACL_IP_TYPE_NON_IPv6 == value->aclfield.data.s32) {
                SX_LOG_ERR(" Not supported in present phase \n");
                status = SAI_STATUS_NOT_SUPPORTED;
                goto out;

                /*
                 *  if( !is_key_type_present){
                 *   flex_acl_rule_p[ii].key_desc_count++;
                 *  }
                 *
                 *  flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.is_ip_v6 = 0;
                 *  flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.is_ip_v6 = 0xFF;
                 *  flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_IS_IP_V6;
                 */
            } else if (SAI_ACL_IP_TYPE_ARP == value->aclfield.data.s32) {
                if (!is_key_type_present) {
                    flex_acl_rule_p[ii].key_desc_count++;
                }
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.is_arp  = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.is_arp = true;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id      = FLEX_ACL_KEY_IS_ARP;
            } else if ((SAI_ACL_IP_TYPE_ARP_REQUEST == value->aclfield.data.s32) ||
                       (SAI_ACL_IP_TYPE_ARP_REPLY == value->aclfield.data.s32)) {
                SX_LOG_ERR(" Arp Request/Reply Not supported \n");
                status = SAI_STATUS_NOT_SUPPORTED;
                goto out;
            }
            break;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}


static sai_status_t mlnx_acl_entry_ip_frag_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    uint32_t                   index, flex_acl_rules_num = 0;
    uint32_t                   ii, key_desc_index = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p  = NULL;
    sx_acl_key_t               ip_frag_keys[IP_FRAG_KEY_TYPE_SIZE];
    bool                       is_ip_frag_key_type_present[IP_FRAG_KEY_TYPE_SIZE];
    uint32_t                   ip_frag_key_desc_index[IP_FRAG_KEY_TYPE_SIZE];

    SX_LOG_ENTER();

    memset(is_ip_frag_key_type_present, 0, sizeof(is_ip_frag_key_type_present));
    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    ip_frag_keys[INDEX_ZERO] = FLEX_ACL_KEY_IP_FRAGMENTED;
    ip_frag_keys[INDEX_ONE]  = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;

    for (index = 0; index < IP_FRAG_KEY_TYPE_SIZE; index++) {
        for (ip_frag_key_desc_index[index] = 0;
             ip_frag_key_desc_index[index] < flex_acl_rule_p[0].key_desc_count;
             ip_frag_key_desc_index[index]++) {
            key_desc_index = ip_frag_key_desc_index[index];
            if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == ip_frag_keys[index]) {
                is_ip_frag_key_type_present[index] = true;
                break;
            }
        }
    }

    key_desc_index = flex_acl_rule_p[0].key_desc_count;
    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        /* Remove previous frag key from the rule */
        if (is_ip_frag_key_type_present[0] && is_ip_frag_key_type_present[1]) {
            flex_acl_rule_p[ii].key_desc_count = flex_acl_rule_p[ii].key_desc_count - 2;
            for (key_desc_index = ip_frag_key_desc_index[0];
                 key_desc_index < flex_acl_rule_p[ii].key_desc_count;
                 key_desc_index++) {
                memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index], \
                       &flex_acl_rule_p[ii].key_desc_list_p[key_desc_index + 2], \
                       sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index]));
            }
        } else if (is_ip_frag_key_type_present[0] || is_ip_frag_key_type_present[1]) {
            flex_acl_rule_p[ii].key_desc_count--;
            if (is_ip_frag_key_type_present[0]) {
                key_desc_index = ip_frag_key_desc_index[0];
            } else {
                key_desc_index = ip_frag_key_desc_index[1];
            }
            for (; key_desc_index < flex_acl_rule_p[ii].key_desc_count; key_desc_index++) {
                memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index], \
                       &flex_acl_rule_p[ii].key_desc_list_p[key_desc_index + 1], \
                       sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index]));
            }
        }
        /* Set the new key field provided in setter */
        if (SAI_ACL_IP_FRAG_ANY == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_fragmented  = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_fragmented = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            flex_acl_rule_p[ii].key_desc_count++;
        }

        if (SAI_ACL_IP_FRAG_NON_FRAG == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_fragmented  = false;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_fragmented = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            flex_acl_rule_p[ii].key_desc_count++;
        }

        if (SAI_ACL_IP_FRAG_NON_FRAG_OR_HEAD == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_fragment_not_first  = false;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_fragment_not_first = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id                     =
                FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
            flex_acl_rule_p[ii].key_desc_count++;
        }

        if (SAI_ACL_IP_FRAG_HEAD == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_fragmented  = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_fragmented = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            flex_acl_rule_p[ii].key_desc_count++;
            key_desc_index++;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_fragment_not_first  = false;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_fragment_not_first = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id                     =
                FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
            flex_acl_rule_p[ii].key_desc_count++;
        }

        if (SAI_ACL_IP_FRAG_NON_HEAD == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_fragmented  = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_fragmented = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            flex_acl_rule_p[ii].key_desc_count++;
            key_desc_index++;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ip_fragment_not_first  = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ip_fragment_not_first = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id                     =
                FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
            flex_acl_rule_p[ii].key_desc_count++;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status = sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,
                                                offsets_list_p, flex_acl_rule_p, flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sx_status_t        ret_status;
    sai_status_t       status;
    sx_acl_region_id_t region_id = 0;
    uint32_t           ii, flex_acl_rules_num = 1;
    uint8_t            key_desc_index = 0;

#ifdef ACL_TODO
    uint32_t *temp_data_p, *temp_mask_p;
#endif
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p  = NULL;
    sx_acl_key_t               key_id          = 0;
    sx_ip_addr_t               ipaddr_data, ipaddr_mask;
    sai_ip_address_t           ip_address_data, ip_address_mask;
    bool                       is_key_type_present = false;

    SX_LOG_ENTER();

#ifdef ACL_TODO
    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == (int64_t)arg));
#else
    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == (int64_t)arg));
#endif /* ACL_TODO */

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
        key_id = FLEX_ACL_KEY_SIP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
        key_id = FLEX_ACL_KEY_DIP;
        break;

#ifdef ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
        key_id = FLEX_ACL_KEY_SIP_PART2;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
        key_id = FLEX_ACL_KEY_DIP_PART2;
        break;
#endif /* ACL_TODO */
    }
    memset(&ipaddr_data, 0, sizeof(ipaddr_data));
    memset(&ip_address_data, 0, sizeof(ip_address_data));
    memset(&ipaddr_mask, 0, sizeof(ipaddr_mask));
    memset(&ip_address_mask, 0, sizeof(ip_address_mask));

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
            ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            ip_address_data.addr.ip4    = value->aclfield.data.ip4;
            ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            ip_address_mask.addr.ip4    = value->aclfield.mask.ip4;
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
                goto out;
            }

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
                goto out;
            }
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip, &ipaddr_data, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.sip, &ipaddr_mask, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP;
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
            ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            ip_address_data.addr.ip4    = value->aclfield.data.ip4;
            ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            ip_address_mask.addr.ip4    = value->aclfield.mask.ip4;

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
                goto out;
            }
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip, &ipaddr_data, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dip, &ipaddr_mask, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP;
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;

#ifdef ACL_TODO
        case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count = flex_acl_rule_p[ii].key_desc_count + 4;
            } else {
                /* Searched key_desc_index was sip_part_2 */
                key_desc_index--;
            }
            temp_data_p                 = (uint32_t*)(value->aclfield.data.ip6);
            temp_mask_p                 = (uint32_t*)(value->aclfield.mask.ip6);
            temp_data_p                 = (uint32_t*)&ipaddr_data.addr.ipv6.s6_addr32[0];
            temp_mask_p                 = (uint32_t*)&ipaddr_mask.addr.ipv6.s6_addr32[0];
            ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_data.addr.ip6,  &value->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
            ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_mask.addr.ip6, &value->aclfield.mask.ip6, sizeof((ip_address_mask.addr.ip6)));

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
                goto out;
            }
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip, &ipaddr_data, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.sip, &ipaddr_mask, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP;
            key_desc_index++;

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip_part2, temp_data_p + 1, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.sip_part2, temp_mask_p + 1, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP_PART2;
            key_desc_index++;

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip_part3, temp_data_p + 2, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.sip_part3, temp_mask_p + 2, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP_PART3;
            key_desc_index++;

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip_part4, temp_data_p + 3, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.sip_part4, temp_mask_p + 3, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP_PART4;
            key_desc_index++;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count = flex_acl_rule_p[ii].key_desc_count + 4;
            } else {
                /* Searched key_desc_index was sip_part_2 */
                key_desc_index--;
            }
            temp_data_p                 = (uint32_t*)(value->aclfield.data.ip6);
            temp_mask_p                 = (uint32_t*)(value->aclfield.mask.ip6);
            temp_data_p                 = (uint32_t*)&ipaddr_data.addr.ipv6.s6_addr32[0];
            temp_mask_p                 = (uint32_t*)&ipaddr_mask.addr.ipv6.s6_addr32[0];
            ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_data.addr.ip6,  &value->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
            ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_mask.addr.ip6, &value->aclfield.mask.ip6, sizeof((ip_address_mask.addr.ip6)));

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
                goto out;
            }

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip, &ipaddr_data, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dip, &ipaddr_mask, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP;
            key_desc_index++;

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip_part2, temp_data_p + 1, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dip_part2, temp_mask_p + 1, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP_PART2;
            key_desc_index++;

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip_part3, temp_data_p + 2, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dip_part3, temp_mask_p + 2, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP_PART3;
            key_desc_index++;

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip_part4, temp_data_p + 3, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dip_part4, temp_mask_p + 3, \
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP_PART4;
            key_desc_index++;
            break;
#endif /* ACL_TODO */
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_vlan_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id           = 0;
    uint32_t                   flex_acl_rules_num  = 0, ii;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    sx_acl_key_t               key_id              = 0;
    bool                       is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == (int64_t)arg) ||
/*#ifdef ACL_TODO
 *           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID == (int64_t) arg)||
 *           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == (int64_t) arg)||
 *           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == (int64_t) arg)||
 #endif */
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == (int64_t)arg));

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
        key_id = FLEX_ACL_KEY_VLAN_ID;
        break;

#ifdef ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
        key_id = FLEX_ACL_KEY_INNER_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_INNER_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_INNER_DEI;
        break;
#endif /* ACL_TODO */

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_PCP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_DEI;
        break;
    }
    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[INDEX_ZERO].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.vlan_id  = value->aclfield.data.u16 & 0x0fff;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.vlan_id = value->aclfield.mask.u16 & 0x0fff;
            break;

#ifdef ACL_TODO
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_vlan_id  = value->aclfield.data.u16 & 0x0fff;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_vlan_id = value->aclfield.mask.u16 & 0x0fff;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_pcp  = value->aclfield.data.u8 & 0x07;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_pcp = value->aclfield.mask.u8 & 0x07;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_dei  = value->aclfield.data.u8 & 0x01;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_dei = value->aclfield.mask.u8 & 0x01;
            break;
#endif /* ACL_TODO */

        case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.pcp  = value->aclfield.data.u8 & 0x07;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.pcp = value->aclfield.mask.u8 & 0x07;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dei  = value->aclfield.data.u8 & 0x01;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dei = value->aclfield.mask.u8 & 0x01;
            break;
        }
        flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = key_id;
        if (!is_key_type_present) {
            flex_acl_rule_p[ii].key_desc_count++;
        }
    }
    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_ports_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    sx_flex_acl_rule_offset_t  rule_offset;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p        = NULL;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_delete_p = NULL;
    sx_flex_acl_flex_rule_t    flex_acl_rule;
    sx_flex_acl_rule_offset_t *offsets_list_p = NULL;
    sx_acl_key_t               key_id         = 0;
    uint32_t                   acl_entry_id, acl_entry_index;
    uint32_t                   acl_table_index;
    uint32_t                   num_rules, port, index;
    uint32_t                   flex_acl_rules_num = 1;
    uint32_t                   delete_rules_count = 0, rule_counter = 0;
    uint32_t                   new_num_rules, port_counter;
    uint32_t                   offset_max_count = 0;
    uint32_t                   counter_index;
    uint8_t                    key_desc_index      = 0, action_index = 0;
    bool                       is_key_type_present = false;
    uint32_t                   ii, offset_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        return status;
    }

    sai_db_write_lock();
    counter_index = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].counter_id;
    num_rules     = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules;
    rule_offset   = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset;
    region_id     = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id;

    memset(&flex_acl_rule, 0, sizeof(sx_flex_acl_flex_rule_t));

    if (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg) {
        if (g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].stage != SX_ACL_DIRECTION_EGRESS) {
            SX_LOG_ERR("Port type(OUT PORT) and stage do not match\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
    }

    new_num_rules = value->aclfield.data.objlist.count;
    if (value->aclfield.data.objlist.count == 0) {
        new_num_rules = 1;
    }

    ret_status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                           MAX_NUM_OF_ACTIONS, &flex_acl_rule);
    if (SX_STATUS_SUCCESS != ret_status) {
        SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(ret_status));
        sai_db_unlock();
        SX_LOG_EXIT();
        return sdk_to_sai(ret_status);
    }

    if (SAI_STATUS_SUCCESS ==
        (ret_status =
             sx_api_acl_flex_rules_get(gh_sdk, region_id, &rule_offset, &flex_acl_rule, &flex_acl_rules_num))) {
        if (flex_acl_rules_num == 0) {
            SX_LOG_ERR("Number of rules at start offset [%d] from region [%u] in SDK - %s\n",
                       rule_offset,
                       region_id,
                       SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
    } else {
        SX_LOG_ERR("Failed to retrieve rules from region [%u] in SDK - %s\n", region_id, SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(new_num_rules * sizeof(sx_flex_acl_flex_rule_t));
    if (flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    offset_max_count = (new_num_rules > num_rules) ? new_num_rules : num_rules;
    offsets_list_p   = (sx_flex_acl_rule_offset_t*)malloc(offset_max_count * sizeof(sx_flex_acl_rule_offset_t));
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for offsets list\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (offset_index = 0; offset_index < offset_max_count; offset_index++) {
        offsets_list_p[offset_index] = rule_offset + offset_index;
    }

    for (ii = 0; ii < new_num_rules; ii++) {
        ret_status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                               MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[ii]);
        if (SX_STATUS_SUCCESS != ret_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(ret_status));
            status        = sdk_to_sai(ret_status);
            new_num_rules = ii;
            goto out_deinit;
        }
    }

    for (index = 0; index < new_num_rules; index++) {
        flex_acl_rule_p[index].valid          = flex_acl_rule.valid;
        flex_acl_rule_p[index].key_desc_count = flex_acl_rule.key_desc_count;
        flex_acl_rule_p[index].action_count   = flex_acl_rule.action_count;
        memcpy(flex_acl_rule_p[index].key_desc_list_p, flex_acl_rule.key_desc_list_p,
               flex_acl_rule.key_desc_count * sizeof(sx_flex_acl_key_desc_t));
        memcpy(flex_acl_rule_p[index].action_list_p, flex_acl_rule.action_list_p,
               flex_acl_rule.action_count * sizeof(sx_flex_acl_flex_action_t));
    }

    if (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) {
        key_id = FLEX_ACL_KEY_SRC_PORT;
    } else {
        key_id = FLEX_ACL_KEY_DST_PORT;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[INDEX_ZERO].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    if (!is_key_type_present) {
        for (rule_counter = 0; rule_counter < new_num_rules; rule_counter++) {
            flex_acl_rule_p[rule_counter].key_desc_count++;
        }
    }

    rule_counter = 0;

    if (value->aclfield.data.objlist.count > 0) {
        for (port_counter = 0; port_counter < value->aclfield.data.objlist.count; port_counter++) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(value->aclfield.data.objlist.list[port_counter], SAI_OBJECT_TYPE_PORT, &port,
                                         NULL))) {
                goto out_deinit;
            }
            flex_acl_rule_p[rule_counter].action_list_p[action_index].type =
                SX_FLEX_ACL_ACTION_COUNTER;
            flex_acl_rule_p[rule_counter].action_list_p[action_index].fields.action_counter.counter_id = \
                g_sai_db_ptr->acl_db.acl_counter_db[counter_index].counter_id;

            if (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) {
                flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index].key.src_port  = port;
                flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_SRC_PORT;
                flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index].mask.src_port = true;
            } else {
                flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index].key.dst_port  = port;
                flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_DST_PORT;
                flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index].mask.dst_port = true;
            }
            rule_counter++;
        }
    }
    /* When port list count = 0 */
    else {
        for (ii = key_desc_index; ii < flex_acl_rule.key_desc_count - 1; ii++) {
            memcpy(&flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index],
                   &flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index + 1],
                   sizeof(flex_acl_rule_p[rule_counter].key_desc_list_p[key_desc_index]));
            flex_acl_rule_p[rule_counter].key_desc_count = flex_acl_rule_p[rule_counter].key_desc_count - 1;
        }
        rule_counter++;
    }


    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       new_num_rules))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out_deinit;
    }


    if (new_num_rules < num_rules) {
        delete_rules_count     = num_rules - new_num_rules;
        flex_acl_rule_delete_p =
            (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * delete_rules_count);
        if (flex_acl_rule_delete_p == NULL) {
            SX_LOG_ERR(" Unable to allocate memory for flex_acl_rule_delete_p.\n");
            status = SAI_STATUS_NO_MEMORY;
            goto out_deinit;
        }

        memset(flex_acl_rule_delete_p, 0, sizeof(sx_flex_acl_flex_rule_t) * delete_rules_count);

        if (SAI_STATUS_SUCCESS ==
            (ret_status =
                 sx_api_acl_flex_rules_get(gh_sdk, region_id, offsets_list_p + rule_counter, flex_acl_rule_delete_p,
                                           &delete_rules_count))) {
            if (0 == delete_rules_count) {
                SX_LOG_ERR("Number of rules from start offset [%d] for region [%u] in SDK is zero \n",
                           offsets_list_p[0] + rule_counter,
                           region_id);
                status = sdk_to_sai(ret_status);
                goto out_deinit;
            }
        } else {
            SX_LOG_ERR("Failed to retrieve rules from region [%u] in SDK - %s\n", region_id,
                       SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out_deinit;
        }

        if (SAI_STATUS_SUCCESS !=
            (ret_status =
                 sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_DELETE, region_id,  offsets_list_p + rule_counter,
                                           flex_acl_rule_delete_p, delete_rules_count))) {
            SX_LOG_ERR("Failed to delete ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out_deinit;
        }
    }

    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules = new_num_rules;

out_deinit:
    if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
    }

    for (ii = 0; ii < new_num_rules; ii++) {
        if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
            SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
        }
    }

out:
    if (flex_acl_rule_delete_p) {
        free(flex_acl_rule_delete_p);
    }
    if (flex_acl_rule_p) {
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_port_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0, ii;
    uint32_t                   port_data;
    uint32_t                   key_id = 0;
    uint32_t                   acl_entry_index, acl_table_index, acl_entry_id;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    bool                       is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == (int64_t)arg));

    sai_db_write_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT:
        key_id = FLEX_ACL_KEY_L4_SOURCE_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT:
        key_id = FLEX_ACL_KEY_L4_DESTINATION_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[INDEX_ZERO].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.l4_source_port  = value->aclfield.data.u16;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.l4_source_port = value->aclfield.mask.u16;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.l4_destination_port  = value->aclfield.data.u16;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.l4_destination_port = value->aclfield.mask.u16;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(value->aclfield.data.oid, SAI_OBJECT_TYPE_PORT, &port_data, NULL))) {
                goto out;
            }
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.src_port  = port_data;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.src_port = true;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
                SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
                goto out;
            }
            if (g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].stage != SX_ACL_DIRECTION_EGRESS) {
                SX_LOG_ERR("Port type(OUT PORT) and stage do not match\n");
                status = SAI_STATUS_NOT_SUPPORTED;
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(value->aclfield.data.oid, SAI_OBJECT_TYPE_PORT, &port_data, NULL))) {
                goto out;
            }
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dst_port  = port_data;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dst_port = true;
            break;
        }
        if (!is_key_type_present) {
            flex_acl_rule_p[ii].key_desc_count++;
        }
        flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = key_id;
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    /* Delete Rules during in-port/out-por set, except the rule at the start offset, if prev number of rules > 1 */
    if (((int64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT) || ((int64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT)) {
        if (flex_acl_rules_num > 1) {
            if (SAI_STATUS_SUCCESS !=
                (ret_status =
                     sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_DELETE, region_id, offsets_list_p + 1,
                                               flex_acl_rule_p + 1,
                                               flex_acl_rules_num - 1))) {
                SX_LOG_ERR("Failed to delete ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
                status = sdk_to_sai(ret_status);
                goto out;
            }
        }

        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
            goto out;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
            goto out;
        }

        /* Update New Rule Count in DB */
        g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules = 1;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_fields_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id           = 0;
    uint32_t                   flex_acl_rules_num  = 0, ii;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    sx_acl_key_t               key_id              = 0;
    bool                       is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ADMIN_STATE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == (int64_t)arg) ||
/*#ifdef ACL_TODO
 *           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == (int64_t)arg)||
 #endif*/
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == (int64_t)arg));

    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE:
        key_id = FLEX_ACL_KEY_ETHERTYPE;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TC:
        key_id = FLEX_ACL_KEY_SWITCH_PRIO;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
        key_id = FLEX_ACL_KEY_TTL;
        break;

#if ACL_TODO
    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
        key_id = FLEX_ACL_KEY_USER_TOKEN;
        break;

#endif
    case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS:
        key_id = FLEX_ACL_KEY_TCP_CONTROL;
        break;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[INDEX_ZERO].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ADMIN_STATE:
            SX_LOG_ERR(" Admin State ( if set to false ) deletes rule \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        /* flex_acl_rule_p[ii].valid = (uint8_t)value->aclfield.enable;
         *  break; */

        case SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ethertype  = value->aclfield.data.u16;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ethertype = value->aclfield.mask.u16;
            break;

#if ACL_TODO
        case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.user_token  = value->aclfield.data.u16;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.user_token = value->aclfield.mask.u16;
            break;

#endif
        case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.tcp_control  = value->aclfield.data.u8 & 0x3F;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.tcp_control = value->aclfield.mask.u8 & 0x3F;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_TC:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.switch_prio  = value->aclfield.data.u8;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.switch_prio = value->aclfield.mask.u8;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ttl  = value->aclfield.data.u8;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ttl = value->aclfield.mask.u8;
            break;
        }
        flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = key_id;
        if (!is_key_type_present) {
            flex_acl_rule_p[ii].key_desc_count++;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_tos_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p    = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p     = NULL;
    uint32_t                   flex_acl_rules_num = 0;
    uint32_t                   key_desc_index, ii;
    bool                       is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TOS == (int64_t)arg));

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_FIELD_DSCP:
            for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[ii].key_desc_count; key_desc_index++) {
                if (flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_DSCP) {
                    is_key_type_present = true;
                    break;
                }
            }
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dscp  = (value->aclfield.data.u8) & 0x3f;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dscp = (value->aclfield.mask.u8) & 0x3f;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id    = FLEX_ACL_KEY_DSCP;
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_ECN:
            for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[ii].key_desc_count; key_desc_index++) {
                if (flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_ECN) {
                    is_key_type_present = true;
                    break;
                }
            }

            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ecn  = (value->aclfield.data.u8) & 0x03;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ecn = (value->aclfield.mask.u8) & 0x03;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id   = FLEX_ACL_KEY_ECN;
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_TOS:
            for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[ii].key_desc_count; key_desc_index++) {
                if (flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_DSCP) {
                    is_key_type_present = true;
                    break;
                }
            }

            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dscp  = (value->aclfield.data.u8 >> 0x02) & 0x3f;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dscp = (value->aclfield.mask.u8 >> 0x02) & 0x3f;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id    = FLEX_ACL_KEY_DSCP;
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            is_key_type_present = false;

            for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[ii].key_desc_count; key_desc_index++) {
                if (flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_ECN) {
                    is_key_type_present = true;
                    break;
                }
            }
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.ecn  = (value->aclfield.data.u8) & 0x03;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.ecn = (value->aclfield.mask.u8) & 0x03;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id   = FLEX_ACL_KEY_ECN;
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_packet_action_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sx_status_t                    ret_status;
    sai_status_t                   status;
    sx_acl_region_id_t             region_id       = 0;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p = NULL;
    sx_flex_acl_rule_offset_t     *offsets_list_p  = NULL;
    sai_packet_action_t            packet_action_type;
    sx_flex_acl_flex_action_type_t action_type;
    uint32_t                       flex_acl_rules_num = 0;
    uint16_t                       trap_id            = SX_TRAP_ID_ACL_MIN;
    uint8_t                        flex_action_index;
    uint8_t                        ii;
    uint8_t                        trap_action_index      = 0, forward_action_index = 0;
    bool                           is_trap_action_present = false, is_forward_action_present = false;

    SX_LOG_ENTER();

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[0].action_count; flex_action_index++) {
        action_type = flex_acl_rule_p[0].action_list_p[flex_action_index].type;
        if (action_type == SX_FLEX_ACL_ACTION_TRAP) {
            is_trap_action_present = true;
            trap_action_index      = flex_action_index;
        }
        if (action_type == SX_FLEX_ACL_ACTION_FORWARD) {
            is_forward_action_present = true;
            forward_action_index      = flex_action_index;
        }
    }

    packet_action_type = value->aclaction.parameter.s32;

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (is_forward_action_present && !is_trap_action_present) {
            flex_acl_rule_p[ii].action_count--;
            for (flex_action_index = forward_action_index;
                 flex_action_index < flex_acl_rule_p[ii].action_count;
                 flex_action_index++) {
                memcpy((&flex_acl_rule_p[ii].action_list_p[flex_action_index]), \
                       &(flex_acl_rule_p[ii].action_list_p[flex_action_index + 1]), \
                       sizeof(sx_flex_acl_flex_action_t));
            }
        }
        if (!is_forward_action_present && is_trap_action_present) {
            flex_acl_rule_p[ii].action_count--;
            for (flex_action_index = trap_action_index;
                 flex_action_index < flex_acl_rule_p[ii].action_count;
                 flex_action_index++) {
                memcpy((&flex_acl_rule_p[ii].action_list_p[flex_action_index]), \
                       &(flex_acl_rule_p[ii].action_list_p[flex_action_index + 1]), \
                       sizeof(sx_flex_acl_flex_action_t));
            }
        }
        if (is_forward_action_present && is_trap_action_present) {
            flex_acl_rule_p[ii].action_count = flex_acl_rule_p[ii].action_count - 2;
            for (flex_action_index = trap_action_index;
                 flex_action_index < flex_acl_rule_p[ii].action_count;
                 flex_action_index++) {
                memcpy((&flex_acl_rule_p[ii].action_list_p[flex_action_index]), \
                       &(flex_acl_rule_p[ii].action_list_p[flex_action_index + 2]), \
                       sizeof(sx_flex_acl_flex_action_t));
            }
        }

        if (value->aclaction.enable == true) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_acl_packet_actions_handler(packet_action_type, trap_id, &flex_acl_rule_p[ii],
                                                     &flex_action_index))) {
                goto out;
            }
            flex_acl_rule_p[ii].action_count = flex_action_index;
        }
    }
    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_action_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sx_status_t                    ret_status;
    sai_status_t                   status;
    sx_acl_region_id_t             region_id          = 0;
    uint32_t                       flex_acl_rules_num = 0;
    uint32_t                       port_counter       = 0, ii;
    uint32_t                       action_set_policer_id_data;
    uint8_t                        flex_action_index = 0;
    sx_acl_pbs_entry_t             pbs_entry;
    sx_swid_t                      swid_id   = 0;
    sx_acl_pbs_id_t                pbs_index = 0;
    sx_acl_pbs_id_t                old_pbs_id;
    sx_port_id_t                   redirect_port;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_port_log_id_t              *port_arr               = NULL;
    bool                           is_action_type_present = false;
    sx_flex_acl_flex_action_type_t action_type            = 0;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_FLOOD == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == (int64_t)arg));

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        action_type = SX_FLEX_ACL_ACTION_PBS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
        action_type = SX_FLEX_ACL_ACTION_PBS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
        action_type = SX_FLEX_ACL_ACTION_POLICER;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC:
        action_type = SX_FLEX_ACL_ACTION_SET_PRIO;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP:
        action_type = SX_FLEX_ACL_ACTION_SET_DSCP;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR:
        action_type = SX_FLEX_ACL_ACTION_SET_COLOR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN:
        action_type = SX_FLEX_ACL_ACTION_SET_ECN;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL:
        action_type = SX_FLEX_ACL_ACTION_DEC_TTL;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA:
        action_type = SX_FLEX_ACL_ACTION_SET_USER_TOKEN;
        break;

    default:
        SX_LOG_ERR(" Invalid Attrib to Set \n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[INDEX_ZERO].action_count; flex_action_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].action_list_p[flex_action_index].type == action_type) {
            is_action_type_present = true;
            break;
        }
    }
    /* Retrieve old PBS Id and create new PBS Entry */
    if (((int64_t)arg == SAI_ACL_ENTRY_ATTR_ACTION_FLOOD) || ((int64_t)arg == (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT))) {
        if ((int64_t)arg == SAI_ACL_ENTRY_ATTR_ACTION_FLOOD) {
            port_arr = (sx_port_log_id_t*)malloc(g_sai_db_ptr->ports_number * sizeof(sx_port_log_id_t));
            if (port_arr == NULL) {
                SX_LOG_ERR("ERROR: unable to allocate memory for port_arr\n");
                status = SAI_STATUS_NO_MEMORY;
                goto out;
            }
            memset(port_arr, 0, g_sai_db_ptr->ports_number * sizeof(sx_port_log_id_t));
            for (port_counter = 0; port_counter < g_sai_db_ptr->ports_number; port_counter++) {
                port_arr[port_counter] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[port_counter].logical;
            }
        } else if ((int64_t)arg == SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(value->aclaction.parameter.oid, SAI_OBJECT_TYPE_PORT, &redirect_port,
                                         NULL))) {
                goto out;
            }
        }
        /* Store the PBS IDs to delete OLD PBS entries after the ACL Entry is Set */
        if (is_action_type_present) {
            old_pbs_id = flex_acl_rule_p[0].action_list_p[flex_action_index].fields.action_pbs.pbs_id;
        }

        if (value->aclaction.enable == true) {
            memset(&pbs_entry, 0, sizeof(pbs_entry));
            pbs_entry.entry_type = SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT ==
                                   (int64_t)arg ? SX_ACL_PBS_ENTRY_TYPE_UNICAST : SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
            pbs_entry.port_num  = SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg ? 1 : g_sai_db_ptr->ports_number;
            pbs_entry.log_ports = SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg ? &redirect_port : port_arr;

            if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_policy_based_switching_set(gh_sdk,
                                                                                          SX_ACCESS_CMD_ADD,
                                                                                          swid_id,
                                                                                          &pbs_entry,
                                                                                          &pbs_index))) {
                SX_LOG_ERR("failed to set REDIRECT PORT  %s.\n", SX_STATUS_MSG(ret_status));
                status = sdk_to_sai(ret_status);
                goto out;
            }
        }

        if (port_arr) {
            free(port_arr);
            port_arr = NULL;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_index;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
            if (value->aclaction.enable == true) {
                if (SAI_STATUS_SUCCESS !=
                    (status =
                         mlnx_object_to_type(value->aclaction.parameter.oid, SAI_OBJECT_TYPE_POLICER,
                                             &action_set_policer_id_data, NULL))) {
                    goto out;
                }

                /* cl_plock_acquire(&g_sai_db_ptr->p_lock); */
                if (SAI_STATUS_SUCCESS != (status = mlnx_sai_get_or_create_regular_sx_policer_for_bind(
                                               value->aclaction.parameter.oid,
                                               &flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.
                                               action_policer.policer_id))) {
                    SX_LOG_ERR("Failed to obtain sx_policer_id. input sai policer object_id:0x%" PRIx64 "\n",
                               value->aclaction.parameter.oid);
                    /* cl_plock_release(&g_sai_db_ptr->p_lock); */
                    goto out;
                }
                /*cl_plock_release(&g_sai_db_ptr->p_lock); */
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_POLICER;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_prio.prio_val =
                    value->aclaction.parameter.u8;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_PRIO;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_dscp.dscp_val =
                    value->aclaction.parameter.u8;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_DSCP;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_ecn.ecn_val =
                    value->aclaction.parameter.u8;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_ECN;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_color.color_val =
                    value->aclaction.parameter.s32;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_COLOR;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_dec_ttl.ttl_val = 1;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type                          =
                    SX_FLEX_ACL_ACTION_DEC_TTL;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA:
            if (value->aclaction.enable == true) {
                if (value->aclaction.parameter.u32 >> 0x10 == 0) {
                    flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_user_token.user_token =
                        (uint16_t)value->aclaction.parameter.u32;
                    flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                        SX_FLEX_ACL_ACTION_SET_USER_TOKEN;
                } else {
                    SX_LOG_ERR(" Acl Meta Data to Set is not in range \n");
                    status = SAI_STATUS_NOT_SUPPORTED;
                }
            }
            break;
        }

        if (value->aclaction.enable == false) {
            if (is_action_type_present) {
                flex_acl_rule_p[ii].action_count--;
                for (; flex_action_index < flex_acl_rule_p[ii].action_count; flex_action_index++) {
                    memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index],
                           &flex_acl_rule_p[ii].action_list_p[flex_action_index + 1], \
                           sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index]));
                }
            }
        } else {
            if (!is_action_type_present) {
                flex_acl_rule_p[ii].action_count++;
            }
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    /* Delete Old PBS Entries */
    if ((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg) || (SAI_ACL_ENTRY_ATTR_ACTION_FLOOD == (int64_t)arg)) {
        if (is_action_type_present) {
            memset(&pbs_entry, 0, sizeof(pbs_entry));
            port_arr = (sx_port_log_id_t*)malloc(g_sai_db_ptr->ports_number * sizeof(sx_port_log_id_t));
            if (port_arr == NULL) {
                SX_LOG_ERR("ERROR: unable to allocate memory for port_arr\n");
                status = SAI_STATUS_NO_MEMORY;
                goto out;
            }
            memset(port_arr, 0, g_sai_db_ptr->ports_number * sizeof(sx_port_log_id_t));
            pbs_entry.log_ports = port_arr;
            pbs_entry.port_num  = g_sai_db_ptr->ports_number;

            if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_policy_based_switching_get(gh_sdk,
                                                                                          SX_ACCESS_CMD_GET,
                                                                                          swid_id,
                                                                                          old_pbs_id,
                                                                                          &pbs_entry))) {
                SX_LOG_ERR("failed to get UC PBS in SDK  %s.\n", SX_STATUS_MSG(ret_status));
                status = sdk_to_sai(ret_status);
                goto out;
            }
            if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_policy_based_switching_set(gh_sdk,
                                                                                          SX_ACCESS_CMD_DELETE,
                                                                                          swid_id,
                                                                                          &pbs_entry,
                                                                                          &old_pbs_id))) {
                SX_LOG_ERR("failed to DELETE old PBS Entry  %s.\n", SX_STATUS_MSG(ret_status));
                status = sdk_to_sai(ret_status);
                goto out;
            }
        }
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    if (port_arr) {
        free(port_arr);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mirror_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sx_status_t                ret_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0, acl_entry_id, ii;
    uint32_t                   acl_direction      = SAI_ACL_STAGE_INGRESS, acl_table_index, acl_table_id;
    uint8_t                    flex_action_index  = 0;
    uint32_t                   session_id;
    sx_flex_acl_rule_offset_t *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p        = NULL;
    bool                       is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == (int64_t)arg));

    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
        acl_direction = SAI_ACL_STAGE_INGRESS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
        acl_direction = SAI_ACL_STAGE_EGRESS;
        break;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        goto out;
    }
    acl_table_id    = acl_entry_id >> 0x10;
    acl_table_index = acl_table_id;


    if (g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].stage != acl_direction) {
        SX_LOG_ERR(" Invalid Attribute to Get : Action Mirror  \n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }


    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[INDEX_ZERO].action_count; flex_action_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].action_list_p[flex_action_index].type == SX_FLEX_ACL_ACTION_MIRROR) {
            is_action_type_present = true;
            break;
        }
    }
    if (value->aclaction.parameter.objlist.count != 1) {
        SX_LOG_ERR(" Failure : Only 1 Session ID is allowed to associate in an ACL Rule at this phase\n");
        status = SAI_STATUS_NOT_IMPLEMENTED;
        goto out;
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (value->aclaction.enable == true) {
            if (!is_action_type_present) {
                flex_acl_rule_p[ii].action_count++;
            }

            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(value->aclaction.parameter.objlist.list[0], SAI_OBJECT_TYPE_MIRROR,
                                         &session_id,
                                         NULL))) {
                goto out;
            }
            flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_mirror.session_id = session_id;
            flex_acl_rule_p[ii].action_list_p[flex_action_index].type                            =
                SX_FLEX_ACL_ACTION_MIRROR;
        } else {
            if (is_action_type_present) {
                flex_acl_rule_p[ii].action_count--;
                for (; flex_action_index < flex_acl_rule_p[ii].action_count; flex_action_index++) {
                    memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index],
                           &flex_acl_rule_p[ii].action_list_p[flex_action_index + 1], \
                           sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index]));
                }
            }
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mac_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    sx_status_t                    ret_status;
    sai_status_t                   status;
    sx_acl_region_id_t             region_id          = 0;
    uint32_t                       flex_acl_rules_num = 0, ii;
    uint8_t                        flex_action_index;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_flex_action_type_t action_type            = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
    bool                           is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC == (int64_t)arg));

    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC:
        action_type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC:
        action_type = SX_FLEX_ACL_ACTION_SET_DST_MAC;
        break;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[INDEX_ZERO].action_count; flex_action_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].action_list_p[flex_action_index].type == action_type) {
            is_action_type_present = true;
            break;
        }
    }
    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC:
            if (value->aclaction.enable == true) {
                memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_src_mac.mac, \
                       value->aclaction.parameter.mac, \
                       sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_src_mac.mac));
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC:
            if (value->aclaction.enable == true) {
                memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_dst_mac.mac, \
                       value->aclaction.parameter.mac, \
                       sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_dst_mac.mac));
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_DST_MAC;
            }
            break;
        }


        if (value->aclaction.enable == false) {
            if (is_action_type_present) {
                flex_acl_rule_p[ii].action_count--;
                for (; flex_action_index < flex_acl_rule_p[ii].action_count; flex_action_index++) {
                    memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index],
                           &flex_acl_rule_p[ii].action_list_p[flex_action_index + 1], \
                           sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index]));
                }
            }
        } else {
            if (!is_action_type_present) {
                flex_acl_rule_p[ii].action_count++;
            }
        }
    }
    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}


static sai_status_t mlnx_acl_entry_action_vlan_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg)
{
    sx_status_t                    ret_status;
    sai_status_t                   status;
    sx_acl_region_id_t             region_id              = 0;
    uint32_t                       flex_acl_rules_num     = 0, ii;
    uint8_t                        flex_action_index      = 0;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_flex_action_type_t action_type            = 0;
    bool                           is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI == (int64_t)arg));

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status =
             fetch_flex_acl_rule_params_to_set(key, &flex_acl_rule_p, &offsets_list_p, &region_id,
                                               &flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID:
        action_type = SX_FLEX_ACL_ACTION_SET_INNER_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID:
        action_type = SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_ID;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI:
        action_type = SX_FLEX_ACL_ACTION_SET_INNER_VLAN_PRI;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI:
        action_type = SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_PRI;
        break;
    }
    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[INDEX_ZERO].action_count; flex_action_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].action_list_p[flex_action_index].type == action_type) {
            is_action_type_present = true;
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_INNER_VLAN_ID;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_inner_vlan_id.vlan_id =
                    value->aclaction.parameter.u16;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_INNER_VLAN_PRI;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_inner_vlan_prio.pcp =
                    value->aclaction.parameter.u8;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_ID;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_outer_vlan_id.vlan_id =
                    value->aclaction.parameter.u16;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_PRI;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_outer_vlan_prio.pcp =
                    value->aclaction.parameter.u8;
                break;
            }
            break;
        }
        if (value->aclaction.enable == false) {
            if (is_action_type_present) {
                flex_acl_rule_p[ii].action_count--;
                for (; flex_action_index < flex_acl_rule_p[ii].action_count; flex_action_index++) {
                    memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index],
                           &flex_acl_rule_p[ii].action_list_p[flex_action_index + 1], \
                           sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index]));
                }
            }
        } else {
            if (!is_action_type_present) {
                flex_acl_rule_p[ii].action_count++;
            }
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_entry_action_counter_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg)
{
    sx_status_t               ret_status;
    sai_status_t              status;
    sx_acl_region_id_t        region_id = 0;
    sx_flex_acl_rule_offset_t rule_offset;
    sx_acl_rule_offset_t     *offsets_list_p     = NULL;
    sx_flex_acl_flex_rule_t  *flex_acl_rule_p    = NULL;
    uint32_t                  flex_acl_rules_num = 1;
    uint32_t                  acl_entry_id, acl_entry_index;
    uint32_t                  acl_table_index;
    uint32_t                  rule_counter, index, offset_index;
    uint8_t                   flex_action_index      = 0;
    bool                      is_action_type_present = false;
    uint32_t                  counter_id, counter_index;
    uint32_t                  ii = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &acl_entry_id, NULL))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index))) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        return status;
    }

    sai_db_write_lock();
    flex_acl_rules_num = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules;
    region_id          = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id;
    rule_offset        = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset;

    flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);
    if (flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for flex_acl_rule_p\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(flex_acl_rule_p, 0, sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        ret_status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                               MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[ii]);
        if (SX_STATUS_SUCCESS != ret_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(ret_status));
            status             = sdk_to_sai(ret_status);
            flex_acl_rules_num = ii;
            goto out;
        }
    }

    offsets_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for offsets list\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(offsets_list_p, 0, sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);

    for (offset_index = 0; offset_index < flex_acl_rules_num; offset_index++) {
        offsets_list_p[offset_index] = rule_offset + offset_index;
    }

    if (SAI_STATUS_SUCCESS ==
        (ret_status =
             sx_api_acl_flex_rules_get(gh_sdk, region_id, offsets_list_p, flex_acl_rule_p, &flex_acl_rules_num))) {
        if (flex_acl_rules_num == 0) {
            SX_LOG_ERR("Number of rules at start offset [%d] for region [%u] in SDK - %s\n",
                       rule_offset,
                       region_id,
                       SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
    } else {
        SX_LOG_ERR("Failed to retrieve rules from region [%u] in SDK - %s\n", region_id, SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }
    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[INDEX_ZERO].action_count; flex_action_index++) {
        if (flex_acl_rule_p[INDEX_ZERO].action_list_p[flex_action_index].type == SX_FLEX_ACL_ACTION_COUNTER) {
            is_action_type_present = true;
            break;
        }
    }

    if (value->aclaction.enable == false) {
        if (is_action_type_present) {
            for (rule_counter = 0; rule_counter < flex_acl_rules_num; rule_counter++) {
                for (index = flex_action_index; index < flex_acl_rule_p[rule_counter].action_count - 1; index++) {
                    memcpy(&flex_acl_rule_p[rule_counter].action_list_p[index],
                           &flex_acl_rule_p[rule_counter].action_list_p[index + 1], \
                           sizeof(flex_acl_rule_p[rule_counter].action_list_p[index]));
                }
                flex_acl_rule_p[rule_counter].action_count--;
            }
            g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].counter_id =
                SX_FLOW_COUNTER_ID_INVALID;
        }
    } else {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 mlnx_object_to_type(value->aclaction.parameter.oid, SAI_OBJECT_TYPE_ACL_COUNTER, &counter_id,
                                     NULL))) {
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        counter_index = counter_id;
        for (rule_counter = 0; rule_counter < flex_acl_rules_num; rule_counter++) {
            flex_acl_rule_p[rule_counter].action_list_p[flex_action_index].fields.action_counter.counter_id = \
                g_sai_db_ptr->acl_db.acl_counter_db[counter_index].counter_id;
            flex_acl_rule_p[rule_counter].action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_COUNTER;
            if (!is_action_type_present) {
                flex_acl_rule_p[rule_counter].action_count++;
            }
        }


        g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].counter_id = counter_id;
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, offsets_list_p, flex_acl_rule_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }


out:
    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_acl_packet_actions_handler(_In_ sai_packet_action_t         packet_action_type,
                                                    _In_ uint16_t                    trap_id,
                                                    _Inout_ sx_flex_acl_flex_rule_t *flex_rule,
                                                    _Inout_ uint8_t                 *flex_action_index)
{
    sx_status_t status  = SAI_STATUS_SUCCESS;
    uint8_t     a_index = *flex_action_index;

    SX_LOG_ENTER();

    switch (packet_action_type) {
    case SAI_PACKET_ACTION_DROP:
        flex_rule->action_list_p[a_index].fields.action_forward.action = SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_FORWARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_FORWARD:
        flex_rule->action_list_p[a_index].fields.action_forward.action = SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD;
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_FORWARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_COPY:
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_TRAP;
        flex_rule->action_list_p[a_index].fields.action_forward.action =
            SX_ACL_TRAP_ACTION_TYPE_TRAP;
        flex_rule->action_list_p[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        break;

    case SAI_PACKET_ACTION_COPY_CANCEL:
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_TRAP;
        flex_rule->action_list_p[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        flex_rule->action_list_p[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        break;

    case SAI_PACKET_ACTION_LOG:
        flex_rule->action_list_p[a_index].type                      = SX_FLEX_ACL_ACTION_TRAP;
        flex_rule->action_list_p[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_TRAP;
        flex_rule->action_list_p[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_FORWARD;
        flex_rule->action_list_p[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_TRAP:
        flex_rule->action_list_p[a_index].type                      = SX_FLEX_ACL_ACTION_TRAP;
        flex_rule->action_list_p[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_TRAP;
        flex_rule->action_list_p[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_FORWARD;
        flex_rule->action_list_p[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_DENY:
        flex_rule->action_list_p[a_index].type                      = SX_FLEX_ACL_ACTION_TRAP;
        flex_rule->action_list_p[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_DISCARD;
        flex_rule->action_list_p[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_FORWARD;
        flex_rule->action_list_p[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_TRANSIT:
        flex_rule->action_list_p[a_index].type                      = SX_FLEX_ACL_ACTION_TRAP;
        flex_rule->action_list_p[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_DISCARD;
        flex_rule->action_list_p[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_rule->action_list_p[a_index].type                         = SX_FLEX_ACL_ACTION_FORWARD;
        flex_rule->action_list_p[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD;
        a_index++;
        break;

    default:
        SX_LOG_ERR(" Invalid Packet Action Type Value \n");
        status = SAI_STATUS_FAILURE;
    }

    *flex_action_index = a_index;
    SX_LOG_EXIT();
    return status;
}


/*
 * Routine Description:
 *   Create an ACL Entry
 *
 * Arguments:
 *  [out] acl_entry_id -  acl entry/rule id
 *  [in] attr_count - number of attributes
 *  [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */

static sai_status_t mlnx_create_acl_entry(_Out_ sai_object_id_t     * acl_entry_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  ret_status;
    sx_acl_pbs_entry_t           pbs_entry;
    sx_flex_acl_flex_rule_t      flex_acl_rule;
    sx_flex_acl_flex_rule_t     *flex_acl_rule_p = NULL;
    sx_swid_t                    swid_id         = 0;
    sx_acl_pbs_id_t              pbs_index       = 0;
    sx_port_log_id_t            *port_arr        = NULL;
    sx_acl_region_id_t           region_id;
    sx_acl_rule_offset_t        *offsets_list_p = NULL;
    sx_acl_key_t                 port_key_id    = 0;
    sx_ip_addr_t                 ipaddr_data, ipaddr_mask;
    sai_ip_address_t             ip_address_data, ip_address_mask;
    sai_packet_action_t          packet_action_type;
    const sai_attribute_value_t *table_id, *priority;
    const sai_attribute_value_t *src_mac, *dst_mac, *src_ip, *dst_ip;
    const sai_attribute_value_t *in_port, *in_ports, *ports = NULL, *out_port, *out_ports;
    const sai_attribute_value_t *outer_vlan_id, *outer_vlan_pri, *outer_vlan_cfi;
    const sai_attribute_value_t *L4_src_port, *L4_dst_port;
    const sai_attribute_value_t *ether_type, *ip_protocol;
    const sai_attribute_value_t *ip_tos, *dscp, *ecn;
    const sai_attribute_value_t *ip_type, *ip_frag;
    const sai_attribute_value_t *ip_flags, *tcp_flags;
    const sai_attribute_value_t *tc, *ttl;
    const sai_attribute_value_t *packet_action, *action_counter;
    const sai_attribute_value_t *action_set_src_mac, *action_set_dst_mac;
    const sai_attribute_value_t *action_set_dscp;
    const sai_attribute_value_t *action_set_color, *action_set_ecn;
    const sai_attribute_value_t *action_mirror_ingress, *action_mirror_egress;
    const sai_attribute_value_t *action_dec_ttl, *action_set_user_token;
    const sai_attribute_value_t *action_set_policer, *action_set_tc, *action_redirect;
    const sai_attribute_value_t *action_set_inner_vlan_id, *action_set_inner_vlan_pri;
    const sai_attribute_value_t *action_set_outer_vlan_id, *action_set_outer_vlan_pri;
    const sai_attribute_value_t *action_flood;
    const sai_attribute_value_t *admin_state;

#ifdef ACL_TODO
    const sai_attribute_value_t *src_ipv6, *dst_ipv6;
    const sai_attribute_value_t *inner_vlan_id, *inner_vlan_pri, *inner_vlan_cfi;
    uint32_t                     inner_vlan_id_index, inner_vlan_pri_index, inner_vlan_cfi_index;
    uint32_t                     src_ipv6_index, dst_ipv6_index;
#endif /* ACL_TODO */
    uint32_t table_id_index, priority_index;
    uint32_t src_mac_index, dst_mac_index, src_ip_index, dst_ip_index;
    uint32_t in_port_index, admin_state_index, in_ports_index;
    uint32_t out_port_index, out_ports_index;
    uint32_t outer_vlan_id_index, outer_vlan_pri_index, outer_vlan_cfi_index;
    uint32_t L4_src_port_index, L4_dst_port_index;
    uint32_t ether_type_index, ip_protocol_index;
    uint32_t ip_tos_index, dscp_index, ecn_index;
    uint32_t ip_type_index, ip_frag_index;
    uint32_t ip_flags_index, tcp_flags_index;
    uint32_t tc_index, ttl_index;
    uint32_t action_set_src_mac_index, action_set_dst_mac_index;
    uint32_t action_set_dscp_index;
    uint32_t packet_action_index, action_counter_index, action_redirect_index;
    uint32_t action_set_policer_index, action_set_tc_index;
    uint32_t action_mirror_ingress_index, action_mirror_egress_index, egress_session_id, ingress_session_id;
    uint32_t action_set_color_index, action_set_ecn_index;
    uint32_t action_set_user_token_index, action_dec_ttl_index;
    uint32_t action_set_inner_vlan_id_index, action_set_inner_vlan_pri_index;
    uint32_t action_set_outer_vlan_id_index, action_set_outer_vlan_pri_index;
    uint32_t action_flood_index, port_key_index = 0;
    uint32_t in_port_data, out_port_data, action_counter_data, action_set_policer_data, action_redirect_data;
    uint32_t port, ports_count = 0, port_counter = 0;
    uint32_t acl_table_id, acl_table_index;
    uint32_t acl_entry_index = 0, entry_id = 0, counter_index = 0;
    uint32_t num_rules       = 0, rule_counter = 0;
    uint32_t stage;
    uint32_t key_desc_index    = 0, acl_table_size = 0;
    uint16_t trap_id           = SX_TRAP_ID_ACL_MIN;
    uint8_t  flex_action_index = 0;
    char     list_str[MAX_LIST_VALUE_STR_LEN];
    char     key_str[MAX_KEY_STR_LEN];
    bool     is_ipv6_present            = false;
    bool     tos_attrib_present         = false;    /* Value is TRUE when TOS FIELD received from user */
    bool     is_redirect_action_present = false;
    uint32_t ii                         = 0;

    SX_LOG_ENTER();

    memset(&pbs_entry, 0, sizeof(pbs_entry));
    memset(&flex_acl_rule, 0, sizeof(flex_acl_rule));
    memset(&ipaddr_data, 0, sizeof(ipaddr_data));
    memset(&ip_address_data, 0, sizeof(ip_address_data));
    memset(&ipaddr_mask, 0, sizeof(ipaddr_mask));
    memset(&ip_address_mask, 0, sizeof(ip_address_mask));

    if (NULL == acl_entry_id) {
        SX_LOG_ERR("NULL acl entry id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, acl_entry_attribs, acl_entry_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }
    sai_attr_list_to_str(attr_count, attr_list, acl_entry_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Entry, %s\n", list_str);

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_TABLE_ID, &table_id, &table_id_index));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(table_id->oid, SAI_OBJECT_TYPE_ACL_TABLE, &acl_table_id, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = db_find_acl_entry_free_index(&acl_entry_index, acl_table_id))) {
        return status;
    }

    sai_db_read_lock();
    stage           = g_sai_db_ptr->acl_db.acl_table_db[acl_table_id].stage;
    acl_table_index = acl_table_id;
    region_id       = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id;
    acl_table_size  = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].table_size;

    status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                       MAX_NUM_OF_ACTIONS, &flex_acl_rule);
    if (SX_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failure to create Entry - %s\n", SX_STATUS_MSG(status));
        sai_db_unlock();
        return sdk_to_sai(status);
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_PRIORITY, &priority, &priority_index))) {          /*
                                                                                                                               *  if ((priority->u32 < SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY)||(priority->u32 > SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY)) {
                                                                                                                               *  SX_LOG_ERR(" priority %u out of range (%u,%u)\n",
                                                                                                                               *  priority->u32,
                                                                                                                               *  SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY,
                                                                                                                               *  SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY );
                                                                                                                               *  return SAI_STATUS_INVALID_ATTR_VALUE_0 + priority_index;
                                                                                                                               *  } */
        if ((priority->u32 <= 0) || (priority->u32 > acl_table_size)) {
            SX_LOG_ERR(" priority %u out of range (%u,%u)\n", priority->u32, 1, acl_table_size);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + priority_index;
            goto out;
        }

        g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset = acl_table_size -
                                                                                                  priority->u32;
    } else { /* Default rule is at last offset*/
        g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset = acl_table_size - 1;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ADMIN_STATE, &admin_state,
                                 &admin_state_index))) {
        flex_acl_rule.valid = admin_state->booldata;
    } else {  /* set default enabled */
        flex_acl_rule.valid = true;
    }

#ifdef ACL_TODO
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6, &src_ipv6, &src_ipv6_index)) {
        is_ipv6_present             = true;
        temp_data_p                 = (uint32_t*)(src_ipv6->aclfield.data.ip6);
        temp_mask_p                 = (uint32_t*)(src_ipv6->aclfield.mask.ip6);
        temp_data_p                 = (uint32_t*)&ipaddr_data.addr.ipv6.s6_addr32[0];
        temp_mask_p                 = (uint32_t*)&ipaddr_mask.addr.ipv6.s6_addr32[0];
        ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_data.addr.ip6,  &src_ipv6->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
        ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_mask.addr.ip6, &src_ipv6->aclfield.mask.ip6, sizeof((ip_address_mask.addr.ip6)));

        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
            goto out;
        }
        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
            goto out;
        }

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sip, temp_data_p,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip, temp_mask_p,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP;
        key_desc_index++;

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sip_part2, temp_data_p + 1,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip_part2, temp_mask_p + 1,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP_PART2;
        key_desc_index++;

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sip_part3, temp_data_p + 2,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip_part3, temp_mask_p + 2,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP_PART3;
        key_desc_index++;

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sip_part4, temp_data_p + 3,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip_part4, temp_mask_p + 3,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP_PART4;
        key_desc_index++;
    }
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6, &dst_ipv6, &dst_ipv6_index)) {
        is_ipv6_present = true;

        temp_data_p                 = (uint32_t*)(dst_ipv6->aclfield.data.ip6);
        temp_mask_p                 = (uint32_t*)(dst_ipv6->aclfield.mask.ip6);
        temp_data_p                 = (uint32_t*)&ipaddr_data.addr.ipv6.s6_addr32[0];
        temp_mask_p                 = (uint32_t*)&ipaddr_mask.addr.ipv6.s6_addr32[0];
        ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_data.addr.ip6,  &dst_ipv6->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
        ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_mask.addr.ip6, &dst_ipv6->aclfield.mask.ip6, sizeof((ip_address_mask.addr.ip6)));

        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
            goto out;
        }
        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
            goto out;
        }
        memcpy(&flex_acl_rule.key_dsc_list_p[key_desc_index].key.dip, temp_data_p,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip, temp_mask_p,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP;
        key_desc_index++;

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dip_part2, temp_data_p + 1,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip_part2, temp_mask_p + 1,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP_PART2;
        key_desc_index++;

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dip_part3, temp_data_p + 2,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip_part3, temp_mask_p + 2,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP_PART3;
        key_desc_index++;

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dip_part4, temp_data_p + 3,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip_part4, temp_mask_p + 3,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP_PART4;
        key_desc_index++;
    }
#endif /* ACL_TODO */

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC, &src_mac, &src_mac_index)) {
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.smac, src_mac->aclfield.data.mac,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.smac));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.smac, src_mac->aclfield.mask.mac,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].mask.smac));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SMAC;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC, &dst_mac, &dst_mac_index)) {
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dmac, dst_mac->aclfield.data.mac,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dmac));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dmac, dst_mac->aclfield.mask.mac,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].mask.dmac));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DMAC;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP, &src_ip, &src_ip_index)) {
        if (is_ipv6_present) {
            SX_LOG_ERR(" Invalid Attribute to Send as IPv6 is already present. \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
        ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ip_address_data.addr.ip4    = src_ip->aclfield.data.ip4;
        ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ip_address_mask.addr.ip4    = src_ip->aclfield.mask.ip4;

        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
            goto out;
        }

        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
            goto out;
        }
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sip, &ipaddr_data,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip, &ipaddr_mask,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIP;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_DST_IP, &dst_ip, &dst_ip_index)) {
        if (is_ipv6_present) {
            SX_LOG_ERR(" Invalid Attribute to Send as IPv6 is already present. \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
        ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ip_address_data.addr.ip4    = dst_ip->aclfield.data.ip4;
        ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ip_address_mask.addr.ip4    = dst_ip->aclfield.mask.ip4;

        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data))) {
            goto out;
        }
        if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask))) {
            goto out;
        }
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dip, &ipaddr_data,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dip));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip, &ipaddr_mask,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dip));
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS, &in_ports, &in_ports_index)) {
        ports_count                                          = in_ports->aclfield.data.objlist.count;
        ports                                                = in_ports;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SRC_PORT;
        port_key_index                                       = key_desc_index;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS, &out_ports, &out_ports_index)) {
        if (stage != SAI_ACL_STAGE_EGRESS) {
            SX_LOG_ERR("Port type and stage do not match\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
        ports_count                                          = out_ports->aclfield.data.objlist.count;
        ports                                                = out_ports;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DST_PORT;
        port_key_index                                       = key_desc_index;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT, &in_port, &in_port_index)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(in_port->aclfield.data.oid, SAI_OBJECT_TYPE_PORT, &in_port_data, NULL))) {
            goto out;
        }
        flex_acl_rule.key_desc_list_p[key_desc_index].key.src_port  = in_port_data;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.src_port = true;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_SRC_PORT;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT, &out_port, &out_port_index)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(out_port->aclfield.data.oid, SAI_OBJECT_TYPE_PORT, &out_port_data, NULL))) {
            goto out;
        }
        if (stage != SAI_ACL_STAGE_EGRESS) {
            SX_LOG_ERR("Port type and stage do not match\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
        flex_acl_rule.key_desc_list_p[key_desc_index].key.dst_port  = out_port_data;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.dst_port = true;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_DST_PORT;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID, &outer_vlan_id,
                            &outer_vlan_id_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.vlan_id  = (outer_vlan_id->aclfield.data.u16) & 0xFFF;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.vlan_id = (outer_vlan_id->aclfield.mask.u16) & 0xFFF;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id       = FLEX_ACL_KEY_VLAN_ID;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI, &outer_vlan_pri,
                            &outer_vlan_pri_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.pcp  = (outer_vlan_pri->aclfield.data.u8) & 0x07;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.pcp = (outer_vlan_pri->aclfield.mask.u8) & 0x07;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id   = FLEX_ACL_KEY_PCP;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI, &outer_vlan_cfi,
                            &outer_vlan_cfi_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.dei  = (outer_vlan_cfi->aclfield.data.u8) & 0x01;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.dei = (outer_vlan_cfi->aclfield.mask.u8) & 0x01;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id   = FLEX_ACL_KEY_DEI;
        key_desc_index++;
    }
#ifdef ACL_TODO
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID, &inner_vlan_id,
                            &inner_vlan_id_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_vlan_id  = (inner_vlan_id->aclfield.data.u16) & 0xFFF;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_vlan_id = (inner_vlan_id->aclfield.mask.u16) & 0xFFF;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_VLAN_ID;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI, &inner_vlan_pri,
                            &inner_vlan_pri_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_pcp  = (inner_vlan_pri->aclfield.data.u8) & 0x07;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_pcp = (inner_vlan_pri->aclfield.mask.u8) & 0x07;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id         = FLEX_ACL_KEY_PCP;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI, &inner_vlan_cfi,
                            &inner_vlan_cfi_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_dei  = (inner_vlan_cfi->aclfield.data.u8) & 0x01;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_dei = (inner_vlan_cfi->aclfield.mask.u8) & 0x01;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id         = FLEX_ACL_KEY_DEI;
        key_desc_index++;
    }
#endif /* ACL_TODO */

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT, &L4_src_port,
                            &L4_src_port_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.l4_source_port  = L4_src_port->aclfield.data.u16;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.l4_source_port = L4_src_port->aclfield.mask.u16;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id              = FLEX_ACL_KEY_L4_SOURCE_PORT;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT, &L4_dst_port,
                            &L4_dst_port_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.l4_destination_port  = L4_dst_port->aclfield.data.u16;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.l4_destination_port = L4_dst_port->aclfield.mask.u16;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id                   = FLEX_ACL_KEY_L4_DESTINATION_PORT;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE, &ether_type,
                            &ether_type_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.ethertype  = ether_type->aclfield.data.u16;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.ethertype = ether_type->aclfield.mask.u16;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id         = FLEX_ACL_KEY_ETHERTYPE;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL, &ip_protocol,
                            &ip_protocol_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_proto  = ip_protocol->aclfield.data.u8;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_proto = ip_protocol->aclfield.mask.u8;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_IP_PROTO;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_TOS, &ip_tos, &ip_tos_index)) {
        tos_attrib_present = true;

        flex_acl_rule.key_desc_list_p[key_desc_index].key.dscp  = (ip_tos->aclfield.data.u8 >> 0x02) & 0x3f;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.dscp = (ip_tos->aclfield.mask.u8 >> 0x02) & 0x3f;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id    = FLEX_ACL_KEY_DSCP;
        key_desc_index++;

        flex_acl_rule.key_desc_list_p[key_desc_index].key.ecn  = (ip_tos->aclfield.data.u8) & 0x03;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.ecn = (ip_tos->aclfield.mask.u8) & 0x03;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id   = FLEX_ACL_KEY_ECN;
        key_desc_index++;
    }
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_DSCP, &dscp, &dscp_index)) {
        if (true == tos_attrib_present) {
            SX_LOG_ERR(" tos attribute already received. \n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + dscp_index;
            goto out;
        }
        flex_acl_rule.key_desc_list_p[key_desc_index].key.dscp  = (dscp->aclfield.data.u8) & 0x3f;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.dscp = (dscp->aclfield.mask.u8) & 0x3f;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id    = FLEX_ACL_KEY_DSCP;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_ECN, &ecn, &ecn_index)) {
        if (true == tos_attrib_present) {
            SX_LOG_ERR(" tos attribute already received. \n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + ecn_index;
            goto out;
        }
        flex_acl_rule.key_desc_list_p[key_desc_index].key.ecn  = (ecn->aclfield.data.u8) & 0x03;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.ecn = (ecn->aclfield.mask.u8) & 0x03;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id   = FLEX_ACL_KEY_ECN;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_TTL, &ttl, &ttl_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.ttl  = ttl->aclfield.data.u8;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.ttl = ttl->aclfield.mask.u8;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id   = FLEX_ACL_KEY_TTL;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS, &ip_flags, &ip_flags_index)) {
        SX_LOG_ERR(" Not supported in present phase \n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;

        /*
         *  flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_flags = ip_flags->aclfield.data.u8;
         *  flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_flags = ip_flags->aclfield.data.u8;
         *  flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_IP_FLAGS;
         *  key_desc_index++;
         */
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS, &tcp_flags, &tcp_flags_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.tcp_control  = tcp_flags->aclfield.data.u8 & 0x3F;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.tcp_control = tcp_flags->aclfield.data.u8 & 0x3F;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_TCP_CONTROL;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IP_FRAG, &ip_frag, &ip_frag_index)) {
        if (SAI_ACL_IP_FRAG_ANY == ip_frag->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_fragmented  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_fragmented = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            key_desc_index++;
        }

        if (SAI_ACL_IP_FRAG_NON_FRAG == ip_frag->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_fragmented  = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_fragmented = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            key_desc_index++;
        }

        if (SAI_ACL_IP_FRAG_NON_FRAG_OR_HEAD == ip_frag->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_fragment_not_first  = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_fragment_not_first = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id                     =
                FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
            key_desc_index++;
        }

        if (SAI_ACL_IP_FRAG_HEAD == ip_frag->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_fragmented  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_fragmented = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            key_desc_index++;
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_fragment_not_first  = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_fragment_not_first = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id                     =
                FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
            key_desc_index++;
        }

        if (SAI_ACL_IP_FRAG_NON_HEAD == ip_frag->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_fragmented  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_fragmented = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
            key_desc_index++;
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_fragment_not_first  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_fragment_not_first = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id                     =
                FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
            key_desc_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_TC, &tc, &tc_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.switch_prio  = tc->aclfield.data.u8 & 0xF;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.switch_prio = tc->aclfield.mask.u8 & 0xF;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_SWITCH_PRIO;
        key_desc_index++;
    }
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE, &ip_type, &ip_type_index)) {
        if (SAI_ACL_IP_TYPE_ANY == ip_type->aclfield.data.s32) {
            /* Do Nothing */
        }
        if (SAI_ACL_IP_TYPE_IP == ip_type->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_ok  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_ok = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id     = FLEX_ACL_KEY_IP_OK;
            key_desc_index++;
        }

        if (SAI_ACL_IP_TYPE_NON_IP == ip_type->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_ok  = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.ip_ok = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id     = FLEX_ACL_KEY_IP_OK;
            key_desc_index++;
        }

        if (SAI_ACL_IP_TYPE_IPv4ANY == ip_type->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v4  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.is_ip_v4 = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_IS_IP_V4;
            key_desc_index++;
        }

        if (SAI_ACL_IP_TYPE_NON_IPv4 == ip_type->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v4  = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.is_ip_v4 = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_IS_IP_V4;
            key_desc_index++;
        }

        if (SAI_ACL_IP_TYPE_IPv6ANY == ip_type->aclfield.data.s32) {
            SX_LOG_ERR(" ip_v6 IP TYPE not supported for current phase \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
            /*
             *  flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v6 = 1;
             *  flex_acl_rule.key_desc_list_p[key_desc_index].mask.is_ip_v6 = 0xFF;
             *  flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_IS_IP_V6;
             *  key_desc_index++;
             */
        }

        if (SAI_ACL_IP_TYPE_NON_IPv6 == ip_type->aclfield.data.s32) {
            SX_LOG_ERR(" ip_v6 IP TYPE not supported for current phase \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
            /*
             *  flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v6 = 0;
             *  flex_acl_rule.key_desc_list_p[key_desc_index].mask.is_ip_v6 = 0xFF;
             *  flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_IS_IP_V6;
             *  key_desc_index++;
             */
        }

        if (SAI_ACL_IP_TYPE_ARP == ip_type->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.is_arp  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.is_arp = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id      = FLEX_ACL_KEY_IS_ARP;
            key_desc_index++;
        }

        if ((SAI_ACL_IP_TYPE_ARP_REQUEST == ip_type->aclfield.data.s32) ||
            (SAI_ACL_IP_TYPE_ARP_REPLY == ip_type->aclfield.data.s32)) {
            SX_LOG_ERR(" Arp Request/Reply Not supported \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
    }
#ifdef ACL_TODO
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META, &tc, &tc_index)) {
        if (((tc->aclfield.data.u32 >> 0x10) == 0) && ((tc->aclfield.mask.u32 >> 0x10) == 0)) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.user_token  = (uint16_t)tc->aclfield.data.u32;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.user_token = (uint16_t)tc->aclfield.mask.u32;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id          = FLEX_ACL_KEY_USER_TOKEN;
            key_desc_index++;
        } else {
            SX_LOG_ERR(" Range of ACL user Meta is not supported \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
    }
#endif /* ACL_TODO */

    /* ACL Field Atributes ...End */
    if (0 == key_desc_index) {
        SX_LOG_ERR(" Mandatory to Send Atleast one ACL Field during ACL Entry Create \n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT, &action_redirect,
                            &action_redirect_index)) {
        if (action_redirect->aclaction.enable == true) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(action_redirect->aclaction.parameter.oid, SAI_OBJECT_TYPE_PORT,
                                         &action_redirect_data,
                                         NULL))) {
                goto out;
            }
            pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_UNICAST;
            pbs_entry.log_ports  = &action_redirect_data;
            pbs_entry.port_num   = 1;
            if (SAI_STATUS_SUCCESS !=
                (ret_status =
                     sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_ADD, swid_id, &pbs_entry,
                                                           &pbs_index))) {
                SX_LOG_ERR("Can't initiate forwarding action for the rule - %s.\n", SX_STATUS_MSG(ret_status));
                status = sdk_to_sai(ret_status);
                goto out;
            }
            is_redirect_action_present                                              = true;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_index;
            flex_acl_rule.action_list_p[flex_action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_PACKET_ACTION, &packet_action,
                            &packet_action_index)) {
        if (packet_action->aclaction.enable == true) {
            packet_action_type = packet_action->aclaction.parameter.s32;
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_acl_packet_actions_handler(packet_action_type, trap_id, &flex_acl_rule,
                                                     &flex_action_index))) {
                goto out;
            }
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_FLOOD, &action_flood,
                            &action_flood_index)) {
        if (action_flood->aclaction.enable == true) {
            if (is_redirect_action_present == true) {
                SX_LOG_ERR(" Redirect Action is already present as an ACL Entry Attribute \n");
                status = SAI_STATUS_INVALID_ATTR_VALUE_0 + action_flood_index;
                goto out;
            }
            pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
            pbs_entry.port_num   = g_sai_db_ptr->ports_number;

            port_arr = (sx_port_log_id_t*)malloc(g_sai_db_ptr->ports_number * sizeof(sx_port_log_id_t));
            if (port_arr == NULL) {
                SX_LOG_ERR(" Unable to allocate memory for port array\n");
                status = SAI_STATUS_NO_MEMORY;
                goto out;
            }

            for (port_counter = 0; port_counter < pbs_entry.port_num; port_counter++) {
                port_arr[port_counter] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[port_counter].logical;
            }

            pbs_entry.log_ports = port_arr;
            if (SAI_STATUS_SUCCESS !=
                (status =
                     sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_ADD, swid_id, &pbs_entry,
                                                           &pbs_index))) {
                SX_LOG_ERR("Can't initiate forwarding action flood for the rule - %s.\n", SX_STATUS_MSG(status));
                status = sdk_to_sai(status);
                goto out;
            }
            flex_acl_rule.action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_index;
            flex_acl_rule.action_list_p[flex_action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_COUNTER, &action_counter,
                            &action_counter_index)) {
        if (action_counter->aclaction.enable == true) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(action_counter->aclaction.parameter.oid, SAI_OBJECT_TYPE_ACL_COUNTER,
                                         &action_counter_data, NULL))) {
                goto out;
            }
            counter_index                                                                   = action_counter_data;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_counter.counter_id = \
                g_sai_db_ptr->acl_db.acl_counter_db[counter_index].counter_id;
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_COUNTER;
            flex_action_index++;

            g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].counter_id =
                action_counter_data;
        }
    } else {
        g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].counter_id =
            SX_FLOW_COUNTER_ID_INVALID;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, &action_mirror_ingress,
                            &action_mirror_ingress_index)) {
        if (SAI_ACL_STAGE_INGRESS != stage) {
            SX_LOG_ERR(" Failure as Stage( Not Ingress ) and Mirror Action Mismatch \n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        if (action_mirror_ingress->aclaction.enable == true) {
            if (action_mirror_ingress->aclaction.parameter.objlist.count != 1) {
                SX_LOG_ERR(" Failure : Only 1 Session ID is associated to an ACL Rule at this phase \n");
                status = SAI_STATUS_NOT_IMPLEMENTED;
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(action_mirror_ingress->aclaction.parameter.objlist.list[0],
                                         SAI_OBJECT_TYPE_MIRROR,
                                         &ingress_session_id, NULL))) {
                goto out;
            }

            flex_acl_rule.action_list_p[flex_action_index].fields.action_mirror.session_id =
                (sx_span_session_id_t)ingress_session_id;
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_MIRROR;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS, &action_mirror_egress,
                            &action_mirror_egress_index)) {
        if (SAI_ACL_STAGE_EGRESS != stage) {
            SX_LOG_ERR(" Failure as Stage( Not Egress ) and Mirror Action Mismatch \n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        if (action_mirror_egress->aclaction.enable == true) {
            if (action_mirror_egress->aclaction.parameter.objlist.count != 1) {
                SX_LOG_ERR(" Failure : Only 1 Session ID is supported in an ACL Rule \n");
                status = SAI_STATUS_NOT_IMPLEMENTED;
                goto out;
            }

            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(action_mirror_egress->aclaction.parameter.objlist.list[0],
                                         SAI_OBJECT_TYPE_MIRROR,
                                         &egress_session_id, NULL))) {
                goto out;
            }

            flex_acl_rule.action_list_p[flex_action_index].fields.action_mirror.session_id =
                (sx_span_session_id_t)egress_session_id;
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_MIRROR;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER, &action_set_policer,
                            &action_set_policer_index)) {
        if (action_set_policer->aclaction.enable == true) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(action_set_policer->aclaction.parameter.oid, SAI_OBJECT_TYPE_POLICER,
                                         &action_set_policer_data, NULL))) {
                goto out;
            }

            /* cl_plock_acquire(&g_sai_db_ptr->p_lock); */
            if (SAI_STATUS_SUCCESS != (status = mlnx_sai_get_or_create_regular_sx_policer_for_bind(
                                           action_set_policer->aclaction.parameter.oid,
                                           &flex_acl_rule.action_list_p[flex_action_index].fields.action_policer.
                                           policer_id))) {
                SX_LOG_ERR("Failed to obtain sx_policer_id. input sai policer object_id:0x%" PRIx64 "\n",
                           action_set_policer->aclaction.parameter.oid);
                /*  cl_plock_release(&g_sai_db_ptr->p_lock); */
                goto out;
            }
            /* cl_plock_release(&g_sai_db_ptr->p_lock); */

            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_POLICER;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC, &action_set_tc,
                            &action_set_tc_index)) {
        if (action_set_tc->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_prio.prio_val =
                action_set_tc->aclaction.parameter.u8;
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_PRIO;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL, &action_dec_ttl,
                            &action_dec_ttl_index)) {
        if (action_dec_ttl->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_dec_ttl.ttl_val = 1;
            flex_acl_rule.action_list_p[flex_action_index].type                          = SX_FLEX_ACL_ACTION_DEC_TTL;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR, &action_set_color,
                            &action_set_color_index)) {
        if (action_set_color->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_color.color_val =
                action_set_color->aclaction.parameter.s32;
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_COLOR;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID,
                            &action_set_inner_vlan_id, &action_set_inner_vlan_id_index)) {
        if (action_set_inner_vlan_id->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_INNER_VLAN_ID;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_id.vlan_id =
                action_set_inner_vlan_id->aclaction.parameter.u16;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI,
                            &action_set_inner_vlan_pri, &action_set_inner_vlan_pri_index)) {
        if (action_set_inner_vlan_pri->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_INNER_VLAN_PRI;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_prio.pcp =
                action_set_inner_vlan_pri->aclaction.parameter.u8;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID,
                            &action_set_outer_vlan_id, &action_set_outer_vlan_id_index)) {
        if (action_set_outer_vlan_id->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_ID;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_id.vlan_id =
                action_set_outer_vlan_id->aclaction.parameter.u16;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI,
                            &action_set_outer_vlan_pri, &action_set_outer_vlan_pri_index)) {
        if (action_set_outer_vlan_pri->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_PRI;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_prio.pcp =
                action_set_outer_vlan_pri->aclaction.parameter.u8;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC, &action_set_src_mac,
                            &action_set_src_mac_index)) {
        if (action_set_src_mac->aclaction.enable == true) {
            memcpy(&flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac, \
                   action_set_src_mac->aclaction.parameter.mac, \
                   sizeof(flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac));
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC, &action_set_dst_mac,
                            &action_set_dst_mac_index)) {
        if (action_set_dst_mac->aclaction.enable == true) {
            memcpy(&flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dst_mac.mac, \
                   action_set_dst_mac->aclaction.parameter.mac, \
                   sizeof(flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dst_mac.mac));
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_DST_MAC;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP, &action_set_dscp,
                            &action_set_dscp_index)) {
        if (action_set_dscp->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dscp.dscp_val = \
                action_set_dscp->aclaction.parameter.u8;
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_DSCP;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN, &action_set_ecn,
                            &action_set_ecn_index)) {
        if (action_set_ecn->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_ecn.ecn_val = \
                action_set_ecn->aclaction.parameter.u8;
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_ECN;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA, &action_set_user_token,
                            &action_set_user_token_index)) {
        if (action_set_user_token->aclaction.parameter.u32 >> 0x10 == 0) {
            if (action_set_user_token->aclaction.enable == true) {
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_user_token.user_token = \
                    (uint16_t)action_set_user_token->aclaction.parameter.u32;
                flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_USER_TOKEN;
                flex_action_index++;
            }
        } else {
            SX_LOG_ERR(" Range of ACL user Meta is not supported \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
    }


    if (ports_count > 0) {
        num_rules += ports->aclfield.data.objlist.count;
    } else {
        num_rules++;
    }

    /* CHECK NUM_RULES + OFFSET <= ACL_TABLE_SIZE */
    if (num_rules + (acl_table_size - priority->u32) > acl_table_size) {
        SX_LOG_ERR("  Failure : The required number of rules exceed the offset parameter range \n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(num_rules * sizeof(sx_flex_acl_flex_rule_t));
    if (flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    offsets_list_p = (sx_acl_rule_offset_t*)malloc(num_rules * sizeof(sx_acl_rule_offset_t));
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for offsets list\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    /* offset value update */
    for (rule_counter = 0; rule_counter < num_rules; rule_counter++) {
        ret_status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                               MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[rule_counter]);
        if (SX_STATUS_SUCCESS != ret_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(ret_status));
            num_rules = rule_counter;
            goto out;
        }
        offsets_list_p[rule_counter]                 = (acl_table_size - priority->u32) + rule_counter;
        flex_acl_rule_p[rule_counter].valid          = flex_acl_rule.valid;
        flex_acl_rule_p[rule_counter].key_desc_count = key_desc_index;
        flex_acl_rule_p[rule_counter].action_count   = flex_action_index;
        memcpy(flex_acl_rule_p[rule_counter].key_desc_list_p, flex_acl_rule.key_desc_list_p,
               sizeof(sx_flex_acl_key_desc_t) * key_desc_index);
        memcpy(flex_acl_rule_p[rule_counter].action_list_p, flex_acl_rule.action_list_p,
               sizeof(sx_flex_acl_flex_action_t) * flex_action_index);
    }

    rule_counter = 0;
    if (ports_count > 0) {
        for (port_counter = 0; port_counter < ports->aclfield.data.objlist.count; port_counter++) {
            if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(ports->aclfield.data.objlist.list[port_counter],
                                                                    SAI_OBJECT_TYPE_PORT, &port, NULL))) {
                goto out;
            }
            if (port_key_id == FLEX_ACL_KEY_SRC_PORT) {
                flex_acl_rule_p[rule_counter].key_desc_list_p[port_key_index].key.src_port  = port;
                flex_acl_rule_p[rule_counter].key_desc_list_p[port_key_index].mask.src_port = true;
            } else {
                flex_acl_rule_p[rule_counter].key_desc_list_p[port_key_index].key.dst_port  = port;
                flex_acl_rule_p[rule_counter].key_desc_list_p[port_key_index].mask.dst_port = true;
            }
            rule_counter++;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id,  offsets_list_p, flex_acl_rule_p,
                                       num_rules))) {
        SX_LOG_ERR("Failed to set FLEX ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset =
        acl_table_size - priority->u32;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules          = num_rules;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].is_entry_allocated = true;
    entry_id                                                                                            =
        (acl_table_id << 0x10) + acl_entry_index;

    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_id, NULL, acl_entry_id))) {
        goto out;
    }

    acl_entry_key_to_str(*acl_entry_id, key_str);
    SX_LOG_NTC("Created acl entry %s\n", key_str);

out:
    if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule))) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
    }

    if (port_arr) {
        free(port_arr);
    }

    if (flex_acl_rule_p) {
        for (ii = 0; ii < num_rules; ii++) {
            if (SX_STATUS_SUCCESS !=
                (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
            }
        }
        free(flex_acl_rule_p);
    }

    if (offsets_list_p) {
        free(offsets_list_p);
    }

    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Failure to ceate Entry \n");
        g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].is_entry_allocated = false;
    }
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

static sai_status_t acl_db_port_bind_set(sx_access_cmd_t    cmd,
                                         sx_acl_direction_t direction,
                                         sx_acl_id_t        acl_id,
                                         sx_port_log_id_t  *port_arr,
                                         uint32_t          *port_num)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if ((cmd != SX_ACCESS_CMD_BIND) && (cmd != SX_ACCESS_CMD_UNBIND)) {
        SX_LOG_ERR("Command Not Supported, cmd type is:%u \n", cmd);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
        /* return SAI_STATUS_INVALID_PARAMETER; */
    }

    if (port_num == NULL) {
        SX_LOG_ERR("NULL port_num %s %d \n", __func__, __LINE__);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (*port_num == 0) {
        SX_LOG_ERR("Wrong number of ports -[%u]. Need to configure more than 0.\n",
                   *port_num);
        return SAI_STATUS_INVALID_PORT_NUMBER;
    }

    if (port_arr == NULL) {
        SX_LOG_ERR("NULL port array %s %d \n", __func__, __LINE__);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status = acl_db_bind_acl_to_ports(direction, cmd, acl_id, port_arr, *port_num))) {
        SX_LOG_ERR("Failure to %s ACL to ports \n ", (cmd == SX_ACCESS_CMD_BIND) ? "bind" : "unbind");
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t acl_db_bind_acl_to_ports(sx_acl_direction_t direction,
                                             sx_access_cmd_t    cmd,
                                             sx_acl_id_t        acl_id,
                                             sx_port_log_id_t  *port_arr,
                                             uint32_t           port_num)
{
    sx_status_t  ret_status = SX_STATUS_SUCCESS;
    sai_status_t status     = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    uint32_t port_index = 0;
    /* Check each port if it is binded to acl_id */

    for (port_index = 0; port_index < port_num; port_index++) {
        if (SX_STATUS_SUCCESS != (ret_status = sx_api_acl_port_bind_set(gh_sdk, cmd, port_arr[port_index], acl_id))) {
            SX_LOG_ERR("Unable to %s  port [%d] to  acl group[%d] - %s.\n ", \
                       (SX_ACCESS_CMD_BIND == cmd) ? "bind" : "unbind", port_arr[port_index], acl_id,
                       SX_STATUS_MSG(ret_status));
            return sdk_to_sai(ret_status);
        }
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t sort_tables_in_group(_In_ uint32_t        stage,
                                         _In_ uint32_t        priority,
                                         _In_ uint32_t        acl_id,
                                         _Inout_ sx_acl_id_t *acl_table_ids,
                                         _In_ uint32_t        acl_count)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     index  = 0, ii;

    SX_LOG_ENTER();

    if (NULL == acl_table_ids) {
        return SAI_STATUS_FAILURE;
    }

    for (index = 0; index < acl_count - 1; index++) {
        if (g_sai_db_ptr->acl_db.acl_group_db[stage].priority[index] < priority) {
            break;
        }
    }

    for (ii = acl_count - 1; ii > index; ii--) {
        acl_table_ids[ii] = acl_table_ids[ii - 1];

        g_sai_db_ptr->acl_db.acl_group_db[stage].priority[ii] = \
            g_sai_db_ptr->acl_db.acl_group_db[stage].priority[ii - 1];
    }
    acl_table_ids[index]                                     = acl_id;
    g_sai_db_ptr->acl_db.acl_group_db[stage].priority[index] = priority;

    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *   Create an ACL table
 *
 * Arguments:
 *  [out] acl_table_id - the the acl table id
 *  [in] attr_count - number of attributes
 *  [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */

static sai_status_t mlnx_create_acl_table(_Out_ sai_object_id_t     * acl_table_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  ret_status;
    const sai_attribute_value_t *stage, *table_size, *priority, *group_id;
    const sai_attribute_value_t *src_mac, *dst_mac, *src_ip, *dst_ip;
    const sai_attribute_value_t *outer_vlan_id, *outer_vlan_pri, *outer_vlan_cfi;
    const sai_attribute_value_t *L4_src_port, *L4_dst_port;
    const sai_attribute_value_t *ether_type, *ip_protocol;
    const sai_attribute_value_t *dscp, *ecn;
    const sai_attribute_value_t *in_port, *out_port, *in_ports, *out_ports;
    const sai_attribute_value_t *ip_type, *ip_frag, *ip_flags, *tcp_flags;
    const sai_attribute_value_t *tc, *ttl, *tos;

#ifdef ACL_TODO
    const sai_attribute_value_t *inner_vlan_id, *inner_vlan_pri, *inner_vlan_cfi;
    const sai_attribute_value_t *user_meta, *src_ip_v6, *dst_ip_v6;
    uint32_t                     src_ip_v6_index, dst_ip_v6_index;
    uint32_t                     inner_vlan_id_index, inner_vlan_pri_index, inner_vlan_cfi_index;
    uint32_t                     user_meta_index;
#endif
    uint32_t                   stage_index, table_size_index, priority_index, group_id_index;
    uint32_t                   src_mac_index, dst_mac_index, src_ip_index, dst_ip_index;
    uint32_t                   outer_vlan_id_index, outer_vlan_pri_index, outer_vlan_cfi_index;
    uint32_t                   L4_src_port_index, L4_dst_port_index;
    uint32_t                   ether_type_index, ip_protocol_index;
    uint32_t                   dscp_index, ecn_index;
    uint32_t                   in_port_index, out_port_index, in_ports_index, out_ports_index;
    uint32_t                   ip_type_index, ip_frag_index, ip_flags_index, tcp_flags_index;
    uint32_t                   tc_index, ttl_index, tos_index;
    uint32_t                   acl_count      = 0, key_count, key_index = 0;
    uint32_t                   acl_table_size = 0;
    uint16_t                   ii             = 0;
    sx_acl_key_type_t          key_handle;
    const sx_acl_action_type_t action_type = SX_ACL_ACTION_TYPE_BASIC;
    const sx_acl_type_t        acl_type    = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_region_id_t         region_id;
    sx_acl_region_group_t      region_group;
    sx_acl_id_t                acl_id, acl_table_index;
    sx_acl_id_t                group_index;
    sx_acl_id_t                acl_table_ids[MAX_INGRESS_TABLE_SIZE];
    char                       list_str[MAX_LIST_VALUE_STR_LEN];
    char                       key_str[MAX_KEY_STR_LEN];
    sx_acl_key_t               keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    bool                       is_dscp_present = false, is_ecn_present = false;
    uint32_t                   port_num;
    sx_port_log_id_t           port_arr[MAX_PORTS];

    SX_LOG_ENTER();

    if (NULL == acl_table_id) {
        SX_LOG_ERR("NULL acl table id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status =
                                   check_attribs_metadata(attr_count, attr_list, acl_table_attribs,
                                                          acl_table_vendor_attribs, SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }
    sai_attr_list_to_str(attr_count, attr_list, acl_table_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Table, %s\n", list_str);

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_STAGE, &stage, &stage_index));

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_PRIORITY, &priority, &priority_index));

    memset(acl_table_ids, 0, sizeof(acl_table_ids));

#ifdef ACL_TODO
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6, &src_ip_v6, &src_ip_v6_index)) {
        if (true == src_ip_v6->booldata) {
            keys[key_index] = FLEX_ACL_KEY_SIP;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_SIP_PART2;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_SIP_PART3;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_SIP_PART4;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6, &dst_ip_v6, &dst_ip_v6_index)) {
        if (true == dst_ip_v6->booldata) {
            keys[key_index] = FLEX_ACL_KEY_DIP;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_DIP_PART2;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_DIP_PART3;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_DIP_PART4;
            key_index++;
        }
    }
#endif /* ACL_TODO */

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC, &src_mac, &src_mac_index)) {
        if (true == src_mac->booldata) {
            keys[key_index] = FLEX_ACL_KEY_SMAC;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_DST_MAC, &dst_mac, &dst_mac_index)) {
        if (true == dst_mac->booldata) {
            keys[key_index] = FLEX_ACL_KEY_DMAC;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_SRC_IP, &src_ip, &src_ip_index)) {
        if (true == src_ip->booldata) {
            keys[key_index] = FLEX_ACL_KEY_SIP;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_DST_IP, &dst_ip, &dst_ip_index)) {
        if (true == dst_ip->booldata) {
            keys[key_index] = FLEX_ACL_KEY_DIP;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS, &in_ports, &in_ports_index)) {
        if (true == in_ports->booldata) {
            keys[key_index] = FLEX_ACL_KEY_SRC_PORT;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS, &out_ports, &out_ports_index)) {
        if (true == out_ports->booldata) {
            keys[key_index] = FLEX_ACL_KEY_DST_PORT;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IN_PORT, &in_port, &in_port_index)) {
        if (true == in_port->booldata) {
            keys[key_index] = FLEX_ACL_KEY_SRC_PORT;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT, &out_port, &out_port_index)) {
        if (true == out_port->booldata) {
            keys[key_index] = FLEX_ACL_KEY_DST_PORT;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID, &outer_vlan_id,
                            &outer_vlan_id_index)) {
        if (true == outer_vlan_id->booldata) {
            keys[key_index] = FLEX_ACL_KEY_VLAN_ID;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_PRI, &outer_vlan_pri,
                            &outer_vlan_pri_index)) {
        if (true == outer_vlan_pri->booldata) {
            keys[key_index] = FLEX_ACL_KEY_PCP;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_CFI, &outer_vlan_cfi,
                            &outer_vlan_cfi_index)) {
        if (true == outer_vlan_cfi->booldata) {
            keys[key_index] = FLEX_ACL_KEY_DEI;
            key_index++;
        }
    }

#ifdef ACL_TODO
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID, &inner_vlan_id,
                            &inner_vlan_id_index)) {
        if (true == inner_vlan_id->booldata) {
            keys[key_index] = FLEX_ACL_KEY_INNER_VLAN_ID;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI, &inner_vlan_pri,
                            &inner_vlan_pri_index)) {
        if (true == inner_vlan_pri->booldata) {
            keys[key_index] = FLEX_ACL_KEY_INNER_PCP;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI, &inner_vlan_cfi,
                            &inner_vlan_cfi_index)) {
        if (true == inner_vlan_cfi->booldata) {
            keys[key_index] = FLEX_ACL_KEY_INNER_DEI;
            key_index++;
        }
    }
#endif /* ACL_TODO */

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT, &L4_src_port,
                            &L4_src_port_index)) {
        if (true == L4_src_port->booldata) {
            keys[key_index] = FLEX_ACL_KEY_L4_SOURCE_PORT;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT, &L4_dst_port,
                            &L4_dst_port_index)) {
        if (true == L4_dst_port->booldata) {
            keys[key_index] = FLEX_ACL_KEY_L4_DESTINATION_PORT;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE, &ether_type,
                            &ether_type_index)) {
        if (true == ether_type->booldata) {
            keys[key_index] = FLEX_ACL_KEY_ETHERTYPE;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,  &ip_protocol,
                            &ip_protocol_index)) {
        if (true == ip_protocol->booldata) {
            keys[key_index] = FLEX_ACL_KEY_IP_PROTO;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_DSCP,  &dscp, &dscp_index)) {
        if (true == dscp->booldata) {
            is_dscp_present = true;
            keys[key_index] = FLEX_ACL_KEY_DSCP;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_ECN,  &ecn, &ecn_index)) {
        if (true == ecn->booldata) {
            is_ecn_present  = true;
            keys[key_index] = FLEX_ACL_KEY_ECN;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_TTL,  &ttl, &ttl_index)) {
        if (true == ttl->booldata) {
            keys[key_index] = FLEX_ACL_KEY_TTL;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_TOS,  &tos, &tos_index)) {
        if (true == tos->booldata) {
            if (!is_dscp_present) {
                keys[key_index] = FLEX_ACL_KEY_DSCP;
                key_index++;
            }
            if (!is_ecn_present) {
                keys[key_index] = FLEX_ACL_KEY_ECN;
                key_index++;
            }
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS, &ip_flags, &ip_flags_index)) {
        if (true == ip_flags->booldata) {
            SX_LOG_ERR(" Not supported in present phase \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
            /*
             *  keys[key_index] = FLEX_ACL_KEY_IP_FLAGS;
             *  key_index++; */
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS, &tcp_flags, &tcp_flags_index)) {
        if (true == tcp_flags->booldata) {
            keys[key_index] = FLEX_ACL_KEY_TCP_CONTROL;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IP_TYPE, &ip_type, &ip_type_index)) {
        if (true == ip_type->booldata) {
            keys[key_index] = FLEX_ACL_KEY_IP_OK;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_IS_IP_V4;
            key_index++;
            /*
             *  keys[key_index] = FLEX_ACL_KEY_IS_IP_V6;
             *  key_index;
             */
            keys[key_index] = FLEX_ACL_KEY_IS_ARP;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IP_FRAG, &ip_frag, &ip_frag_index)) {
        if (true == ip_frag->booldata) {
            keys[key_index] = FLEX_ACL_KEY_IP_FRAGMENTED;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_TC,  &tc, &tc_index)) {
        if (true == tc->booldata) {
            keys[key_index] = FLEX_ACL_KEY_SWITCH_PRIO;
            key_index++;
        }
    }

#ifdef ACL_TODO
    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META, &user_meta,
                            &user_meta_index)) {
        if (true == user_meta->booldata) {
            keys[key_index] = FLEX_ACL_KEY_USER_TOKEN;
            key_index++;
        }
    }
#endif

    key_count = key_index;
    if (SAI_STATUS_SUCCESS !=
        (ret_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_CREATE, keys, key_count, &key_handle))) {
        SX_LOG_ERR(" Failed to create flex key - %s. \n", SX_STATUS_MSG(ret_status));
        return sdk_to_sai(ret_status);
    }

    sai_db_read_lock();
    acl_count = g_sai_db_ptr->acl_db.acl_group_db[stage->s32].acl_table_count;

    /* SDK Group Limit :  16  ACLs in a Group */
    if (acl_count == MAX_ACL_LIMIT_IN_GROUP) {
        SX_LOG_ERR(" Max 16 ACLs are allowed in a group \n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }


    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_GROUP_ID, &group_id, &group_id_index)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(group_id->oid, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &group_index, NULL))) {
            goto out;
        }
        group_index = g_sai_db_ptr->acl_db.acl_group_db[stage->s32].group_id;
    } else {
        group_index = g_sai_db_ptr->acl_db.acl_group_db[stage->s32].group_id;
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_get(gh_sdk, group_index, (sx_acl_direction_t*)&(stage->s32), acl_table_ids,
                                  &acl_count))) {
        SX_LOG_ERR("Failed to get acl group - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    if (SAI_ACL_STAGE_INGRESS == stage->s32) {
        if (acl_count >= MAX_INGRESS_TABLE_SIZE) {
            SX_LOG_ERR(" Max tables for ingress stage have already been created \n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    } else if (SAI_ACL_STAGE_EGRESS == stage->s32) {
        if (acl_count >= MAX_EGRESS_TABLE_SIZE) {
            SX_LOG_ERR(" Max tables for egress stage have already been created \n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }
    /* Check for max tables ends here */

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_SIZE, &table_size, &table_size_index)) {
        if (!table_size->u32) {
            SX_LOG_ERR("Table size received is zero. Value is set to DEFAULT TABLE SIZE \n");
            acl_table_size = DEFAULT_ACL_TABLE_SIZE;
        } else {
            acl_table_size = table_size->u32;
        }
    } else {   /* if table size is not present, use default */
        acl_table_size = DEFAULT_ACL_TABLE_SIZE;
    }

    if (SX_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_CREATE, key_handle, action_type, acl_table_size,
                                   &region_id))) {
        SX_LOG_ERR("Failed to create region - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type                           = acl_type;
    region_group.regions.acl_packet_agnostic.region = region_id;


    if (SAI_STATUS_SUCCESS !=
        (ret_status = sx_api_acl_set(gh_sdk, SX_ACCESS_CMD_CREATE, acl_type, stage->s32, &region_group, &acl_id))) {
        SX_LOG_ERR("Failed to create acl table - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    acl_table_index = acl_id;
    /* Update D.B */
    g_sai_db_ptr->acl_db.acl_group_db[stage->s32].priority[acl_count] = priority->u32;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].table_id       = acl_id;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].table_size     = acl_table_size;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].stage          = stage->s32;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].priority       = priority->u32;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type       = key_handle;
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id      = region_id;

    acl_table_ids[acl_count] = acl_id;
    acl_count                = acl_count + 1;

    /* sort tables in group according to priority */
    if (SAI_STATUS_SUCCESS !=
        (status = sort_tables_in_group(stage->s32, priority->u32, acl_id, acl_table_ids, acl_count))) {
        SX_LOG_ERR(" Unable to sort ACL tables in a group /n");
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, stage->s32, acl_table_ids, acl_count, &group_index))) {
        SX_LOG_ERR("Failed to create acl table - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }
    /* update table count in group */
    g_sai_db_ptr->acl_db.acl_group_db[stage->s32].acl_table_count = acl_count;

    if (acl_count == 1) {
        port_num = g_sai_db_ptr->ports_number;
        if (port_num == 0) {
            SX_LOG_ERR("Unable to get ports from switch \n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        for (ii = 0; ii < port_num; ii++) {
            port_arr[ii] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[ii].logical;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = acl_db_port_bind_set(SX_ACCESS_CMD_BIND, stage->s32, group_index, port_arr, &port_num))) {
            SX_LOG_ERR("Unable to Bind all ports to %s acl group \n",
                       (stage->s32 == SX_ACL_DIRECTION_INGRESS) ? "Ingress" : "Egress");
            goto out;
        }
    }
    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, acl_id, NULL, acl_table_id))) {
        goto out;
    }

    acl_table_key_to_str(*acl_table_id, key_str);
    SX_LOG_NTC("Created acl table %s\n", key_str);

out:
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}


static void acl_table_key_to_str(_In_ sai_object_id_t acl_table_id, _Out_ char *key_str)
{
    uint32_t table_id;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(acl_table_id, SAI_OBJECT_TYPE_ACL_TABLE, &table_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid ACL Table Id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL Table [%u]", table_id);
    }
}

static void acl_entry_key_to_str(_In_ sai_object_id_t acl_entry_id, _Out_ char *key_str)
{
    uint32_t entry_id;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(acl_entry_id, SAI_OBJECT_TYPE_ACL_ENTRY, &entry_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid acl entry id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL Entry [%u]", entry_id);
    }
}

/*
 * Routine Description:
 *   Set ACL table attribute
 *
 * Arguments:
 *    [in] acl_table_id - the acl table id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_acl_table_attribute(_In_ sai_object_id_t acl_table_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = acl_table_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_table_key_to_str(acl_table_id, key_str);
    return sai_set_attribute(&key, key_str, acl_table_attribs, acl_table_vendor_attribs, attr);
}


/*
 * Routine Description:
 *   Get ACL table attribute
 *
 * Arguments:
 *    [in] acl_table_id - acl table id
 *    [in] attr_count - number of attributes
 *    [Out] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_acl_table_attribute(_In_ sai_object_id_t   acl_table_id,
                                                 _In_ uint32_t          attr_count,
                                                 _Out_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = acl_table_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_table_key_to_str(acl_table_id, key_str);
    return sai_get_attributes(&key, key_str, acl_table_attribs, acl_table_vendor_attribs, attr_count, attr_list);
}


static void acl_counter_key_to_str(_In_ sai_object_id_t acl_counter_id, _Out_ char *key_str)
{
    uint32_t counter_id;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(acl_counter_id, SAI_OBJECT_TYPE_ACL_COUNTER, &counter_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid acl counter id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL Counter [%u]", counter_id);
    }
}


/*
 * Routine Description:
 *   Set ACL counter attribute
 *
 * Arguments:
 *    [in] acl_counter_id - the acl counter id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_acl_counter_attribute(_In_ sai_object_id_t        acl_counter_id,
                                                   _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = acl_counter_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_counter_key_to_str(acl_counter_id, key_str);
    return sai_set_attribute(&key, key_str, acl_counter_attribs, acl_counter_vendor_attribs, attr);
}

/*
 * Routine Description:
 *   Get ACL counter attribute
 *
 * Arguments:
 *    [in] acl_counter_id - acl counter id
 *    [in] attr_count - number of attributes
 *    [Out] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_acl_counter_attribute(_In_ sai_object_id_t   acl_counter_id,
                                                   _In_ uint32_t          attr_count,
                                                   _Out_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = acl_counter_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_counter_key_to_str(acl_counter_id, key_str);
    return sai_get_attributes(&key, key_str, acl_counter_attribs, acl_counter_vendor_attribs, attr_count, attr_list);
}

static sai_status_t mlnx_acl_counter_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg)
{
    sai_status_t status;
    sx_status_t  ret_status;
    sx_acl_id_t  acl_counter_id, acl_counter_index;
    uint32_t     counter_id = 0;

    SX_LOG_ENTER();

    assert((SAI_ACL_COUNTER_ATTR_PACKETS == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_BYTES == (int64_t)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_COUNTER, &acl_counter_id, NULL))) {
        return status;
    }

    sai_db_read_lock();
    acl_counter_index = acl_counter_id;

    if (value->u64 == 0) {
        counter_id = g_sai_db_ptr->acl_db.acl_counter_db[acl_counter_index].counter_id;
        if (SX_STATUS_SUCCESS != (ret_status = sx_api_flow_counter_clear_set(gh_sdk, counter_id))) {
            SX_LOG_ERR("Failed to clear counter: [%d] - %s \n", acl_counter_id, SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
    }

out:
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_counter_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    sx_status_t           ret_status;
    sai_status_t          status;
    sx_acl_id_t           acl_counter_id, acl_counter_index;
    sx_flow_counter_set_t counter_value;
    sx_flow_counter_id_t  counter_id;

    SX_LOG_ENTER();
    assert((SAI_ACL_COUNTER_ATTR_PACKETS == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_BYTES == (int64_t)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_COUNTER, &acl_counter_id, NULL))) {
        return status;
    }

    sai_db_read_lock();

    acl_counter_index = acl_counter_id;
    counter_id        = g_sai_db_ptr->acl_db.acl_counter_db[acl_counter_index].counter_id;

    if (SAI_STATUS_SUCCESS !=
        (ret_status = sx_api_flow_counter_get(gh_sdk, SX_ACCESS_CMD_READ, counter_id, &counter_value))) {
        SX_LOG_ERR(" Failure to get counter in SDK - %s \n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_COUNTER_ATTR_BYTES:
        value->u64 = counter_value.flow_counter_bytes;
        break;

    case SAI_ACL_COUNTER_ATTR_PACKETS:
        value->u64 = counter_value.flow_counter_packets;
        break;
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}


static sai_status_t db_find_acl_counter_free_index(_Out_ uint32_t *free_index)
{
    uint32_t     ii;
    sai_status_t status;

    if (NULL == free_index) {
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_ENTER();

    for (ii = 0; ii < MAX_ACL_COUNTER_NUM; ii++) {
        if (false == g_sai_db_ptr->acl_db.acl_counter_db[ii].is_valid) {
            *free_index                                      = ii;
            g_sai_db_ptr->acl_db.acl_counter_db[ii].is_valid = true;
            status                                           = SAI_STATUS_SUCCESS;
            break;
        }
    }

    if (MAX_ACL_COUNTER_NUM == ii) {
        SX_LOG_ERR("ACL Table counter table full\n");
        status = SAI_STATUS_TABLE_FULL;
    }

    SX_LOG_EXIT();
    return status;
}


static sai_status_t mlnx_acl_counter_flag_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    sx_acl_id_t acl_counter_id, counter_index;

    assert((SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT == (int64_t)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ACL_COUNTER, &acl_counter_id, NULL))) {
        return status;
    }

    sai_db_read_lock();
    counter_index = acl_counter_id;
    switch ((int64_t)arg) {
    case SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT:
        value->booldata = g_sai_db_ptr->acl_db.acl_counter_db[counter_index].packet_counter_flag;
        break;

    case SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT:
        value->booldata = g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag;
        break;
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *   Create an ACL counter
 *
 * Arguments:
 *   [out] acl_counter_id - the acl counter id
 *   [in] attr_count - number of attributes
 *   [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_acl_counter(_Out_ sai_object_id_t      *acl_counter_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  ret_status;
    const sai_attribute_value_t *byte_counter_flag, *packet_counter_flag, *table_id;
    uint32_t                     byte_counter_flag_index, packet_counter_flag_index;
    uint32_t                     table_id_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_flow_counter_type_t       counter_type;
    sx_flow_counter_id_t         counter_id;
    uint32_t                     acl_table_id, counter_index = 0;

    SX_LOG_ENTER();

    if (NULL == acl_counter_id) {
        SX_LOG_ERR("NULL acl counter id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status =
                                   check_attribs_metadata(attr_count, attr_list, acl_counter_attribs,
                                                          acl_counter_vendor_attribs, SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }
    sai_attr_list_to_str(attr_count, attr_list, acl_counter_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Counter, %s\n", list_str);


    /* get table id from attributes */
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_ACL_COUNTER_ATTR_TABLE_ID, &table_id, &table_id_index));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(table_id->oid, SAI_OBJECT_TYPE_ACL_TABLE, &acl_table_id, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = db_find_acl_counter_free_index(&counter_index))) {
        return status;
    }

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
                                      &byte_counter_flag, &byte_counter_flag_index))) {
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag = byte_counter_flag->booldata;

        if (byte_counter_flag->booldata == true) {
            counter_type = SX_FLOW_COUNTER_TYPE_BYTES;
        }
    } else {
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag = false;
    }


    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
                            &packet_counter_flag, &packet_counter_flag_index)) {
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].packet_counter_flag = packet_counter_flag->booldata;

        if (packet_counter_flag->booldata == true) {
            if (g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag) {
                counter_type = SX_FLOW_COUNTER_TYPE_PACKETS_AND_BYTES;
            } else {
                counter_type = SX_FLOW_COUNTER_TYPE_PACKETS;
            }
        }
    } else {
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].packet_counter_flag = false;
    }

    if (!(g_sai_db_ptr->acl_db.acl_counter_db[counter_index].packet_counter_flag) &&
        !(g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag)) {
        SX_LOG_ERR(" Failure to create Counter as both counter types [ byte & packet] are false.\n ");
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].is_valid = false;
        status                                                      = SAI_STATUS_FAILURE;
        goto out;
    }

    if (SX_STATUS_SUCCESS !=
        (ret_status = sx_api_flow_counter_set(gh_sdk, SX_ACCESS_CMD_CREATE, counter_type, &counter_id))) {
        SX_LOG_ERR("Failure to create Counter - %s.\n", SX_STATUS_MSG(ret_status));
        status                                                      = sdk_to_sai(ret_status);
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].is_valid = false;
        goto out;
    }
    g_sai_db_ptr->acl_db.acl_counter_db[counter_index].counter_id = counter_id;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_index, NULL, acl_counter_id))) {
        goto out;
    }

    acl_counter_key_to_str(*acl_counter_id, key_str);
    SX_LOG_NTC("Created acl counter %s\n", key_str);


out:
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

/*
 *  Routine Description:
 *   Set ACL Entry attribute
 *
 *    Arguments:
 *       [in] acl_entry_id - acl entry id
 *       [in] attr -attribute to set
 *
 *    Return Values:
 *       SAI_STATUS_SUCCESS on success
 *       Failure status code on error
 */

static sai_status_t mlnx_set_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = acl_entry_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_entry_key_to_str(acl_entry_id, key_str);
    return sai_set_attribute(&key, key_str, acl_entry_attribs, acl_entry_vendor_attribs, attr);
}
/*
 * Routine Description:
 *   Get ACL Entry attribute
 *
 * Arguments:
 *    [in] acl_entry_id - acl entry id
 *    [in] attr_count - number of attributes
 *    [Out] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */

static sai_status_t mlnx_get_acl_entry_attribute(_In_ sai_object_id_t   acl_entry_id,
                                                 _In_ uint32_t          attr_count,
                                                 _Out_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = acl_entry_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_entry_key_to_str(acl_entry_id, key_str);
    return sai_get_attributes(&key, key_str, acl_entry_attribs, acl_entry_vendor_attribs, attr_count, attr_list);
}

/*
 *  Routine Description:
 *  Delete an ACL Entry
 *
 *    Arguments:
 *      [in] acl_entry_id - acl entry id
 *
 *    Return Values:
 *       SAI_STATUS_SUCCESS on success
 *       Failure status code on error
 **/
static sai_status_t mlnx_delete_acl_entry(_In_ sai_object_id_t acl_entry_id)
{
    sx_status_t               ret_status;
    sai_status_t              status;
    char                      key_str[MAX_KEY_STR_LEN];
    uint32_t                  entry_id, acl_entry_index, acl_table_index;
    sx_acl_region_id_t        region_id;
    sx_flex_acl_rule_offset_t rule_offset, *offsets_list_p = NULL;
    sx_flex_acl_flex_rule_t  *flex_acl_rules_p = NULL;
    uint32_t                  offset_index;
    uint32_t                  flex_acl_rules_num = 0;
    uint32_t                  action_index;
    sx_acl_pbs_entry_t        pbs_entry;
    sx_swid_t                 swid_id = 0;
    sx_port_id_t              port_arr[MAX_PORTS];
    sx_acl_pbs_id_t           pbs_id;
    bool                      is_action_type_present = false;
    uint32_t                  ii                     = 0;

    SX_LOG_ENTER();
    acl_entry_key_to_str(acl_entry_id, key_str);
    SX_LOG_NTC("Delete ACL Entry %s\n", key_str);

    memset(port_arr, 0, sizeof(port_arr));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(acl_entry_id, SAI_OBJECT_TYPE_ACL_ENTRY, &entry_id, NULL))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = extract_acl_table_index_and_entry_index(entry_id, &acl_table_index, &acl_entry_index))) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        return status;
    }
    sai_db_read_lock();
    if (false == g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].is_entry_allocated) {
        SX_LOG_ERR(" Failure : ACL Rule doesn't exist \n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    flex_acl_rules_num = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].num_rules;
    rule_offset        = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].offset;
    region_id          = g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].region_id;

    flex_acl_rules_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);
    if (flex_acl_rules_p == NULL) {
        SX_LOG_ERR(" unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    offsets_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);
    if (offsets_list_p == NULL) {
        SX_LOG_ERR(" unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(flex_acl_rules_p, 0, sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);
    memset(offsets_list_p, 0, sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);

    for (offset_index = 0; offset_index < flex_acl_rules_num; offset_index++) {
        offsets_list_p[offset_index] = rule_offset + offset_index;
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        ret_status = sx_lib_flex_acl_rule_init(g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].key_type,
                                               MAX_NUM_OF_ACTIONS, &flex_acl_rules_p[ii]);
        if (SX_STATUS_SUCCESS != ret_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(ret_status));
            status             = sdk_to_sai(ret_status);
            flex_acl_rules_num = ii;
            goto out;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        (ret_status =
             sx_api_acl_flex_rules_get(gh_sdk, region_id, offsets_list_p, flex_acl_rules_p, &flex_acl_rules_num))) {
        if (0 == flex_acl_rules_num) {
            SX_LOG_ERR("Number of rules at start offset [%d] from region [%u] in SDK - %s\n",
                       rule_offset,
                       region_id,
                       SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
    } else {
        SX_LOG_ERR("Failed to retrieve rules from region [%u] in SDK - %s\n", region_id, SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    /* Check if PBS entry is associated or not */
    for (action_index = 0; action_index < flex_acl_rules_p[0].action_count; action_index++) {
        if (flex_acl_rules_p[0].action_list_p[action_index].type == SX_FLEX_ACL_ACTION_PBS) {
            is_action_type_present = true;
            pbs_id                 = flex_acl_rules_p[0].action_list_p[action_index].fields.action_pbs.pbs_id;
            break;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_DELETE, region_id, offsets_list_p, flex_acl_rules_p,
                                       flex_acl_rules_num))) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }
    g_sai_db_ptr->acl_db.acl_table_db[acl_table_index].acl_entry_db[acl_entry_index].is_entry_allocated = false;

    /* Delete PBS Entries after deleting the ACL Entry */
    if (is_action_type_present == true) {
        memset(&pbs_entry, 0, sizeof(pbs_entry));
        memset(port_arr, 0, sizeof(port_arr));
        pbs_entry.log_ports = port_arr;

        if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_policy_based_switching_get(gh_sdk,
                                                                                      SX_ACCESS_CMD_GET,
                                                                                      swid_id,
                                                                                      pbs_id,
                                                                                      &pbs_entry))) {
            SX_LOG_ERR("failed to get UC PBS in SDK  %s.\n", SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
        if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_policy_based_switching_set(gh_sdk,
                                                                                      SX_ACCESS_CMD_DELETE,
                                                                                      swid_id,
                                                                                      &pbs_entry,
                                                                                      &pbs_id))) {
            SX_LOG_ERR("failed to DELETE old PBS Entry  %s.\n", SX_STATUS_MSG(ret_status));
            status = sdk_to_sai(ret_status);
            goto out;
        }
    }

out:
    sai_db_sync();
    sai_db_unlock();
    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (SX_STATUS_SUCCESS != (ret_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rules_p[ii]))) {
            SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(ret_status));
        }
    }
    if (flex_acl_rules_p) {
        free(flex_acl_rules_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }
    SX_LOG_EXIT();
    return status;
}


/*
 * Routine Description:
 *   Delete an ACL table
 *
 * Arguments:
 *   [in] acl_table_id - the acl table id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */

static sai_status_t mlnx_delete_acl_table(_In_ sai_object_id_t acl_table_id)
{
    char                  key_str[MAX_KEY_STR_LEN];
    sx_acl_id_t           table_id, table_index;
    sai_status_t          status;
    sx_status_t           ret_status;
    sx_acl_region_id_t    region_id;
    sx_acl_direction_t    acl_direction;
    sx_acl_region_group_t region_group;
    uint32_t              region_size;
    const sx_acl_type_t   acl_type = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_id_t           acl_table_ids[MAX_INGRESS_TABLE_SIZE];
    sx_acl_id_t           group_id = 0;
    sx_port_log_id_t      port_arr[MAX_PORTS];
    uint32_t              port_num = 0;
    sx_acl_key_type_t     key_handle;
    uint32_t              ii        = 0, index = 0;
    uint32_t              acl_count = 0, key_count = 0;
    uint32_t              entry_id;
    sai_object_id_t       acl_entry_id;
    sx_acl_key_t          keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    bool                  is_table_present_in_group = false;

    SX_LOG_ENTER();

    acl_table_key_to_str(acl_table_id, key_str);
    SX_LOG_NTC("Delete ACL Table %s\n", key_str);

    memset(acl_table_ids, 0, sizeof(acl_table_ids));
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(acl_table_id, SAI_OBJECT_TYPE_ACL_TABLE, &table_id, NULL))) {
        return status;
    }

    sai_db_write_lock();
    table_index   = table_id;
    region_id     = g_sai_db_ptr->acl_db.acl_table_db[table_index].region_id;
    acl_direction = g_sai_db_ptr->acl_db.acl_table_db[table_index].stage;
    region_size   = g_sai_db_ptr->acl_db.acl_table_db[table_index].table_size;
    group_id      = g_sai_db_ptr->acl_db.acl_group_db[acl_direction].group_id;
    acl_count     = g_sai_db_ptr->acl_db.acl_group_db[acl_direction].acl_table_count;

    if (SX_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_get(gh_sdk, group_id, (sx_acl_direction_t*)&(acl_direction), acl_table_ids,
                                  &acl_count))) {
        SX_LOG_ERR("Failed to get acl group - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    for (index = 0; index < acl_count; index++) {
        if (acl_table_ids[index] == table_id) {
            is_table_present_in_group = true;
            break;
        }
    }

    if (false == is_table_present_in_group) {
        SX_LOG_ERR(" Failure to delete ACL Table which doesnot exist in SDK. \n");
        goto out;
    }

    for (; index < acl_count - 1; index++) {
        acl_table_ids[index]                                                  = acl_table_ids[index + 1];
        g_sai_db_ptr->acl_db.acl_group_db[acl_direction].priority[index + ii] =
            g_sai_db_ptr->acl_db.acl_group_db[acl_direction].priority[index + ii + 1];
    }

    if (1 == acl_count) {
        port_num = g_sai_db_ptr->ports_number;
        for (ii = 0; ii < port_num; ii++) {
            port_arr[ii] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[ii].logical;
        }

        /* Unbind  all ports to ACL group */
        if (SAI_STATUS_SUCCESS !=
            (status = acl_db_port_bind_set(SX_ACCESS_CMD_UNBIND, acl_direction, group_id, port_arr, &port_num))) {
            SX_LOG_ERR("Unable to unbind all ports to %s acl group \n",
                       acl_direction == SX_ACL_DIRECTION_INGRESS ? "Ingress" : "Egress");
            goto out;
        }
    }

    acl_count = acl_count - 1;


    if (SX_STATUS_SUCCESS !=
        (ret_status =
             sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, acl_direction, acl_table_ids, acl_count, &group_id))) {
        SX_LOG_ERR("Failed to delete acl table [%d] from group [%d]\n - %s", table_id, group_id,
                   SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    for (ii = 0; ii < MAX_ACL_ENTRY_NUM; ii++) {
        if (g_sai_db_ptr->acl_db.acl_table_db[table_id].acl_entry_db[ii].is_entry_allocated) {
            entry_id = (table_id << 0x10) + ii;
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_id, NULL, &acl_entry_id))) {
                goto out;
            }
            sai_db_sync();
            sai_db_unlock();
            if (SAI_STATUS_SUCCESS != (status = mlnx_delete_acl_entry(acl_entry_id))) {
                SX_LOG_ERR(" Failed to delete ACL Entry. \n");
                sai_db_write_lock();
                goto out;
            }
            sai_db_write_lock();
        }
    }

    /* destroy the ACL */
    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type                           = acl_type;
    region_group.regions.acl_packet_agnostic.region = region_id;

    if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_set(gh_sdk,
                                                           SX_ACCESS_CMD_DESTROY,
                                                           SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC,
                                                           acl_direction,
                                                           &region_group,
                                                           &(table_id)))) {
        SX_LOG_ERR("Failed to destroy ACL - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    g_sai_db_ptr->acl_db.acl_group_db[acl_direction].acl_table_count = acl_count;

    if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_region_set(gh_sdk,
                                                                  SX_ACCESS_CMD_DESTROY,
                                                                  SX_ACL_KEY_TYPE_MAC_IPV4_FULL,
                                                                  SX_ACL_ACTION_TYPE_BASIC,
                                                                  region_size,
                                                                  &region_id))) {
        SX_LOG_ERR(" Failed to delete region ACL - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    key_handle = g_sai_db_ptr->acl_db.acl_table_db[table_index].key_type;

    if (SAI_STATUS_SUCCESS != (ret_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, keys, &key_count))) {
        SX_LOG_ERR(" Failed to get flex keys - %s. \n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (ret_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_DELETE, keys, key_count, &key_handle))) {
        SX_LOG_ERR(" Failed to delete flex keys - %s. \n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }

out:
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}
/*
 *  Routine Description:
 *   Delete an ACL counter
 *
 *    Arguments:
 *      [in] acl_counter_id - ACL counter id
 *
 *    Return Values:
 *       SAI_STATUS_SUCCESS on success
 *       Failure status code on error
 */

static sai_status_t mlnx_delete_acl_counter(_In_ sai_object_id_t acl_counter_id)
{
    sx_status_t            ret_status;
    char                   key_str[MAX_KEY_STR_LEN];
    uint32_t               counter_id, counter_index, flow_counter_id;
    sai_status_t           status;
    bool                   is_byte_counter, is_packet_counter;
    sx_flow_counter_type_t counter_type;

    SX_LOG_ENTER();

    acl_counter_key_to_str(acl_counter_id, key_str);
    SX_LOG_NTC("Delete ACL Counter %s\n", key_str);
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(acl_counter_id, SAI_OBJECT_TYPE_ACL_COUNTER, &counter_id, NULL))) {
        return status;
    }

    sai_db_read_lock();
    counter_index     = counter_id;
    is_byte_counter   = g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag;
    is_packet_counter = g_sai_db_ptr->acl_db.acl_counter_db[counter_index].packet_counter_flag;

    if (is_byte_counter && is_packet_counter) {
        counter_type = SX_FLOW_COUNTER_TYPE_PACKETS_AND_BYTES;
    } else if (is_byte_counter) {
        counter_type = SX_FLOW_COUNTER_TYPE_BYTES;
    } else if (is_packet_counter) {
        counter_type = SX_FLOW_COUNTER_TYPE_PACKETS;
    } else {
        SX_LOG_ERR("counter to be deleted does not exist\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    flow_counter_id = g_sai_db_ptr->acl_db.acl_counter_db[counter_index].counter_id;

    if (SAI_STATUS_SUCCESS !=
        (ret_status = sx_api_flow_counter_set(gh_sdk, SX_ACCESS_CMD_DESTROY, counter_type, &flow_counter_id))) {
        SX_LOG_ERR("Failed delete counter - %s.\n", SX_STATUS_MSG(ret_status));
        status = sdk_to_sai(ret_status);
        goto out;
    }
    switch (counter_type) {
    case SX_FLOW_COUNTER_TYPE_PACKETS:
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].packet_counter_flag = false;
        break;

    case SX_FLOW_COUNTER_TYPE_BYTES:
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag = false;
        break;

    case SX_FLOW_COUNTER_TYPE_PACKETS_AND_BYTES:
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].packet_counter_flag = false;
        g_sai_db_ptr->acl_db.acl_counter_db[counter_index].byte_counter_flag   = false;
        break;

    default:
        SX_LOG_ERR("counter type not supported \n");
        goto out;
    }

    g_sai_db_ptr->acl_db.acl_counter_db[counter_index].is_valid = false;


out:
    SX_LOG_EXIT();
    sai_db_sync();
    sai_db_unlock();
    return status;
}

static void acl_range_key_to_str(_In_ sai_object_id_t acl_range_id, _Out_ char *key_str)
{
    uint32_t range_id;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(acl_range_id, SAI_OBJECT_TYPE_ACL_RANGE, &range_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid acl range id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL range [%u]", range_id);
    }
}

/**
 *   Routine Description:
 *     @brief Create an ACL Range
 *
 *  Arguments:
 *  @param[out] acl_range_id - the acl range id
 *  @param[in] attr_count - number of attributes
 *  @param[in] attr_list - array of attributes
 *
 *  Return Values:
 *    @return  SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */
static sai_status_t mlnx_create_acl_range(_Out_ sai_object_id_t     * acl_range_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 *  Routine Description:
 *    @brief Remove an ACL Range
 *
 *  Arguments:
 *    @param[in] acl_range_id - the acl range id
 *
 *  Return Values:
 *    @return  SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */
static sai_status_t mlnx_remove_acl_range(_In_ sai_object_id_t acl_range_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * Routine Description:
 *   @brief Set ACL range attribute
 *
 * Arguments:
 *    @param[in] acl_range_id - the acl range id
 *    @param[in] attr - attribute
 *
 * Return Values:
 *    @return  SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */
static sai_status_t mlnx_set_acl_range_attribute(_In_ sai_object_id_t acl_range_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = acl_range_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_range_key_to_str(acl_range_id, key_str);
    return sai_set_attribute(&key, key_str, acl_range_attribs, acl_range_vendor_attribs, attr);
}

/**
 * Routine Description:
 *   @brief Get ACL range attribute
 *
 * Arguments:
 *    @param[in] acl_range_id - acl range id
 *    @param[in] attr_count - number of attributes
 *    @param[out] attr_list - array of attributes
 *
 * Return Values:
 *    @return  SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */
static sai_status_t mlnx_get_acl_range_attribute(_In_ sai_object_id_t   acl_range_id,
                                                 _In_ uint32_t          attr_count,
                                                 _Out_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = acl_range_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_range_key_to_str(acl_range_id, key_str);
    return sai_get_attributes(&key, key_str, acl_range_attribs, acl_range_vendor_attribs, attr_count, attr_list);
}


const sai_acl_api_t mlnx_acl_api = {
    mlnx_create_acl_table,
    mlnx_delete_acl_table,
    mlnx_set_acl_table_attribute,
    mlnx_get_acl_table_attribute,
    mlnx_create_acl_entry,
    mlnx_delete_acl_entry,
    mlnx_set_acl_entry_attribute,
    mlnx_get_acl_entry_attribute,
    mlnx_create_acl_counter,
    mlnx_delete_acl_counter,
    mlnx_set_acl_counter_attribute,
    mlnx_get_acl_counter_attribute,
    mlnx_create_acl_range,
    mlnx_remove_acl_range,
    mlnx_set_acl_range_attribute,
    mlnx_get_acl_range_attribute
};
