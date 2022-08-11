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
#include <sx/sdk/sx_api_tunnel.h>
#include <sx/sdk/sx_api_rm.h>

#undef  __MODULE__
#define __MODULE__ SAI_TUNNEL

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_sai_get_tunnel_attribs(_In_ sai_object_id_t         sai_tunnel_id,
                                                _Out_ sx_tunnel_attribute_t *sx_tunnel_attr);
static sai_status_t mlnx_sai_get_tunnel_cos_data(_In_ sai_object_id_t        sai_tunnel_id,
                                                 _Out_ sx_tunnel_cos_data_t *sx_tunnel_cos_data);
static sai_status_t mlnx_sai_get_tunnel_ttl_data(_In_ sai_object_id_t        sai_tunnel_id,
                                                 _Out_ sx_tunnel_ttl_data_t *sx_tunnel_ttl_data);
static sai_status_t mlnx_convert_sai_tunnel_type_to_sx_ipv4(_In_ sai_tunnel_type_t    sai_type,
                                                            _In_ sai_ip_addr_family_t sai_ip_type,
                                                            _Out_ sx_tunnel_type_e   *sx_type);
static sai_status_t mlnx_convert_sai_tunnel_type_to_sx_ipv6(_In_ sai_tunnel_type_t    sai_type,
                                                            _In_ sai_ip_addr_family_t sai_ip_type,
                                                            _Out_ sx_tunnel_type_e   *sx_type);
static sai_status_t mlnx_convert_sx_tunnel_type_to_sai(_In_ sx_tunnel_type_e    sx_tunnel_attr,
                                                       _Out_ sai_tunnel_type_t *sai_type);
sai_status_t mlnx_sai_tunnel_to_sx_tunnel_id(_In_ sai_object_id_t sai_tunnel_id, _Out_ sx_tunnel_id_t *sx_tunnel_id);
static sai_status_t mlnx_get_tunnel_type_by_tunnel_id(_In_ sai_object_id_t    tunnel_oid,
                                                      _Out_ sx_tunnel_type_e *tunnel_type);
static sai_status_t mlnx_sai_get_sai_rif_id(_In_ sai_object_id_t        sai_tunnel_id,
                                            _In_ tunnel_rif_type        sai_tunnel_rif_type,
                                            _In_ sx_tunnel_attribute_t *sx_tunnel_attr,
                                            _Out_ sai_object_id_t      *sai_rif);
static sai_status_t mlnx_tunnel_per_map_array_add(_In_ uint32_t tunnel_idx, _In_ sai_object_id_t tunnel_map_oid);
static sai_status_t mlnx_tunnel_per_map_array_delete(_In_ uint32_t tunnel_idx, _In_ sai_object_id_t tunnel_map_oid);
static sai_status_t mlnx_sai_create_vxlan_tunnel_map_list(_In_ sai_object_id_t      *sai_tunnel_mapper_list,
                                                          _In_ uint32_t              sai_tunnel_mapper_cnt,
                                                          _In_ tunnel_direction_type sai_tunnel_map_type,
                                                          _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                          _In_ sx_access_cmd_t       cmd);
static sai_status_t mlnx_tunnel_map_entry_set_bmtor_obj(_In_ uint32_t tunnel_map_entry_idx,
                                                        _In_ uint32_t tunnel_idx,
                                                        _In_ bool     is_add);
static sai_status_t mlnx_tunnel_map_attr_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_tunnel_map_attr_entry_list_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_tunnel_map_entry_attr_tunnel_map_type_get(_In_ const sai_object_key_t   *key,
                                                                   _Inout_ sai_attribute_value_t *value,
                                                                   _In_ uint32_t                  attr_index,
                                                                   _Inout_ vendor_cache_t        *cache,
                                                                   void                          *arg);
static sai_status_t mlnx_tunnel_map_entry_attr_tunnel_map_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg);
static sai_status_t mlnx_tunnel_map_entry_attr_key_value_get(_In_ const sai_object_key_t   *key,
                                                             _Inout_ sai_attribute_value_t *value,
                                                             _In_ uint32_t                  attr_index,
                                                             _Inout_ vendor_cache_t        *cache,
                                                             void                          *arg);
static sai_status_t mlnx_tunnel_type_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_tunnel_rif_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_tunnel_peer_mode_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_tunnel_encap_src_ip_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_tunnel_ttl_mode_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_tunnel_ttl_val_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_tunnel_dscp_mode_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_tunnel_dscp_val_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_tunnel_encap_gre_key_valid_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_tunnel_encap_gre_key_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_tunnel_encap_ecn_mode_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_tunnel_decap_ecn_mode_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_tunnel_mappers_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_tunnel_mappers_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);
static sai_status_t mlnx_tunnel_vxlan_udp_sport_attr_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg);
static sai_status_t mlnx_tunnel_vxlan_udp_sport_attr_set(_In_ const sai_object_key_t      *key,
                                                         _In_ const sai_attribute_value_t *value,
                                                         void                             *arg);
static sai_status_t mlnx_tunnel_loopback_packet_action_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg);
static sai_status_t mlnx_tunnel_loopback_packet_action_set(_In_ const sai_object_key_t      *key,
                                                           _In_ const sai_attribute_value_t *value,
                                                           void                             *arg);
static sai_status_t mlnx_tunnel_term_table_entry_vr_id_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg);
static sai_status_t mlnx_tunnel_term_table_entry_type_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg);
static sai_status_t mlnx_tunnel_term_table_entry_dst_ip_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg);
static sai_status_t mlnx_tunnel_term_table_entry_src_ip_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg);
static sai_status_t mlnx_tunnel_term_table_entry_tunnel_type_get(_In_ const sai_object_key_t   *key,
                                                                 _Inout_ sai_attribute_value_t *value,
                                                                 _In_ uint32_t                  attr_index,
                                                                 _Inout_ vendor_cache_t        *cache,
                                                                 void                          *arg);
static sai_status_t mlnx_tunnel_term_table_entry_tunnel_id_get(_In_ const sai_object_key_t   *key,
                                                               _Inout_ sai_attribute_value_t *value,
                                                               _In_ uint32_t                  attr_index,
                                                               _Inout_ vendor_cache_t        *cache,
                                                               void                          *arg);
static sai_status_t mlnx_tunnel_stats_get(_In_ sai_object_id_t      tunnel_id,
                                          _In_ uint32_t             number_of_counters,
                                          _In_ const sai_stat_id_t *counter_ids,
                                          _In_ bool                 clear,
                                          _Out_ uint64_t           *counters);
static bool is_underlay_rif_used_by_other_tunnels(_In_ uint32_t              tunnel_db_idx,
                                                  _In_ sx_router_interface_t sx_rif);
/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t tunnel_map_entry_vendor_attribs[] = {
    { SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_tunnel_map_type_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_tunnel_map_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_OECN_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_OECN_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_UECN_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_UECN_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_VLAN_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_VLAN_ID_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_VNI_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_VNI_ID_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_BRIDGE_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_BRIDGE_ID_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_VR_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_entry_attr_key_value_get, (void*)MLNX_VR_ID_VALUE,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        tunnel_map_entry_enum_info[] = {
    [SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN,
        SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN,
        SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID,
        SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI,
        SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF,
        SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI,
        SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID,
        SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI)
};
const mlnx_obj_type_attrs_info_t          mlnx_tunnel_map_entry_obj_type_info =
{ tunnel_map_entry_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(tunnel_map_entry_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};

/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t tunnel_map_vendor_attribs[] = {
    { SAI_TUNNEL_MAP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_attr_type_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ATTR_ENTRY_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_tunnel_map_attr_entry_list_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        tunnel_map_enum_info[] = {
    [SAI_TUNNEL_MAP_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN,
        SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN,
        SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID,
        SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI,
        SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF,
        SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI,
        SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID,
        SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI)
};
const mlnx_obj_type_attrs_info_t          mlnx_tunnel_map_obj_type_info =
{ tunnel_map_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(tunnel_map_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};

/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t tunnel_vendor_attribs[] = {
    { SAI_TUNNEL_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_type_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_rif_get, (void*)MLNX_TUNNEL_UNDERLAY,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_OVERLAY_INTERFACE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_rif_get, (void*)MLNX_TUNNEL_OVERLAY,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_PEER_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_peer_mode_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_SRC_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_encap_src_ip_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_TTL_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_ttl_mode_get, (void*)TUNNEL_ENCAP,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_TTL_VAL,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_ttl_val_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_dscp_mode_get, (void*)TUNNEL_ENCAP,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_dscp_val_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_encap_gre_key_valid_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_GRE_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_encap_gre_key_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_ECN_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_encap_ecn_mode_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_MAPPERS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_mappers_get, (void*)TUNNEL_ENCAP,
      mlnx_tunnel_mappers_set, (void*)TUNNEL_ENCAP },
    { SAI_TUNNEL_ATTR_DECAP_ECN_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_decap_ecn_mode_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_DECAP_MAPPERS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_mappers_get, (void*)TUNNEL_DECAP,
      mlnx_tunnel_mappers_set, (void*)TUNNEL_DECAP },
    { SAI_TUNNEL_ATTR_DECAP_TTL_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_ttl_mode_get, (void*)TUNNEL_DECAP,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_DECAP_DSCP_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_dscp_mode_get, (void*)TUNNEL_DECAP,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_vxlan_udp_sport_attr_get, (void*)SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MODE,
      mlnx_tunnel_vxlan_udp_sport_attr_set, (void*)SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MODE},
    { SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_vxlan_udp_sport_attr_get, (void*)SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT,
      mlnx_tunnel_vxlan_udp_sport_attr_set, (void*)SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT},
    { SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MASK,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_vxlan_udp_sport_attr_get, (void*)SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MASK,
      mlnx_tunnel_vxlan_udp_sport_attr_set, (void*)SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MASK},
    { SAI_TUNNEL_ATTR_LOOPBACK_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_loopback_packet_action_get, NULL,
      mlnx_tunnel_loopback_packet_action_set, NULL},
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        tunnel_enum_info[] = {
    [SAI_TUNNEL_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_TUNNEL_TYPE_IPINIP,
        SAI_TUNNEL_TYPE_IPINIP_GRE,
        SAI_TUNNEL_TYPE_VXLAN),
    [SAI_TUNNEL_ATTR_PEER_MODE] = ATTR_ENUM_VALUES_LIST(
        SAI_TUNNEL_PEER_MODE_P2MP),
    [SAI_TUNNEL_ATTR_ENCAP_TTL_MODE] = ATTR_ENUM_VALUES_LIST(
        SAI_TUNNEL_TTL_MODE_PIPE_MODEL, SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL),
    [SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_TUNNEL_ATTR_ENCAP_ECN_MODE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_TUNNEL_ATTR_DECAP_TTL_MODE] = ATTR_ENUM_VALUES_LIST(
        SAI_TUNNEL_TTL_MODE_PIPE_MODEL),
    [SAI_TUNNEL_ATTR_DECAP_DSCP_MODE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_TUNNEL_ATTR_DECAP_ECN_MODE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MODE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_TUNNEL_ATTR_LOOPBACK_PACKET_ACTION] = ATTR_ENUM_VALUES_LIST(
        SAI_PACKET_ACTION_DROP),
};
static const sai_stat_capability_t        tunnel_stats_capabilities[] = {
    { SAI_TUNNEL_STAT_IN_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_TUNNEL_STAT_OUT_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
};
const mlnx_obj_type_attrs_info_t          mlnx_tunnel_obj_type_info =
{ tunnel_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(tunnel_enum_info), OBJ_STAT_CAP_INFO(tunnel_stats_capabilities)};
/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t tunnel_term_table_entry_vendor_attribs[] = {
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_term_table_entry_vr_id_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_term_table_entry_type_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_term_table_entry_dst_ip_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_term_table_entry_src_ip_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_term_table_entry_tunnel_type_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_term_table_entry_tunnel_id_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        tunnel_term_table_entry_enum_info[] = {
    [SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_TUNNEL_TYPE_IPINIP,
        SAI_TUNNEL_TYPE_IPINIP_GRE,
        SAI_TUNNEL_TYPE_VXLAN),
};
const mlnx_obj_type_attrs_info_t          mlnx_tunnel_term_table_entry_type_info =
{ tunnel_term_table_entry_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(tunnel_term_table_entry_enum_info),
  OBJ_STAT_CAP_INFO_EMPTY()};
static void tunnel_map_key_to_str(_In_ const sai_object_id_t sai_tunnel_map_obj_id, _Out_ char *key_str)
{
    uint32_t internal_tunnel_map_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_tunnel_map_obj_id, SAI_OBJECT_TYPE_TUNNEL_MAP, &internal_tunnel_map_obj_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid sai tunnel map obj ID %" PRIx64 "", sai_tunnel_map_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "tunnel map ID %d",
                 internal_tunnel_map_obj_id);
    }

    SX_LOG_EXIT();
}

static void tunnel_map_entry_key_to_str(_In_ const sai_object_id_t sai_tunnel_map_entry_obj_id, _Out_ char *key_str)
{
    uint32_t internal_tunnel_map_entry_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_tunnel_map_entry_obj_id, SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY,
                            &internal_tunnel_map_entry_obj_id, NULL)) {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "Invalid sai tunnel map entry obj ID %" PRIx64 "",
                 sai_tunnel_map_entry_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "tunnel map entry ID %d",
                 internal_tunnel_map_entry_obj_id);
    }

    SX_LOG_EXIT();
}

static void tunnel_key_to_str(_In_ const sai_object_id_t sai_tunnel_obj_id, _Out_ char *key_str)
{
    uint32_t internal_tunnel_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_tunnel_obj_id, SAI_OBJECT_TYPE_TUNNEL, &internal_tunnel_obj_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid sai tunnel obj ID %" PRIx64 "", sai_tunnel_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "tunnel ID %d",
                 internal_tunnel_obj_id);
    }

    SX_LOG_EXIT();
}

sai_status_t mlnx_tunnel_availability_get(_In_ sai_object_id_t        switch_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list,
                                          _Out_ uint64_t             *count)
{
    const int          ipinip_sx_tunnel_types[] = {
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4,
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6,
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV4,
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV6,
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE,
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV4_WITH_GRE,
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6_WITH_GRE,
        SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_GRE,
        -1
    }, nve_sx_tunnel_types[] = {
        SX_TUNNEL_TYPE_NVE_VXLAN,
        SX_TUNNEL_TYPE_NVE_VXLAN_IPV6,
        -1
    };
    sx_status_t        sx_status;
    sai_tunnel_type_t  tunnel_type;
    sx_tunnel_filter_t sx_tunnel_filter;
    uint32_t           ii, sai_db_idx_start, sai_db_idx_end, specific_tunnel_type_count;
    uint64_t           tunnels_available_sai = 0, tunnels_available_sx = 0;
    const int         *sx_tunnel_types = NULL;

    assert(attr_list);
    assert(count);

    if (attr_count != 1) {
        SX_LOG_ERR("Unexpected attribute list (size != 1)\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (attr_list[0].id != SAI_TUNNEL_ATTR_TYPE) {
        SX_LOG_ERR("Unexpected attribute %d, expected SAI_TUNNEL_ATTR_TYPE\n", attr_list[0].id);
        return SAI_STATUS_INVALID_ATTRIBUTE_0;
    }

    tunnel_type = attr_list[0].value.s32;
    switch (tunnel_type) {
    case SAI_TUNNEL_TYPE_IPINIP:
    case SAI_TUNNEL_TYPE_IPINIP_GRE:
        sai_db_idx_start = MLNX_MAX_TUNNEL_NVE;
        sai_db_idx_end = MAX_TUNNEL_DB_SIZE;
        tunnels_available_sx = MLNX_MAX_TUNNEL_IPINIP;
        sx_tunnel_types = ipinip_sx_tunnel_types;
        break;

    case SAI_TUNNEL_TYPE_VXLAN:
        sai_db_idx_start = 0;
        sai_db_idx_end = MLNX_MAX_TUNNEL_NVE;
        tunnels_available_sx = MLNX_MAX_TUNNEL_NVE;
        sx_tunnel_types = nve_sx_tunnel_types;
        break;

    case SAI_TUNNEL_TYPE_MPLS:
        SX_LOG_ERR("Tunnel MPLS type is not supported yet\n");
        return SAI_STATUS_NOT_IMPLEMENTED;

    default:
        SX_LOG_ERR("Unsupported tunnel type - %d\n", tunnel_type);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    assert(sx_tunnel_types);

    for (; (*sx_tunnel_types) >= 0; ++sx_tunnel_types) {
        specific_tunnel_type_count = 0;
        memset(&sx_tunnel_filter, 0, sizeof(sx_tunnel_filter_t));
        sx_tunnel_filter.type = *sx_tunnel_types;
        sx_tunnel_filter.filter_by_type = SX_TUNNEL_KEY_FILTER_FIELD_VALID;
        sx_tunnel_filter.filter_by_direction = SX_TUNNEL_KEY_FILTER_FIELD_NOT_VALID;

        sx_status = sx_api_tunnel_iter_get(gh_sdk,
                                           SX_ACCESS_CMD_GET,
                                           0,
                                           &sx_tunnel_filter,
                                           NULL,
                                           &specific_tunnel_type_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get count of sx tunnels type %d - %s\n", *sx_tunnel_types, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        tunnels_available_sx -= (uint64_t)specific_tunnel_type_count;
    }

    for (ii = sai_db_idx_start; ii < sai_db_idx_end; ++ii) {
        if (!g_sai_tunnel_db_ptr->tunnel_entry_db[ii].is_used) {
            ++tunnels_available_sai;
        }
    }

    *count = (uint64_t)MIN(tunnels_available_sai, tunnels_available_sx);
    return SAI_STATUS_SUCCESS;
}

static void tunnel_term_table_entry_key_to_str(_In_ const sai_object_id_t sai_tunnel_term_table_entry_obj_id,
                                               _Out_ char                *key_str)
{
    uint32_t internal_tunnel_term_table_entry_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_tunnel_term_table_entry_obj_id, SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                            &internal_tunnel_term_table_entry_obj_id, NULL)) {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "Invalid sai tunnel term table entry obj ID %" PRIx64 "",
                 sai_tunnel_term_table_entry_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "tunnel term table entry ID %d",
                 internal_tunnel_term_table_entry_obj_id);
    }

    SX_LOG_EXIT();
}

sai_status_t mlnx_tunnel_term_table_entry_availability_get(_In_ sai_object_id_t        switch_id,
                                                           _In_ uint32_t               attr_count,
                                                           _In_ const sai_attribute_t *attr_list,
                                                           _Out_ uint64_t             *count)
{
    rm_sdk_table_type_e  table_type;
    sx_status_t          sx_status;
    sai_ip_addr_family_t family;
    uint32_t             available_entries = 0;

    assert(attr_list);
    assert(count);

    if (attr_count != 1) {
        SX_LOG_ERR("Unexpected attribute list (size != 1)\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (attr_list[0].id != SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_IP_ADDR_FAMILY) {
        SX_LOG_ERR("Unexpected attribute %d, expected SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_IP_ADDR_FAMILY\n",
                   attr_list[0].id);
        return SAI_STATUS_INVALID_ATTRIBUTE_0;
    }

    family = attr_list[0].value.s32;
    switch (family) {
    case SAI_IP_ADDR_FAMILY_IPV4:
        table_type = RM_SDK_TABLE_TYPE_DECAP_RULES_IPV4_E;
        break;

    case SAI_IP_ADDR_FAMILY_IPV6:
        table_type = RM_SDK_TABLE_TYPE_DECAP_RULES_IPV6_E;
        break;

    default:
        SX_LOG_ERR("Unsupported IP address family - %d\n", family);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    sx_status = sx_api_rm_free_entries_by_type_get(gh_sdk, table_type, &available_entries);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get a number of free resources for sx table %d - %s\n", table_type,
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    *count = (uint64_t)available_entries;
    return SAI_STATUS_SUCCESS;
}

static void mlnx_tunnel_fill_ulay_domain_rif(_In_ sx_router_interface_t              rif,
                                             _In_ sx_router_id_t                     uvird,
                                             _Out_ sx_router_interface_t            *sx_rif,
                                             _Out_ sx_router_id_t                   *sx_uvird,
                                             _Out_ sx_tunnel_underlay_domain_type_e *ulay_domain_type)
{
    sx_chip_types_t chip_type = g_sai_db_ptr->sx_chip_type;

    assert(sx_rif);
    assert(ulay_domain_type);

    switch (chip_type) {
    case SX_CHIP_TYPE_SPECTRUM:
    case SX_CHIP_TYPE_SPECTRUM_A1:
        *ulay_domain_type = SX_TUNNEL_UNDERLAY_DOMAIN_TYPE_VRID;
        *sx_rif = 0;
        if (sx_uvird) {
            *sx_uvird = uvird;
        }
        break;

    case SX_CHIP_TYPE_SPECTRUM2:
    case SX_CHIP_TYPE_SPECTRUM3:
    case SX_CHIP_TYPE_SPECTRUM4:
        *ulay_domain_type = SX_TUNNEL_UNDERLAY_DOMAIN_TYPE_RIF;
        *sx_rif = rif;
        if (sx_uvird) {
            *sx_uvird = uvird;
        }
        break;

    default:
        SX_LOG_ERR("g_sai_db_ptr->sxd_chip_type = %s\n", SX_CHIP_TYPE_STR(chip_type));
        *ulay_domain_type = SX_TUNNEL_UNDERLAY_DOMAIN_TYPE_MAX + 1;
    }
}

/* caller needs to guard this function with lock */
static sai_status_t mlnx_get_sai_tunnel_map_db_idx(_In_ sai_object_id_t sai_tunnel_map_obj_id,
                                                   _Out_ uint32_t      *tunnel_mapper_db_idx)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_idx = 0;

    SX_LOG_ENTER();

    if (NULL == tunnel_mapper_db_idx) {
        SX_LOG_ERR("tunnel mapper db idx is null ptr\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_tunnel_map_obj_id, SAI_OBJECT_TYPE_TUNNEL_MAP, &tunnel_map_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai tunnel map obj id: %" PRIx64 "\n", sai_tunnel_map_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (MLNX_TUNNEL_MAP_MAX <= tunnel_map_idx) {
        SX_LOG_ERR("tunnel map idx %d is bigger than upper bound %d\n", tunnel_map_idx, MLNX_TUNNEL_MAP_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (!g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].in_use) {
        SX_LOG_ERR("Non-exist tunnel map idx: %d\n", tunnel_map_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    *tunnel_mapper_db_idx = tunnel_map_idx;

    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard the call with lock */
static sai_status_t mlnx_tunnel_map_db_param_get(_In_ const sai_object_id_t sai_tunnel_map_obj_id,
                                                 _Out_ mlnx_tunnel_map_t   *mlnx_tunnel_map)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_get_sai_tunnel_map_db_idx(sai_tunnel_map_obj_id, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel mapper db idx from tunnel mapper obj id %" PRIx64 "\n",
                   sai_tunnel_map_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (!g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].in_use) {
        SX_LOG_ERR("Non-exist tunnel map idx: %d\n", tunnel_map_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    memcpy(mlnx_tunnel_map, &g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx], sizeof(mlnx_tunnel_map_t));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_map_db_param_get_from_db(_In_ const sai_object_id_t sai_tunnel_map_obj_id,
                                                         _Out_ mlnx_tunnel_map_t   *mlnx_tunnel_map)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    assert(NULL != g_sai_tunnel_db_ptr);

    sai_db_read_lock();

    sai_status = mlnx_tunnel_map_db_param_get(sai_tunnel_map_obj_id, mlnx_tunnel_map);

    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Fail to get mlnx tunnel map param for sai tunnel map obj id %" PRIx64 "\n", sai_tunnel_map_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    return sai_status;
}

static sai_status_t mlnx_tunnel_map_attr_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    mlnx_tunnel_map_t mlnx_tunnel_map;
    sai_status_t      sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_db_param_get_from_db(key->key.object_id, &mlnx_tunnel_map))) {
        SX_LOG_ERR("Fail to get mlnx tunnel map for tunnel map obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    value->s32 = mlnx_tunnel_map.tunnel_map_type;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_map_attr_entry_list_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    mlnx_tunnel_map_t mlnx_tunnel_map;
    sai_status_t      sai_status = SAI_STATUS_FAILURE;
    sai_object_id_t  *tunnel_map_entries = NULL;
    uint32_t          tunnel_map_entries_count, ii;

    SX_LOG_ENTER();

    sai_status = mlnx_tunnel_map_db_param_get_from_db(key->key.object_id, &mlnx_tunnel_map);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Fail to get mlnx tunnel map for tunnel map obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    tunnel_map_entries = calloc(mlnx_tunnel_map.tunnel_map_entry_cnt, sizeof(sai_object_id_t));
    if (!tunnel_map_entries) {
        SX_LOG_ERR("Failed to allocate memory\n");
        SX_LOG_EXIT();
        return SAI_STATUS_NO_MEMORY;
    }

    sai_db_read_lock();

    tunnel_map_entries_count = 0;
    for (ii = mlnx_tunnel_map.tunnel_map_entry_head_idx;
         ii != MLNX_TUNNEL_MAP_ENTRY_INVALID;
         ii = g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].next_tunnel_map_entry_idx) {
        sai_status = mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, ii, NULL,
                                        &tunnel_map_entries[tunnel_map_entries_count]);
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        tunnel_map_entries_count++;
    }

    assert(tunnel_map_entries_count == mlnx_tunnel_map.tunnel_map_entry_cnt);

    sai_status = mlnx_fill_objlist(tunnel_map_entries, tunnel_map_entries_count, &value->objlist);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

out:
    sai_db_unlock();
    free(tunnel_map_entries);
    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard this function with lock */
static sai_status_t mlnx_get_sai_tunnel_map_entry_db_idx(_In_ sai_object_id_t sai_tunnel_map_entry_obj_id,
                                                         _Out_ uint32_t      *tunnel_map_entry_db_idx)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_entry_idx = 0;

    SX_LOG_ENTER();

    if (NULL == tunnel_map_entry_db_idx) {
        SX_LOG_ERR("tunnel map entry db idx is null ptr\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_tunnel_map_entry_obj_id, SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, &tunnel_map_entry_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai tunnel map entry obj id: %" PRIx64 "\n", sai_tunnel_map_entry_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (MLNX_TUNNEL_MAP_ENTRY_MAX <= tunnel_map_entry_idx) {
        SX_LOG_ERR("tunnel map entry idx %d is bigger than upper bound %d\n",
                   tunnel_map_entry_idx,
                   MLNX_TUNNEL_MAP_ENTRY_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (!g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].in_use) {
        SX_LOG_ERR("Non-exist tunnel map entry idx: %d\n", tunnel_map_entry_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    *tunnel_map_entry_db_idx = tunnel_map_entry_idx;

    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard the call with lock */
static sai_status_t mlnx_tunnel_map_entry_db_param_get(_In_ const sai_object_id_t     sai_tunnel_map_entry_obj_id,
                                                       _Out_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_entry_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_get_sai_tunnel_map_entry_db_idx(sai_tunnel_map_entry_obj_id, &tunnel_map_entry_idx))) {
        SX_LOG_ERR("Error getting tunnel map entry db idx from tunnel map entry obj id %" PRIx64 "\n",
                   sai_tunnel_map_entry_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (!g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].in_use) {
        SX_LOG_ERR("Non-exist tunnel map entry idx: %d\n", tunnel_map_entry_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    memcpy(mlnx_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(mlnx_tunnel_map_entry_t));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_map_entry_db_param_get_from_db(
    _In_ const sai_object_id_t     sai_tunnel_map_entry_obj_id,
    _Out_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    assert(NULL != g_sai_tunnel_db_ptr);

    sai_db_read_lock();

    sai_status = mlnx_tunnel_map_entry_db_param_get(sai_tunnel_map_entry_obj_id, mlnx_tunnel_map_entry);

    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Fail to get mlnx tunnel map entry param for sai tunnel map entry obj id %" PRIx64 "\n",
                   sai_tunnel_map_entry_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    return sai_status;
}

static sai_status_t mlnx_tunnel_map_entry_attr_tunnel_map_type_get(_In_ const sai_object_key_t   *key,
                                                                   _Inout_ sai_attribute_value_t *value,
                                                                   _In_ uint32_t                  attr_index,
                                                                   _Inout_ vendor_cache_t        *cache,
                                                                   void                          *arg)
{
    mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry;
    sai_status_t            sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_entry_db_param_get_from_db(key->key.object_id, &mlnx_tunnel_map_entry))) {
        SX_LOG_ERR("Fail to get mlnx tunnel map entry for tunnel map entry obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    value->s32 = mlnx_tunnel_map_entry.tunnel_map_type;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_map_entry_attr_tunnel_map_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg)
{
    mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry;
    sai_status_t            sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_entry_db_param_get_from_db(key->key.object_id, &mlnx_tunnel_map_entry))) {
        SX_LOG_ERR("Fail to get mlnx tunnel map entry for tunnel map entry obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    value->oid = mlnx_tunnel_map_entry.tunnel_map_id;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_map_entry_attr_key_value_get(_In_ const sai_object_key_t   *key,
                                                             _Inout_ sai_attribute_value_t *value,
                                                             _In_ uint32_t                  attr_index,
                                                             _Inout_ vendor_cache_t        *cache,
                                                             void                          *arg)
{
    mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry;
    sai_status_t            sai_status = SAI_STATUS_FAILURE;

    assert((MLNX_OECN_KEY == (long)arg) ||
           (MLNX_OECN_VALUE == (long)arg) ||
           (MLNX_UECN_KEY == (long)arg) ||
           (MLNX_UECN_VALUE == (long)arg) ||
           (MLNX_VLAN_ID_KEY == (long)arg) ||
           (MLNX_VLAN_ID_VALUE == (long)arg) ||
           (MLNX_VNI_ID_KEY == (long)arg) ||
           (MLNX_VNI_ID_VALUE == (long)arg) ||
           (MLNX_BRIDGE_ID_KEY == (long)arg) ||
           (MLNX_BRIDGE_ID_VALUE == (long)arg) ||
           (MLNX_VR_ID_KEY == (long)arg) ||
           (MLNX_VR_ID_VALUE == (long)arg));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_entry_db_param_get_from_db(key->key.object_id, &mlnx_tunnel_map_entry))) {
        SX_LOG_ERR("Fail to get mlnx tunnel map entry for tunnel map entry obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    switch ((long)arg) {
    case MLNX_OECN_KEY:
        value->u8 = mlnx_tunnel_map_entry.oecn_key;
        break;

    case MLNX_OECN_VALUE:
        value->u8 = mlnx_tunnel_map_entry.oecn_value;
        break;

    case MLNX_UECN_KEY:
        value->u8 = mlnx_tunnel_map_entry.uecn_key;
        break;

    case MLNX_UECN_VALUE:
        value->u8 = mlnx_tunnel_map_entry.uecn_value;
        break;

    case MLNX_VLAN_ID_KEY:
        value->u16 = mlnx_tunnel_map_entry.vlan_id_key;
        break;

    case MLNX_VLAN_ID_VALUE:
        value->u16 = mlnx_tunnel_map_entry.vlan_id_value;
        break;

    case MLNX_VNI_ID_KEY:
        value->u32 = mlnx_tunnel_map_entry.vni_id_key;
        break;

    case MLNX_VNI_ID_VALUE:
        value->u32 = mlnx_tunnel_map_entry.vni_id_value;
        break;

    case MLNX_BRIDGE_ID_KEY:
        value->oid = mlnx_tunnel_map_entry.bridge_id_key;
        break;

    case MLNX_BRIDGE_ID_VALUE:
        value->oid = mlnx_tunnel_map_entry.bridge_id_value;
        break;

    case MLNX_VR_ID_KEY:
        value->oid = mlnx_tunnel_map_entry.vr_id_key;
        break;

    case MLNX_VR_ID_VALUE:
        value->oid = mlnx_tunnel_map_entry.vr_id_value;
        break;

    default:
        SX_LOG_ERR("Unrecognized tunnel map entry argument %ld\n", (long)arg);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_type_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    sai_status_t          sai_status;
    sx_tunnel_attribute_t sx_tunnel_attr;
    sai_tunnel_type_t     sai_tunnel_type;

    SX_LOG_ENTER();
    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    sai_db_unlock();
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting tunnel attributes\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_convert_sx_tunnel_type_to_sai(sx_tunnel_attr.type, &sai_tunnel_type))) {
        SX_LOG_ERR("Error converting sx tunnel type to sai\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    value->s32 = sai_tunnel_type;

    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard this function with lock */
sai_status_t mlnx_get_sai_tunnel_db_idx(_In_ sai_object_id_t sai_tunnel_id, _Out_ uint32_t *tunnel_db_idx)
{
    sai_status_t sai_status;

    SX_LOG_ENTER();
    if (!tunnel_db_idx) {
        SX_LOG_ERR("NULL tunnel db idx\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_tunnel_id, SAI_OBJECT_TYPE_TUNNEL, tunnel_db_idx, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (*tunnel_db_idx >= MAX_TUNNEL_DB_SIZE) {
        SX_LOG_ERR("tunnel db index:%d out of bounds:%d\n", *tunnel_db_idx, MAX_TUNNEL_DB_SIZE);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    if (!g_sai_tunnel_db_ptr->tunnel_entry_db[*tunnel_db_idx].is_used) {
        SX_LOG_ERR("tunnel db index:%d item marked as not used\n", *tunnel_db_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard this function with lock */
static sai_status_t mlnx_get_tunnel_db_entry(_In_ sai_object_id_t       sai_tunnel_id,
                                             _Out_ mlnx_tunnel_entry_t *sai_tunnel_db_entry)
{
    sai_status_t sai_status;
    uint32_t     tunnel_db_idx;

    SX_LOG_ENTER();

    if (NULL == sai_tunnel_db_entry) {
        SX_LOG_ERR("SAI tunnel db entry pointer is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    memcpy(sai_tunnel_db_entry, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx], sizeof(mlnx_tunnel_entry_t));

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_get_sai_rif_id(_In_ sai_object_id_t        sai_tunnel_id,
                                            _In_ tunnel_rif_type        sai_tunnel_rif_type,
                                            _In_ sx_tunnel_attribute_t *sx_tunnel_attr,
                                            _Out_ sai_object_id_t      *sai_rif)
{
    sai_status_t          sai_status;
    sx_router_interface_t sdk_rif = 0;
    mlnx_tunnel_entry_t   sai_tunnel_db_entry;

    SX_LOG_ENTER();

    switch (sx_tunnel_attr->type) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
        switch (sai_tunnel_rif_type) {
        case MLNX_TUNNEL_OVERLAY:
            sdk_rif = sx_tunnel_attr->attributes.ipinip_p2p.overlay_rif;
            break;

        case MLNX_TUNNEL_UNDERLAY:
            sai_db_read_lock();
            if (SAI_STATUS_SUCCESS !=
                (sai_status = mlnx_get_tunnel_db_entry(sai_tunnel_id,
                                                       &sai_tunnel_db_entry))) {
                SX_LOG_ERR("Failed to get tunnel db entry for sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
                sai_db_unlock();
                SX_LOG_EXIT();
                return sai_status;
            }
            sai_db_unlock();

            *sai_rif = sai_tunnel_db_entry.sai_underlay_rif;

            break;

        default:
            SX_LOG_ERR("Unrecognized sai tunnel rif type %d\n", sai_tunnel_rif_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;
        }
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
        switch (sai_tunnel_rif_type) {
        case MLNX_TUNNEL_OVERLAY:
            sdk_rif = sx_tunnel_attr->attributes.ipinip_p2p_gre.overlay_rif;
            break;

        case MLNX_TUNNEL_UNDERLAY:
            sai_db_read_lock();
            if (SAI_STATUS_SUCCESS !=
                (sai_status = mlnx_get_tunnel_db_entry(sai_tunnel_id,
                                                       &sai_tunnel_db_entry))) {
                SX_LOG_ERR("Failed to get tunnel db entry for sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
                sai_db_unlock();
                SX_LOG_EXIT();
                return sai_status;
            }
            sai_db_unlock();

            *sai_rif = sai_tunnel_db_entry.sai_underlay_rif;

            break;

        default:
            SX_LOG_ERR("Unrecognized sai tunnel rif type %d\n", sai_tunnel_rif_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;
        }
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
    case SX_TUNNEL_TYPE_NVE_VXLAN_IPV6:
        sai_db_read_lock();
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_get_tunnel_db_entry(sai_tunnel_id,
                                                   &sai_tunnel_db_entry))) {
            SX_LOG_ERR("Failed to get tunnel db entry for sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
            sai_db_unlock();
            SX_LOG_EXIT();
            return sai_status;
        }
        sai_db_unlock();
        switch (sai_tunnel_rif_type) {
        case MLNX_TUNNEL_OVERLAY:
            SX_LOG_ERR("Overlay rif is not valid for vxlan tunnel\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;

        case MLNX_TUNNEL_UNDERLAY:
            *sai_rif = sai_tunnel_db_entry.sai_underlay_rif;
            break;

        default:
            SX_LOG_ERR("Unrecognized sai tunnel rif type %d\n", sai_tunnel_rif_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported tunnel type:%d\n", sx_tunnel_attr->type);
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if ((MLNX_TUNNEL_OVERLAY == sai_tunnel_rif_type) &&
        ((SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4 == sx_tunnel_attr->type) ||
         (SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE == sx_tunnel_attr->type))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_rif_sx_to_sai_oid(sdk_rif, sai_rif))) {
            SX_LOG_ERR("Error getting sai rif object from sdk rif %d\n", sdk_rif);
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_rif_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_attribute_t sx_tunnel_attr;

    SX_LOG_ENTER();

    assert((MLNX_TUNNEL_OVERLAY == (long)arg) || (MLNX_TUNNEL_UNDERLAY == (long)arg));

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    sai_db_unlock();
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting tunnel attributes\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_get_sai_rif_id(key->key.object_id, (long)arg, &sx_tunnel_attr, &value->oid))) {
        SX_LOG_ERR("Error getting sai rif id\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_peer_mode_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_TUNNEL_PEER_MODE_P2MP;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_encap_src_ip_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_attribute_t sx_tunnel_attr;
    sx_ip_addr_t          sx_ip_addr;

    SX_LOG_ENTER();

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel attributes from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    switch (sx_tunnel_attr.type) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
        memcpy(&sx_ip_addr, &sx_tunnel_attr.attributes.ipinip_p2p.encap.underlay_sip, sizeof(sx_ip_addr));
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
        memcpy(&sx_ip_addr, &sx_tunnel_attr.attributes.ipinip_p2p_gre.encap.underlay_sip, sizeof(sx_ip_addr));
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
    case SX_TUNNEL_TYPE_NVE_VXLAN_IPV6:
        memcpy(&sx_ip_addr, &sx_tunnel_attr.attributes.vxlan.encap.underlay_sip, sizeof(sx_ip_addr));
        break;

    default:
        SX_LOG_ERR("Unrecognized sx tunnel type: %d\n", sx_tunnel_attr.type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
        break;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_translate_sdk_ip_address_to_sai(&sx_ip_addr, &value->ipaddr))) {
        SX_LOG_ERR("Error translating sdk ip address to sai ip address\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_ttl_mode_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t         sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_ttl_data_t sx_tunnel_ttl_data;

    SX_LOG_ENTER();

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    if (TUNNEL_ENCAP == (long)arg) {
        sx_tunnel_ttl_data.direction = SX_TUNNEL_DIRECTION_ENCAP;
    } else if (TUNNEL_DECAP == (long)arg) {
        sx_tunnel_ttl_data.direction = SX_TUNNEL_DIRECTION_DECAP;
    }

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_ttl_data(key->key.object_id, &sx_tunnel_ttl_data);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel ttl data from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_TUNNEL_TTL_CMD_SET_E == sx_tunnel_ttl_data.ttl_cmd) {
        value->s32 = SAI_TUNNEL_TTL_MODE_PIPE_MODEL;
    } else if (SX_TUNNEL_TTL_CMD_COPY_E == sx_tunnel_ttl_data.ttl_cmd) {
        value->s32 = SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL;
    } else {
        SX_LOG_ERR("Unrecognized ttl mode %d\n", sx_tunnel_ttl_data.ttl_cmd);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_ttl_val_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t         sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_ttl_data_t sx_tunnel_ttl_data;

    SX_LOG_ENTER();

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    if (TUNNEL_ENCAP == (long)arg) {
        sx_tunnel_ttl_data.direction = SX_TUNNEL_DIRECTION_ENCAP;
    } else if (TUNNEL_DECAP == (long)arg) {
        sx_tunnel_ttl_data.direction = SX_TUNNEL_DIRECTION_DECAP;
    }

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_ttl_data(key->key.object_id, &sx_tunnel_ttl_data);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel ttl data from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_TUNNEL_TTL_CMD_SET_E == sx_tunnel_ttl_data.ttl_cmd) {
        value->u8 = sx_tunnel_ttl_data.ttl_value;
    } else if (SX_TUNNEL_TTL_CMD_COPY_E == sx_tunnel_ttl_data.ttl_cmd) {
        SX_LOG_ERR("ttl value is not valid for uniform model\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    } else {
        SX_LOG_ERR("Unrecognized ttl mode %d\n", sx_tunnel_ttl_data.ttl_cmd);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_dscp_mode_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t         sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_cos_data_t sx_tunnel_cos_data;

    SX_LOG_ENTER();

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    memset(&sx_tunnel_cos_data, 0, sizeof(sx_tunnel_cos_data_t));

    if (TUNNEL_ENCAP == (long)arg) {
        sx_tunnel_cos_data.param_type = SX_TUNNEL_COS_PARAM_TYPE_ENCAP_E;
    } else if (TUNNEL_DECAP == (long)arg) {
        sx_tunnel_cos_data.param_type = SX_TUNNEL_COS_PARAM_TYPE_DECAP_E;
    }

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_cos_data(key->key.object_id, &sx_tunnel_cos_data);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel cos data from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (TUNNEL_ENCAP == (long)arg) {
        if ((SX_COS_DSCP_REWRITE_DISABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
            (SX_COS_DSCP_ACTION_COPY_E == sx_tunnel_cos_data.dscp_action)) {
            value->s32 = SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
        } else if ((SX_COS_DSCP_REWRITE_DISABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
                   (SX_COS_DSCP_ACTION_SET_E == sx_tunnel_cos_data.dscp_action)) {
            value->s32 = SAI_TUNNEL_DSCP_MODE_PIPE_MODEL;
        } else {
            SX_LOG_ERR("Unrecognized dscp rewrite %d and dscp action %d\n",
                       sx_tunnel_cos_data.dscp_rewrite,
                       sx_tunnel_cos_data.dscp_action);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    } else if (TUNNEL_DECAP == (long)arg) {
        if ((SX_COS_DSCP_REWRITE_DISABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
            (SX_COS_DSCP_ACTION_COPY_E == sx_tunnel_cos_data.dscp_action)) {
            value->s32 = SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
        } else if ((SX_COS_DSCP_REWRITE_DISABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
                   (SX_COS_DSCP_ACTION_PRESERVE_E == sx_tunnel_cos_data.dscp_action)) {
            value->s32 = SAI_TUNNEL_DSCP_MODE_PIPE_MODEL;
        } else {
            SX_LOG_ERR("Unrecognized dscp rewrite %d and dscp action %d\n",
                       sx_tunnel_cos_data.dscp_rewrite,
                       sx_tunnel_cos_data.dscp_action);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_dscp_val_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t         sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_cos_data_t sx_tunnel_cos_data;

    SX_LOG_ENTER();

    memset(&sx_tunnel_cos_data, 0, sizeof(sx_tunnel_cos_data_t));

    sx_tunnel_cos_data.param_type = SX_TUNNEL_COS_PARAM_TYPE_ENCAP_E;

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_cos_data(key->key.object_id, &sx_tunnel_cos_data);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel cos data from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if ((SX_COS_DSCP_REWRITE_DISABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
        (SX_COS_DSCP_ACTION_COPY_E == sx_tunnel_cos_data.dscp_action)) {
        SX_LOG_ERR("dscp value is not valid for dscp uniform model\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    } else if ((SX_COS_DSCP_REWRITE_DISABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
               (SX_COS_DSCP_ACTION_SET_E == sx_tunnel_cos_data.dscp_action)) {
        value->u8 = sx_tunnel_cos_data.dscp_value;
    } else {
        SX_LOG_ERR("Unrecognized dscp rewrite %d and dscp action %d\n",
                   sx_tunnel_cos_data.dscp_rewrite,
                   sx_tunnel_cos_data.dscp_action);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_encap_gre_key_valid_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_attribute_t sx_tunnel_attr;

    SX_LOG_ENTER();

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel attributes from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE != sx_tunnel_attr.type) {
        SX_LOG_ERR("encap gre key valid is only valid for ip in ip gre type\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (sx_tunnel_attr.attributes.ipinip_p2p.encap.gre_mode) {
    case SX_TUNNEL_IPINIP_GRE_MODE_ENABLED_WITH_KEY:
        value->booldata = true;
        break;

    case SX_TUNNEL_IPINIP_GRE_MODE_ENABLED:
        value->booldata = false;
        break;

    default:
        SX_LOG_ERR("unrecognized sx tunnel encap gre mode %d\n", sx_tunnel_attr.attributes.ipinip_p2p.encap.gre_mode);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
        break;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_encap_gre_key_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_attribute_t sx_tunnel_attr;

    SX_LOG_ENTER();

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel attributes from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE != sx_tunnel_attr.type) {
        SX_LOG_ERR("encap gre key is only valid for ip in ip gre type\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (sx_tunnel_attr.attributes.ipinip_p2p.encap.gre_mode) {
    case SX_TUNNEL_IPINIP_GRE_MODE_ENABLED_WITH_KEY:
        value->u32 = sx_tunnel_attr.attributes.ipinip_p2p.encap.gre_key;
        break;

    case SX_TUNNEL_IPINIP_GRE_MODE_ENABLED:
        SX_LOG_ERR("error: sx tunnel encap type is gre mode enabled without key\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
        break;

    default:
        SX_LOG_ERR("unrecognized sx tunnel encap gre mode %d\n", sx_tunnel_attr.attributes.ipinip_p2p.encap.gre_mode);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
        break;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_encap_ecn_mode_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_TUNNEL_ENCAP_ECN_MODE_STANDARD;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_decap_ecn_mode_is_standard(
    _In_ sx_tunnel_cos_ecn_decap_params_t *sx_tunnel_cos_ecn_decap_params)
{
    /* Based on RFC 6040 */
    const uint8_t non_ect = 0;
    const uint8_t ect1 = 1;
    const uint8_t ect0 = 2;
    const uint8_t ce = 3;
    bool          is_standard = true;

    SX_LOG_ENTER();

    if (NULL == sx_tunnel_cos_ecn_decap_params) {
        SX_LOG_ERR("sx tunnel cos ecn decap params is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    is_standard &= ((sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][non_ect].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][ect1].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][ect0].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][ce].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][non_ect].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][ect1].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][ect0].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][ce].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][non_ect].egress_ecn == ect0) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][ect1].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][ect0].egress_ecn == ect0) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][ce].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][non_ect].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][ect1].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][ect0].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][ce].egress_ecn == ce));

    SX_LOG_EXIT();
    return is_standard ? SAI_STATUS_SUCCESS : SAI_STATUS_FAILURE;
}

static sai_status_t mlnx_tunnel_decap_ecn_mode_is_copy_from_outer(
    _In_ sx_tunnel_cos_ecn_decap_params_t *sx_tunnel_cos_ecn_decap_params)
{
    uint32_t uecn_idx = 0;
    uint32_t oecn_idx = 0;
    bool     is_copy_from_outer = true;

    SX_LOG_ENTER();

    if (NULL == sx_tunnel_cos_ecn_decap_params) {
        SX_LOG_ERR("sx tunnel cos ecn decap params is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    for (oecn_idx = 0; oecn_idx < COS_ECN_MAX_NUM + 1; oecn_idx++) {
        for (uecn_idx = 0; uecn_idx < COS_ECN_MAX_NUM + 1; uecn_idx++) {
            is_copy_from_outer &=
                (uecn_idx == sx_tunnel_cos_ecn_decap_params->ecn_decap_map[oecn_idx][uecn_idx].egress_ecn);
        }
    }

    SX_LOG_EXIT();
    return is_copy_from_outer ? SAI_STATUS_SUCCESS : SAI_STATUS_FAILURE;
}

static sai_status_t mlnx_tunnel_decap_ecn_mode_match(
    _In_ sx_tunnel_cos_ecn_decap_params_t *sx_tunnel_cos_ecn_decap_params,
    _Out_ sai_tunnel_decap_ecn_mode_t     *sai_tunnel_decap_ecn_mode)
{
    uint32_t uecn_idx = 0;
    uint32_t oecn_idx = 0;

    SX_LOG_ENTER();

    if (NULL == sx_tunnel_cos_ecn_decap_params) {
        SX_LOG_ERR("sx tunnel cos ecn decap params is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (NULL == sai_tunnel_decap_ecn_mode) {
        SX_LOG_ERR("sx tunnel decap ecn mode is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS == mlnx_tunnel_decap_ecn_mode_is_standard(sx_tunnel_cos_ecn_decap_params)) {
        *sai_tunnel_decap_ecn_mode = SAI_TUNNEL_DECAP_ECN_MODE_STANDARD;
    } else if (SAI_STATUS_SUCCESS == mlnx_tunnel_decap_ecn_mode_is_copy_from_outer(sx_tunnel_cos_ecn_decap_params)) {
        *sai_tunnel_decap_ecn_mode = SAI_TUNNEL_DECAP_ECN_MODE_COPY_FROM_OUTER;
    } else {
        SX_LOG_ERR("unrecognized tunnel decap ecn mode\n");
        for (oecn_idx = 0; oecn_idx < COS_ECN_MAX_NUM + 1; oecn_idx++) {
            for (uecn_idx = 0; uecn_idx < COS_ECN_MAX_NUM + 1; uecn_idx++) {
                SX_LOG_ERR("ecn decap map [oecn_idx = %d], [uecn_idx = %d], egress_ecn = %d\n",
                           oecn_idx, uecn_idx,
                           sx_tunnel_cos_ecn_decap_params->ecn_decap_map[oecn_idx][uecn_idx].egress_ecn);
            }
        }
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_decap_ecn_mode_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_cos_data_t        sx_tunnel_cos_data;
    sai_tunnel_decap_ecn_mode_t sai_tunnel_decap_ecn_mode = SAI_TUNNEL_DECAP_ECN_MODE_STANDARD;

    SX_LOG_ENTER();

    memset(&sx_tunnel_cos_data, 0, sizeof(sx_tunnel_cos_data_t));

    sx_tunnel_cos_data.param_type = SX_TUNNEL_COS_PARAM_TYPE_DECAP_E;

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_cos_data(key->key.object_id, &sx_tunnel_cos_data);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel cos data from sai tunnel object %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status = mlnx_tunnel_decap_ecn_mode_match(&sx_tunnel_cos_data.cos_ecn_params.ecn_decap,
                                                       &sai_tunnel_decap_ecn_mode))) {
        value->s32 = sai_tunnel_decap_ecn_mode;
    } else {
        SX_LOG_ERR("unrecognized tunnel decap ecn mode\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_ipinip_ecn_mapper_get(_Inout_ sai_attribute_value_t *value,
                                                      void                          *arg)
{
    SX_LOG_ENTER();

    SX_LOG_ERR("Tunnel mapper for ipinip/ipinip gre tunnel is not supported for get yet\n");

    value->objlist.count = 0;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_vxlan_mapper_get(_In_ sai_object_id_t           sai_tunnel_obj_id,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 void                          *arg)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     sai_tunnel_db_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_tunnel_obj_id, SAI_OBJECT_TYPE_TUNNEL, &sai_tunnel_db_idx, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    if (TUNNEL_ENCAP == (long)arg) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_fill_objlist(g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].
                                   sai_tunnel_map_encap_id_array,
                                   g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].
                                   sai_tunnel_map_encap_cnt,
                                   &value->objlist))) {
            SX_LOG_ERR("Error filling objlist for sai tunnel obj id %" PRId64 "\n", sai_tunnel_obj_id);
            goto cleanup;
        }
    } else if (TUNNEL_DECAP == (long)arg) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_fill_objlist(g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].
                                   sai_tunnel_map_decap_id_array,
                                   g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].
                                   sai_tunnel_map_decap_cnt,
                                   &value->objlist))) {
            SX_LOG_ERR("Error filling objlist for sai tunnel obj id %" PRId64 "\n", sai_tunnel_obj_id);
            goto cleanup;
        }
    }

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    SX_LOG_EXIT();

    return sai_status;
}

static sai_status_t mlnx_tunnel_mappers_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sx_tunnel_attribute_t sx_tunnel_attr;
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_id_t        sx_tunnel_id = 0;

    SX_LOG_ENTER();

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel attributes from sai tunnel object %" PRId64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(key->key.object_id, &sx_tunnel_id))) {
        SX_LOG_ERR("Failed to get sx tunnel id form sai tunnel id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    switch (sx_tunnel_attr.type) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_ipinip_ecn_mapper_get(value, arg))) {
            SX_LOG_ERR("Error getting ipinip ecn mapper\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
    case SX_TUNNEL_TYPE_NVE_VXLAN_IPV6:
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_vxlan_mapper_get(key->key.object_id, value, arg))) {
            SX_LOG_ERR("Error getting vxlan mapper\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported sx tunnel type %d\n", sx_tunnel_attr.type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_vxlan_mapper_set(_In_ sai_object_id_t              sai_tunnel_obj_id,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t        sai_status = SAI_STATUS_FAILURE;
    uint32_t            sai_tunnel_db_idx = 0;
    mlnx_tunnel_entry_t old_mlnx_tunnel_db_entry;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_tunnel_obj_id, SAI_OBJECT_TYPE_TUNNEL, &sai_tunnel_db_idx, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    if (MLNX_TUNNEL_MAP_MAX < value->objlist.count) {
        SX_LOG_ERR("tunnel map list count %d is greater than maximum allowed size %d\n",
                   value->objlist.count,
                   MLNX_TUNNEL_MAP_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_db_write_lock();
    sai_status = mlnx_get_tunnel_db_entry(sai_tunnel_obj_id, &old_mlnx_tunnel_db_entry);

    if (SAI_STATUS_SUCCESS != sai_status) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting tunnel db entry from tunnel obj id %" PRIx64 "\n",
                   sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (TUNNEL_ENCAP == (long)arg) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_create_vxlan_tunnel_map_list(old_mlnx_tunnel_db_entry.sai_tunnel_map_encap_id_array,
                                                                old_mlnx_tunnel_db_entry.sai_tunnel_map_encap_cnt,
                                                                TUNNEL_ENCAP,
                                                                sai_tunnel_obj_id,
                                                                SX_ACCESS_CMD_DELETE))) {
            sai_db_unlock();
            SX_LOG_ERR("Error deleting existing vxlan encap tunnel map for sai tunnel obj %" PRIx64 "\n",
                       sai_tunnel_obj_id);
            SX_LOG_EXIT();
            return sai_status;
        }
    } else if (TUNNEL_DECAP == (long)arg) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_create_vxlan_tunnel_map_list(old_mlnx_tunnel_db_entry.sai_tunnel_map_decap_id_array,
                                                                old_mlnx_tunnel_db_entry.sai_tunnel_map_decap_cnt,
                                                                TUNNEL_DECAP,
                                                                sai_tunnel_obj_id,
                                                                SX_ACCESS_CMD_DELETE))) {
            sai_db_unlock();
            SX_LOG_ERR("Error deleting vxlan decap tunnel map for sai tunnel obj %" PRIx64 "\n", sai_tunnel_obj_id);
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_create_vxlan_tunnel_map_list(value->objlist.list,
                                                            value->objlist.count,
                                                            (tunnel_direction_type)arg,
                                                            sai_tunnel_obj_id,
                                                            SX_ACCESS_CMD_ADD))) {
        sai_db_unlock();
        SX_LOG_ERR("Error adding vxlan tunnel map for sai tunnel obj %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (TUNNEL_ENCAP == (long)arg) {
        g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].sai_tunnel_map_encap_cnt = value->objlist.count;
        memcpy(g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].sai_tunnel_map_encap_id_array,
               value->objlist.list,
               value->objlist.count * sizeof(sai_object_id_t));
    } else if (TUNNEL_DECAP == (long)arg) {
        g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].sai_tunnel_map_decap_cnt = value->objlist.count;
        memcpy(g_sai_tunnel_db_ptr->tunnel_entry_db[sai_tunnel_db_idx].sai_tunnel_map_decap_id_array,
               value->objlist.list,
               value->objlist.count * sizeof(sai_object_id_t));
    }

    sai_db_unlock();

    sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_EXIT();

    return sai_status;
}

static sai_status_t mlnx_tunnel_mappers_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sx_tunnel_attribute_t sx_tunnel_attr;
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_id_t        sx_tunnel_id = 0;

    SX_LOG_ENTER();

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel attributes from sai tunnel object %" PRId64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(key->key.object_id, &sx_tunnel_id))) {
        SX_LOG_ERR("Failed to get sx tunnel id form sai tunnel id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    switch (sx_tunnel_attr.type) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
        SX_LOG_ERR("Setting tunnel mapper for IP in IP tunnel is not supported yet\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
    case SX_TUNNEL_TYPE_NVE_VXLAN_IPV6:
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_vxlan_mapper_set(key->key.object_id, value, arg))) {
            SX_LOG_ERR("Error setting vxlan mapper\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported sx tunnel type %d\n", sx_tunnel_attr.type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_vxlan_srcport_set_hash(sx_tunnel_id_t tunnel_id, mlnx_tunnel_hash_cmd_t cmd, int32_t src_port_base)
{
    sai_status_t          sai_status = SAI_STATUS_SUCCESS;
    sx_status_t           sdk_status = SX_STATUS_SUCCESS;
    sx_tunnel_hash_data_t sx_tunnel_hash_data = {0};

    switch (cmd) {
    case SAI_TUNNEL_HASH_CMD_SET_ZERO:
        sx_tunnel_hash_data.hash_field_type = SX_TUNNEL_HASH_FIELD_TYPE_UDP_SPORT_E;
        sx_tunnel_hash_data.hash_cmd = SX_TUNNEL_HASH_CMD_SET_ZERO_E;
        break;

    case SAI_TUNNEL_HASH_CMD_FIXED_VALUE:
        sx_tunnel_hash_data.hash_field_type = SX_TUNNEL_HASH_FIELD_TYPE_UDP_SPORT_E;
        sx_tunnel_hash_data.hash_cmd = SX_TUNNEL_HASH_CMD_FIXED_VALUE_E;
        sx_tunnel_hash_data.nve_data.nve_udp_value_msb_valid = true;
        sx_tunnel_hash_data.nve_data.nve_udp_value_msb = src_port_base >> 8;
        sx_tunnel_hash_data.nve_data.nve_udp_value_lsb = src_port_base & 0xFF;
        break;

    case SAI_TUNNEL_HASH_CMD_MODIFIED_HASH:
        sx_tunnel_hash_data.hash_field_type = SX_TUNNEL_HASH_FIELD_TYPE_UDP_SPORT_E;
        sx_tunnel_hash_data.hash_cmd = SX_TUNNEL_HASH_CMD_MODIFIED_HASH_E;
        sx_tunnel_hash_data.nve_data.nve_udp_value_msb_valid = true;
        sx_tunnel_hash_data.nve_data.nve_udp_value_msb = src_port_base >> 8;
        sx_tunnel_hash_data.nve_data.nve_udp_value_lsb = src_port_base & 0xff;
        break;

    case SAI_TUNNEL_HASH_CMD_CALCULATE:
        sx_tunnel_hash_data.hash_field_type = SX_TUNNEL_HASH_FIELD_TYPE_UDP_SPORT_E;
        sx_tunnel_hash_data.hash_cmd = SX_TUNNEL_HASH_CMD_CALCULATE_E;
        sx_tunnel_hash_data.nve_data.nve_udp_value_msb_valid = true;
        sx_tunnel_hash_data.nve_data.nve_udp_value_msb = src_port_base >> 8;
        break;

    default:
        SX_LOG_ERR("Not supported tunnel hash command!\n");
        return SAI_STATUS_FAILURE;
    }

    sdk_status = sx_api_tunnel_hash_set(gh_sdk, tunnel_id, &sx_tunnel_hash_data);
    if (SX_ERR(sdk_status)) {
        sai_status = sdk_to_sai(sdk_status);
        goto out;
    }

    return SAI_STATUS_SUCCESS;
out:
    SX_LOG_ERR("Error setting src port hash for sdk vxlan tunnel %x, sx status: %s\n",
               tunnel_id, SX_STATUS_MSG(sdk_status));
    return sai_status;
}

sai_status_t mlnx_vxlan_srcport_user_defined_set(uint32_t tunnel_db_idx,
                                                 int32_t  sport_base,
                                                 int8_t   sport_mask,
                                                 bool     acl_created)
{
    mlnx_tunnel_hash_cmd_t cmd;

    if ((sport_mask == 0) && (sport_base == 0)) {
        cmd = SAI_TUNNEL_HASH_CMD_SET_ZERO;
    } else if (((sport_mask == 0) && !mlnx_chip_is_spc())
               || ((sport_mask == 0) && !(sport_base & 0xFF) && mlnx_chip_is_spc())) {
        cmd = SAI_TUNNEL_HASH_CMD_FIXED_VALUE;
    } else if (!mlnx_chip_is_spc()
               && (((0x80 == (sport_base & 0xFF)) && (sport_mask == 7))
                   || ((0xC0 == (sport_base & 0xFF)) && (sport_mask == 6))
                   || ((0xE0 == (sport_base & 0xFF)) && (sport_mask == 5))
                   || ((0xF0 == (sport_base & 0xFF)) && (sport_mask == 4))
                   || ((0xF8 == (sport_base & 0xFF)) && (sport_mask == 3))
                   || ((0xFC == (sport_base & 0xFF)) && (sport_mask == 2))
                   || ((0xFE == (sport_base & 0xFF)) && (sport_mask == 1)))) {
        cmd = SAI_TUNNEL_HASH_CMD_MODIFIED_HASH;
    } else {
        cmd = SAI_TUNNEL_HASH_CMD_CALCULATE;
    }
    if ((cmd != SAI_TUNNEL_HASH_CMD_CALCULATE) && acl_created) {
        if (SAI_ERR(mlnx_vxlan_udp_srcport_acl_remove(tunnel_db_idx))) {
            SX_LOG_ERR("Error deleting UDP VxLAN src port ACL %d \n",
                       g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.acl_group);
            return SAI_STATUS_FAILURE;
        }
    } else if (cmd == SAI_TUNNEL_HASH_CMD_CALCULATE) {
        if (!acl_created && (sport_mask < 8)) {
            if (SAI_ERR(mlnx_vxlan_udp_srcport_acl_add(tunnel_db_idx))) {
                SX_LOG_ERR("Failed to add UDP VxLAN src port ACL\n");
                return SAI_STATUS_FAILURE;
            }
        } else if (acl_created) {
            if (SAI_ERR(mlnx_vxlan_udp_srcport_acl_update(tunnel_db_idx))) {
                SX_LOG_ERR("Failed to update VxLAN src port ACL\n");
                return SAI_STATUS_FAILURE;
            }
        }
    }

    if (SAI_ERR(mlnx_vxlan_srcport_set_hash(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4,
                                            cmd, sport_base))) {
        SX_LOG_ERR("Failed to set UDP VxLAN src port 8bits hash value for sdk vxlan tunnel %x\n",
                   g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4);
        sai_db_unlock();
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vxlan_srcport_config_update(bool                              on_create_set,
                                              uint32_t                          tunnel_db_idx,
                                              sai_tunnel_vxlan_udp_sport_mode_t src_port_mode,
                                              int32_t                           src_port_base,
                                              int8_t                            src_port_mask)
{
    sai_status_t                      sai_status = SAI_STATUS_SUCCESS;
    sai_tunnel_vxlan_udp_sport_mode_t sport_mode;
    uint16_t                          sport_base;
    uint8_t                           sport_mask;

    sport_mode = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode;
    sport_base = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base;
    sport_mask = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask;


    if (on_create_set && (sport_mode == src_port_mode)
        && (sport_base == src_port_base)
        && (sport_mask == src_port_mask)) {
        return SAI_STATUS_SUCCESS;
    }

    if (!on_create_set) {
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.is_acl_created) {
            sai_status = mlnx_vxlan_udp_srcport_acl_remove(tunnel_db_idx);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error deleting UDP VxLAN src port ACL %d \n",
                           g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.acl);
                return SAI_STATUS_FAILURE;
            }
        }
        if (SAI_STATUS_SUCCESS !=
            mlnx_vxlan_srcport_set_hash(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4,
                                        SAI_TUNNEL_HASH_CMD_CALCULATE, 0xC000)) {
            SX_LOG_ERR("Error setting VxLAN UDP SRC port mode EPHEMERAL for sdk vxlan tunnel %x\n",
                       g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4);
            return SAI_STATUS_FAILURE;
        }
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode = src_port_mode;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base = 0;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask = 0;
        return SAI_STATUS_SUCCESS;
    }

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode = src_port_mode;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base = src_port_base;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask = src_port_mask;

    if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode ==
        SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL) {
        if (SAI_STATUS_SUCCESS !=
            mlnx_vxlan_srcport_set_hash(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4,
                                        SAI_TUNNEL_HASH_CMD_CALCULATE, 0xC000)) {
            SX_LOG_ERR("Error setting VxLAN UDP SRC port mode EPHEMERAL for sdk vxlan tunnel %x\n",
                       g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4);
            return SAI_STATUS_FAILURE;
        }
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.is_acl_created) {
            sai_status = mlnx_vxlan_udp_srcport_acl_remove(tunnel_db_idx);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error deleting UDP VxLAN src port ACL %d \n",
                           g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.acl);
                return SAI_STATUS_FAILURE;
            }
        }
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base = 0;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask = 0;
    } else {
        if (SAI_STATUS_SUCCESS !=
            mlnx_vxlan_srcport_user_defined_set(tunnel_db_idx, src_port_base, src_port_mask,
                                                g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.
                                                is_acl_created)) {
            SX_LOG_ERR("Error setting VxLAN UDP SRC port mode USER_DEFINED for sdk vxlan tunnel %x\n",
                       g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4);
            return SAI_STATUS_FAILURE;
        }
    }

    return sai_status;
}

static sai_status_t mlnx_tunnel_vxlan_udp_sport_attr_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg)
{
    sx_tunnel_attribute_t sx_tunnel_attr;
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_id_t        sx_tunnel_id = 0;
    uint32_t              tunnel_db_idx = 0;
    sai_object_id_t       sai_tunnel_id = key->key.object_id;

    SX_LOG_ENTER();

    if (g_sai_db_ptr->vxlan_srcport_range_enabled) {
        SX_LOG_ERR("VxLAN tunnel attributes can not be configured when VxLAN SRC port range feature is enabled!\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_NTC("sai_db_write_lock\n");
    sai_db_write_lock();
    sai_status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);
    SX_LOG_NTC("sai_db_write_unlock\n");
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error getting sdk tunnel attributes from sai tunnel object %" PRId64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(key->key.object_id, &sx_tunnel_id))) {
        SX_LOG_ERR("Failed to get sx tunnel id form sai tunnel id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if ((sx_tunnel_attr.type != SX_TUNNEL_TYPE_NVE_VXLAN) &&
        (sx_tunnel_attr.type != SX_TUNNEL_TYPE_NVE_VXLAN_IPV6)) {
        SX_LOG_ERR("VxLAN UDP SRC port attributes are not supported  for sx tunnel type %d\n", sx_tunnel_attr.type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    switch ((long)arg) {
    case SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MODE:
        value->s32 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode;
        break;

    case SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT:
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode ==
            SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL) {
            SX_LOG_ERR(
                "VxLAN UDP SRC port attribute is supported only for SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_USER_DEFINED src port mode\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        value->u16 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base;
        break;

    case SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MASK:
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode ==
            SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL) {
            SX_LOG_ERR(
                "VxLAN UDP SRC port mask attribute is supported only for SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_USER_DEFINED src port mode\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        value->u8 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask;
        break;

    default:
        SX_LOG_ERR("Unsupported VxLAN SRC port attribute %lu\n", (long)arg);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_vxlan_udp_sport_attr_set(_In_ const sai_object_key_t      *key,
                                                         _In_ const sai_attribute_value_t *value,
                                                         void                             *arg)
{
    sai_status_t                      sai_status = SAI_STATUS_FAILURE;
    uint32_t                          tunnel_db_idx = 0;
    sai_object_id_t                   sai_tunnel_id = key->key.object_id;
    sai_tunnel_vxlan_udp_sport_mode_t new_sport_mode;
    int32_t                           new_sport_base;
    int8_t                            new_sport_mask;

    SX_LOG_ENTER();

    if (g_sai_db_ptr->vxlan_srcport_range_enabled) {
        SX_LOG_ERR("VxLAN tunnel attributes can not be configured when VxLAN SRC port range feature is enabled!\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    new_sport_mode = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode;
    new_sport_base = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base;
    new_sport_mask = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask;

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    switch ((long)arg) {
    case SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MODE:
        new_sport_mode = value->s32;
        if (new_sport_mode == SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL) {
            new_sport_base = 0;
            new_sport_mask = 0;
        }
        break;

    case SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT:
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode ==
            SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL) {
            SX_LOG_ERR(
                "VxLAN UDP SRC port mask attribute is supported only for SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_USER_DEFINED src port mode\n");
            sai_status = SAI_STATUS_FAILURE;
            goto out;
        }
        new_sport_base = value->u16;
        break;

    case SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MASK:
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode ==
            SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL) {
            SX_LOG_ERR(
                "VxLAN UDP SRC port mask attribute is supported only for SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_USER_DEFINED src port mode\n");
            sai_status = SAI_STATUS_FAILURE;
            goto out;
        }
        if (value->u8 > 8) {
            SX_LOG_ERR(
                "Wrong VxLAN UDP SRC port mask attribute value! Supported values are [0..8].\n");
            sai_status = SAI_STATUS_FAILURE;
            goto out;
        }
        new_sport_mask = value->u8;
        break;

    default:
        SX_LOG_ERR("Unsupported VxLAN SRC port attribute %ld\n", (int64_t)arg);
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (new_sport_base & (0xFF >> (8 - new_sport_mask))) {
        SX_LOG_ERR("Wrong VxLAN UDP SRC port base and mask combination (0x%X:0x%X)\n", new_sport_base,
                   (0xFF >> (8 - new_sport_mask)));
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    sai_status = mlnx_vxlan_srcport_config_update(true, tunnel_db_idx, new_sport_mode, new_sport_base, new_sport_mask);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Failed to set VxLAN src port mode attribute\n");
        goto out;
    }

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.is_configured = true;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mode =
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_base =
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mask =
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_loopback_packet_action_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg)
{
    sai_status_t                status = SAI_STATUS_FAILURE;
    sai_object_id_t             rif_oid = SAI_NULL_OBJECT_ID;
    sx_tunnel_attribute_t       sx_tunnel_attr = {0};
    sx_router_interface_state_t rif_state, *rif_state_ptr = &rif_state;
    sx_router_interface_param_t intf_params, *intf_params_ptr = &intf_params;
    sx_interface_attributes_t   intf_attribs, *intf_attribs_ptr = &intf_attribs;
    mlnx_rif_sx_data_t         *sx_data;
    mlnx_rif_type_t             rif_type;
    bool                        is_created;

    SX_LOG_ENTER();

    sai_db_write_lock();

    status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);

    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error getting tunnel attributes\n");
        goto exit;
    }

    status = mlnx_sai_get_sai_rif_id(key->key.object_id, MLNX_TUNNEL_OVERLAY, &sx_tunnel_attr, &rif_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error getting sai rif id\n");
        goto exit;
    }

    status = mlnx_rif_sx_attrs_get(rif_oid,
                                   false,
                                   &rif_type,
                                   &is_created,
                                   &sx_data,
                                   &rif_state_ptr,
                                   &intf_params_ptr,
                                   &intf_attribs_ptr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed getting RIF attributes.\n");
        goto exit;
    }

    value->s32 = intf_attribs_ptr->loopback_enable ? SAI_PACKET_ACTION_FORWARD : SAI_PACKET_ACTION_DROP;

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_tunnel_loopback_packet_action_set(_In_ const sai_object_key_t      *key,
                                                           _In_ const sai_attribute_value_t *value,
                                                           void                             *arg)
{
    sai_status_t                status = SAI_STATUS_FAILURE;
    sx_status_t                 sx_status = SX_STATUS_ERROR;
    sai_object_id_t             rif_oid = SAI_NULL_OBJECT_ID;
    sx_tunnel_attribute_t       sx_tunnel_attr = {0};
    sx_router_interface_state_t rif_state, *rif_state_ptr = &rif_state;
    sx_router_interface_param_t intf_params, *intf_params_ptr = &intf_params;
    sx_interface_attributes_t   intf_attribs, *intf_attribs_ptr = &intf_attribs;
    mlnx_rif_sx_data_t         *sx_data;
    mlnx_rif_type_t             rif_type;
    bool                        is_created;

    SX_LOG_ENTER();

    sai_db_write_lock();

    status = mlnx_sai_get_tunnel_attribs(key->key.object_id, &sx_tunnel_attr);

    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error getting tunnel attributes\n");
        goto exit;
    }

    status = mlnx_sai_get_sai_rif_id(key->key.object_id, MLNX_TUNNEL_OVERLAY, &sx_tunnel_attr, &rif_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error getting sai rif id\n");
        goto exit;
    }

    status = mlnx_rif_sx_attrs_get(rif_oid,
                                   false,
                                   &rif_type,
                                   &is_created,
                                   &sx_data,
                                   &rif_state_ptr,
                                   &intf_params_ptr,
                                   &intf_attribs_ptr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed getting RIF attributes.\n");
        goto exit;
    }

    status = mlnx_rif_loopback_action_sai_to_sx(value, 0, intf_attribs_ptr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert loopback action.\n");
        goto exit;
    }

    sx_status = sx_api_router_interface_set(gh_sdk,
                                            SX_ACCESS_CMD_EDIT,
                                            sx_data->vrf_id,
                                            intf_params_ptr,
                                            intf_attribs_ptr,
                                            &sx_data->rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto exit;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_get_tunnel_type_by_tunnel_id(_In_ sai_object_id_t    tunnel_oid,
                                                      _Out_ sx_tunnel_type_e *tunnel_type)
{
    sai_status_t status;
    uint32_t     tunnel_db_idx;

    if (!tunnel_type) {
        SX_LOG_ERR("NULL tunnel_type\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_get_sai_tunnel_db_idx(tunnel_oid, &tunnel_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", tunnel_oid);
        return status;
    }

    *tunnel_type = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr.type;
    return status;
}

static sai_status_t mlnx_convert_sai_tunnel_type_to_sx_ipv4(_In_ sai_tunnel_type_t    sai_type,
                                                            _In_ sai_ip_addr_family_t sai_outer_ip_type,
                                                            _Out_ sx_tunnel_type_e   *sx_type)
{
    SX_LOG_ENTER();
    if (!sx_type) {
        SX_LOG_ERR("sx_type is null\n");
        return SAI_STATUS_FAILURE;
    }
    switch (sai_type) {
    case SAI_TUNNEL_TYPE_IPINIP:
        if (SAI_IP_ADDR_FAMILY_IPV4 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4;
        } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6;
        } else {
            SX_LOG_ERR("unsupported ip type:%d\n", sai_outer_ip_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_TUNNEL_TYPE_IPINIP_GRE:
        if (SAI_IP_ADDR_FAMILY_IPV4 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE;
        } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6_WITH_GRE;
        } else {
            SX_LOG_ERR("unsupported ip type:%d\n", sai_outer_ip_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_TUNNEL_TYPE_VXLAN:
        if (SAI_IP_ADDR_FAMILY_IPV4 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_NVE_VXLAN;
        } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_NVE_VXLAN_IPV6;
        } else {
            SX_LOG_ERR("unsupported ip type:%d\n", sai_outer_ip_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    default:
        SX_LOG_ERR("unsupported tunnel type:%d\n", sai_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_convert_sai_tunnel_type_to_sx_ipv6(_In_ sai_tunnel_type_t    sai_type,
                                                            _In_ sai_ip_addr_family_t sai_outer_ip_type,
                                                            _Out_ sx_tunnel_type_e   *sx_type)
{
    SX_LOG_ENTER();
    if (!sx_type) {
        SX_LOG_ERR("sx_type is null\n");
        return SAI_STATUS_FAILURE;
    }
    switch (sai_type) {
    case SAI_TUNNEL_TYPE_IPINIP:
        if (SAI_IP_ADDR_FAMILY_IPV4 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV4;
        } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV6;
        } else {
            SX_LOG_ERR("unsupported ip type:%d\n", sai_outer_ip_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_TUNNEL_TYPE_IPINIP_GRE:
        if (SAI_IP_ADDR_FAMILY_IPV4 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV4_WITH_GRE;
        } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_outer_ip_type) {
            *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_GRE;
        } else {
            SX_LOG_ERR("unsupported ip type:%d\n", sai_outer_ip_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_TUNNEL_TYPE_VXLAN:
        *sx_type = SX_TUNNEL_TYPE_NVE_VXLAN_IPV6;
        break;

    default:
        SX_LOG_ERR("unsupported tunnel type:%d\n", sai_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_convert_sx_tunnel_type_to_sai(_In_ sx_tunnel_type_e    sx_tunnel_type,
                                                       _Out_ sai_tunnel_type_t *sai_type)
{
    SX_LOG_ENTER();
    if (!sai_type) {
        SX_LOG_ERR("sai_type is null\n");
        return SAI_STATUS_FAILURE;
    }
    switch (sx_tunnel_type) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6:
        *sai_type = SAI_TUNNEL_TYPE_IPINIP;
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6_WITH_GRE:
        *sai_type = SAI_TUNNEL_TYPE_IPINIP_GRE;
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
    case SX_TUNNEL_TYPE_NVE_VXLAN_IPV6:
        *sai_type = SAI_TUNNEL_TYPE_VXLAN;
        break;

    default:
        SX_LOG_ERR("unsupported tunnel type:%d\n", sx_tunnel_type);
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_IMPLEMENTED;
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_convert_sx_tunnel_type_ipv4_to_ipv6(_In_ sx_tunnel_type_e   sx_tunnel_type_ipv4,
                                                             _Out_ sx_tunnel_type_e *sx_tunnel_type_ipv6)
{
    SX_LOG_ENTER();
    if (!sx_tunnel_type_ipv6) {
        SX_LOG_ERR("sx_tunnel_type_ipv6 is null\n");
        return SAI_STATUS_FAILURE;
    }
    switch (sx_tunnel_type_ipv4) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
        *sx_tunnel_type_ipv6 = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV4;
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6:
        *sx_tunnel_type_ipv6 = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV6;
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
        *sx_tunnel_type_ipv6 = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_IPV4_WITH_GRE;
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV6_WITH_GRE:
        *sx_tunnel_type_ipv6 = SX_TUNNEL_TYPE_IPINIP_P2P_IPV6_IN_GRE;
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
        *sx_tunnel_type_ipv6 = SX_TUNNEL_TYPE_NVE_VXLAN_IPV6;
        break;

    default:
        SX_LOG_ERR("unsupported tunnel type:%d\n", sx_tunnel_type_ipv4);
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_IMPLEMENTED;
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_convert_sai_tunneltable_type_to_sx(_In_ sai_tunnel_term_table_entry_type_t  sai_type,
                                                            _Out_ sx_tunnel_decap_key_fields_type_e *sdk_type)
{
    SX_LOG_ENTER();
    switch (sai_type) {
    case SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P:
        *sdk_type = SX_TUNNEL_DECAP_KEY_FIELDS_TYPE_DIP_SIP;
        break;

    case SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP:
        *sdk_type = SX_TUNNEL_DECAP_KEY_FIELDS_TYPE_DIP;
        break;

    default:
        SX_LOG_ERR("Unrecognized tunnel table type: %d\n", sai_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_convert_sx_tunneltable_type_to_sai(_In_ sx_tunnel_decap_key_fields_type_e    sdk_type,
                                                            _Out_ sai_tunnel_term_table_entry_type_t *sai_type)
{
    SX_LOG_ENTER();
    switch (sdk_type) {
    case SX_TUNNEL_DECAP_KEY_FIELDS_TYPE_DIP_SIP:
        *sai_type = SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P;
        break;

    case SX_TUNNEL_DECAP_KEY_FIELDS_TYPE_DIP:
        *sai_type = SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP;
        break;

    default:
        SX_LOG_ERR("Unrecognized sdk tunnel decap key type %d\n", sdk_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sdk_tunnel_id_to_sai_tunnel_id(_In_ const sx_tunnel_id_t sdk_tunnel_id,
                                                           _Out_ sai_object_id_t    *sai_tunnel_id)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_idx = 0;

    SX_LOG_ENTER();

    sai_db_read_lock();

    for (tunnel_idx = 0; tunnel_idx < MAX_TUNNEL_DB_SIZE; tunnel_idx++) {
        if (sdk_tunnel_id == g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sx_tunnel_id_ipv4) {
            break;
        }
    }

    if (MAX_TUNNEL_DB_SIZE == tunnel_idx) {
        SX_LOG_ERR("Cannot find sai tunnel object which maps to sdk tunnel id %d\n", sdk_tunnel_id);
        sai_status = SAI_STATUS_FAILURE;
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL, tunnel_idx, NULL, sai_tunnel_id))) {
        SX_LOG_ERR("Cannot create sai tunnel object using index %d\n", tunnel_idx);
        goto cleanup;
    }

    sai_status = SAI_STATUS_SUCCESS;
cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard the call with lock */
static sai_status_t mlnx_tunnel_term_table_entry_sdk_param_get(
    _In_ const sai_object_id_t         sai_tunneltable_obj_id,
    _Out_ sx_tunnel_decap_entry_key_t *sdk_tunnel_decap_key)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     internal_tunneltable_entry_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_tunneltable_obj_id, SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                                 &internal_tunneltable_entry_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai tunnel table entry obj id: %" PRIx64 "\n", sai_tunneltable_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (MLNX_TUNNELTABLE_SIZE <= internal_tunneltable_entry_idx) {
        SX_LOG_ERR("Internal tunnel table entry idx %d is bigger than upper bound %d\n",
                   internal_tunneltable_entry_idx,
                   MLNX_TUNNELTABLE_SIZE);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (!g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_entry_idx].in_use) {
        SX_LOG_ERR("Non-exist internal tunnel table entry idx: %d\n", internal_tunneltable_entry_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    memcpy(sdk_tunnel_decap_key,
           &g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_entry_idx].sdk_tunnel_decap_key_ipv4,
           sizeof(sx_tunnel_decap_entry_key_t));

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_term_table_entry_sdk_param_get_from_db(
    _In_ const sai_object_id_t         sai_tunneltable_obj_id,
    _Out_ sx_tunnel_decap_entry_key_t *sdk_tunnel_decap_key)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    sai_db_read_lock();

    sai_status = mlnx_tunnel_term_table_entry_sdk_param_get(sai_tunneltable_obj_id, sdk_tunnel_decap_key);

    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n", sai_tunneltable_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    return sai_status;
}

static sai_status_t mlnx_tunnel_term_table_entry_vr_id_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_decap_entry_key_t sdk_tunnel_decap_key;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_term_table_entry_sdk_param_get_from_db(key->key.object_id, &sdk_tunnel_decap_key))) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, sdk_tunnel_decap_key.underlay_vrid, NULL,
                                &value->oid))) {
        SX_LOG_ERR("Fail to get sai virtual router id from sdk underlay vrid %d\n",
                   sdk_tunnel_decap_key.underlay_vrid);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_term_table_entry_type_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg)
{
    sai_status_t                       sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_decap_entry_key_t        sdk_tunnel_decap_key;
    sai_tunnel_term_table_entry_type_t sai_tunneltable_entry_type;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_term_table_entry_sdk_param_get_from_db(key->key.object_id, &sdk_tunnel_decap_key))) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_convert_sx_tunneltable_type_to_sai(sdk_tunnel_decap_key.type, &sai_tunneltable_entry_type))) {
        SX_LOG_ERR("Error converting sdk tunnel table entry type %d to sai tunnel table entry type\n",
                   sdk_tunnel_decap_key.type);
        SX_LOG_EXIT();
        return sai_status;
    }

    value->s32 = sai_tunneltable_entry_type;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_term_table_entry_dst_ip_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_decap_entry_key_t sdk_tunnel_decap_key;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_term_table_entry_sdk_param_get_from_db(key->key.object_id, &sdk_tunnel_decap_key))) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_translate_sdk_ip_address_to_sai(&sdk_tunnel_decap_key.underlay_dip,
                                                           &value->ipaddr))) {
        SX_LOG_ERR("Error getting dst ip of sai tunnel table entry id: %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_term_table_entry_src_ip_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_decap_entry_key_t sdk_tunnel_decap_key;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_term_table_entry_sdk_param_get_from_db(key->key.object_id, &sdk_tunnel_decap_key))) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_TUNNEL_DECAP_KEY_FIELDS_TYPE_DIP_SIP != sdk_tunnel_decap_key.type) {
        SX_LOG_ERR(
            "src ip should not be got when tunnel table entry type is not P2P, here sdk tunnel decap key type is %d\n",
            sdk_tunnel_decap_key.type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_translate_sdk_ip_address_to_sai(&sdk_tunnel_decap_key.underlay_sip,
                                                           &value->ipaddr))) {
        SX_LOG_ERR("Error getting src ip of sai tunnel table entry id: %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_term_table_entry_tunnel_type_get(_In_ const sai_object_key_t   *key,
                                                                 _Inout_ sai_attribute_value_t *value,
                                                                 _In_ uint32_t                  attr_index,
                                                                 _Inout_ vendor_cache_t        *cache,
                                                                 void                          *arg)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_decap_entry_key_t sdk_tunnel_decap_key;
    sai_tunnel_type_t           sai_tunnel_type;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_term_table_entry_sdk_param_get_from_db(key->key.object_id, &sdk_tunnel_decap_key))) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_convert_sx_tunnel_type_to_sai(sdk_tunnel_decap_key.tunnel_type, &sai_tunnel_type))) {
        SX_LOG_ERR("Unrecognized sdk tunnel decap key tunnel type %d\n", sdk_tunnel_decap_key.tunnel_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    value->s32 = sai_tunnel_type;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_term_table_entry_tunnel_id_get(_In_ const sai_object_key_t   *key,
                                                               _Inout_ sai_attribute_value_t *value,
                                                               _In_ uint32_t                  attr_index,
                                                               _Inout_ vendor_cache_t        *cache,
                                                               void                          *arg)
{
    sai_status_t                 sai_status = SAI_STATUS_FAILURE;
    sx_status_t                  sdk_status = SX_STATUS_ERROR;
    sx_tunnel_decap_entry_key_t  sdk_tunnel_decap_key;
    sx_tunnel_decap_entry_data_t sdk_tunnel_decap_data;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_term_table_entry_sdk_param_get_from_db(key->key.object_id, &sdk_tunnel_decap_key))) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_STATUS_SUCCESS !=
        (sdk_status = sx_api_tunnel_decap_rules_get(gh_sdk, &sdk_tunnel_decap_key, &sdk_tunnel_decap_data))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error getting tunnel id from sai tunnel table entry id %" PRIx64 ", sx status %s\n",
                   key->key.object_id,
                   SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_translate_sdk_tunnel_id_to_sai_tunnel_id(sdk_tunnel_decap_data.tunnel_id, &value->oid))) {
        SX_LOG_ERR("Error creating sai tunnel id from internal tunnel id %d\n", sdk_tunnel_decap_data.tunnel_id);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return sai_status;
}

/* caller of this function should use read lock to guard the callsite */
static sai_status_t mlnx_create_empty_tunnel_map(_Out_ uint32_t *tunnel_map_idx)
{
    uint32_t     idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    for (idx = MLNX_TUNNEL_MAP_MIN; idx < MLNX_TUNNEL_MAP_MAX; idx++) {
        if (!g_sai_tunnel_db_ptr->tunnel_map_db[idx].in_use) {
            *tunnel_map_idx = idx;
            sai_status = SAI_STATUS_SUCCESS;
            goto cleanup;
        }
    }

    SX_LOG_ERR(
        "Not enough resources for sai tunnel map, at most %d sai tunnel map objs can be created\n",
        MLNX_TUNNEL_MAP_MAX);
    sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;

cleanup:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_init_tunnel_map_param(_In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list,
                                               _Out_ mlnx_tunnel_map_t    *mlnx_tunnel_map)
{
    const sai_attribute_value_t *tunnel_map_type = NULL;
    uint32_t                     attr_idx = 0;
    sai_status_t                 sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ATTR_TYPE, &tunnel_map_type, &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    mlnx_tunnel_map->tunnel_map_type = tunnel_map_type->s32;

    mlnx_tunnel_map->tunnel_cnt = 0;

    mlnx_tunnel_map->in_use = true;

    mlnx_tunnel_map->tunnel_map_entry_cnt = 0;

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_tunnel_map(_Out_ sai_object_id_t      *sai_tunnel_map_obj_id,
                                           _In_ sai_object_id_t        switch_id,
                                           _In_ uint32_t               attr_count,
                                           _In_ const sai_attribute_t *attr_list)
{
    char              list_str[MAX_LIST_VALUE_STR_LEN];
    sai_status_t      sai_status = SAI_STATUS_SUCCESS;
    uint32_t          tunnel_map_idx = 0;
    mlnx_tunnel_map_t mlnx_tunnel_map;

    memset(&mlnx_tunnel_map, 0, sizeof(mlnx_tunnel_map_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_TUNNEL_MAP, tunnel_map_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Tunnel map: metadata check failed\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_TUNNEL_MAP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create tunnel map attributes: %s\n", list_str);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_init_tunnel_map_param(attr_count, attr_list, &mlnx_tunnel_map))) {
        SX_LOG_ERR("Fail to set tunnel map param on create\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_empty_tunnel_map(&tunnel_map_idx))) {
        SX_LOG_ERR("Failed to create empty tunnel map\n");
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_MAP, tunnel_map_idx, NULL,
                                sai_tunnel_map_obj_id))) {
        memset(&g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx], 0,
               sizeof(mlnx_tunnel_map_t));
        SX_LOG_ERR("Error creating sai tunnel map obj id from tunnel map idx %d\n",
                   tunnel_map_idx);
        goto cleanup;
    }

    memcpy(&g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx], &mlnx_tunnel_map, sizeof(mlnx_tunnel_map_t));

    SX_LOG_NTC("Created tunnel map obj id: %" PRIx64 "\n", *sai_tunnel_map_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_remove_tunnel_map(_In_ const sai_object_id_t sai_tunnel_map_obj_id)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_tunnel_map_obj_id, SAI_OBJECT_TYPE_TUNNEL_MAP, &tunnel_map_idx, NULL))) {
        SX_LOG_ERR("Invalid sai tunnel map obj id: %" PRIx64 "\n", sai_tunnel_map_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (MLNX_TUNNEL_MAP_MAX <= tunnel_map_idx) {
        SX_LOG_ERR("tunnel map idx %d is bigger than upper bound %d\n", tunnel_map_idx, MLNX_TUNNEL_MAP_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_db_write_lock();

    if (g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].in_use) {
        if (0 < g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt) {
            SX_LOG_ERR("This tunnel map is still used by %d other tunnel(s)\n",
                       g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt);
            sai_status = SAI_STATUS_OBJECT_IN_USE;
            goto cleanup;
        }
        if (0 < g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_cnt) {
            SX_LOG_ERR("This tunnel map is still used by %d other tunnel map entry(s)\n",
                       g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_cnt);
            sai_status = SAI_STATUS_OBJECT_IN_USE;
            goto cleanup;
        }
        memset(&g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx], 0, sizeof(mlnx_tunnel_map_t));
    } else {
        SX_LOG_ERR("Invalid sai tunnel map obj id: %" PRIx64 "\n", sai_tunnel_map_obj_id);
        sai_status = SAI_STATUS_INVALID_OBJECT_ID;
        goto cleanup;
    }

    SX_LOG_NTC("Removed SAI tunnel map obj id %" PRIx64 "\n", sai_tunnel_map_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

/*
 *  Callers need to lock around this method
 */
sai_status_t mlnx_sai_tunnel_to_sx_tunnel_id(_In_ sai_object_id_t sai_tunnel_id, _Out_ sx_tunnel_id_t *sx_tunnel_id)
{
    sai_status_t sai_status;
    uint32_t     tunnel_db_idx;

    SX_LOG_ENTER();
    if (!sx_tunnel_id) {
        SX_LOG_ERR("NULL sx_tunnel_id\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    *sx_tunnel_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4;
    SX_LOG_DBG("sx_tunnel_id:%d\n", *sx_tunnel_id);
    SX_LOG_EXIT();
    return sai_status;
}

/*
 *  Callers need to lock around this method
 */
static sai_status_t mlnx_sai_get_tunnel_attribs(_In_ sai_object_id_t         sai_tunnel_id,
                                                _Out_ sx_tunnel_attribute_t *sx_tunnel_attr)
{
    sai_status_t sai_status;
    uint32_t     tunnel_db_idx = 0;

    SX_LOG_ENTER();

    if (!sx_tunnel_attr) {
        SX_LOG_ERR("NULL sx_tunnel_attr\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    memcpy(sx_tunnel_attr, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr,
           sizeof(*sx_tunnel_attr));
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *  Callers need to lock around this method
 */
static sai_status_t mlnx_sai_get_tunnel_cos_data(_In_ sai_object_id_t        sai_tunnel_id,
                                                 _Out_ sx_tunnel_cos_data_t *sx_tunnel_cos_data)
{
    sai_status_t          sai_status;
    sx_tunnel_direction_e sx_tunnel_direction;
    uint32_t              tunnel_db_idx = 0;

    SX_LOG_ENTER();

    if (!sx_tunnel_cos_data) {
        SX_LOG_ERR("NULL sx_tunnel_cos_data\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    sx_tunnel_direction = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr.direction;

    if (SX_TUNNEL_COS_PARAM_TYPE_ENCAP_E == sx_tunnel_cos_data->param_type) {
        if ((SX_TUNNEL_DIRECTION_ENCAP == sx_tunnel_direction) ||
            (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_direction)) {
            memcpy(sx_tunnel_cos_data, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_encap_cos_data,
                   sizeof(sx_tunnel_cos_data_t));
        } else {
            SX_LOG_ERR("Error getting encap cos data from decap tunnel from sai tunnel id %" PRIx64 "\n",
                       sai_tunnel_id);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    } else if (SX_TUNNEL_COS_PARAM_TYPE_DECAP_E == sx_tunnel_cos_data->param_type) {
        if ((SX_TUNNEL_DIRECTION_DECAP == sx_tunnel_direction) ||
            (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_direction)) {
            memcpy(sx_tunnel_cos_data, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_decap_cos_data,
                   sizeof(sx_tunnel_cos_data_t));
        } else {
            SX_LOG_ERR("Error getting decap cos data from encap tunnel from sai tunnel id %" PRIx64 "\n",
                       sai_tunnel_id);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *  Callers need to lock around this method
 */
static sai_status_t mlnx_sai_get_tunnel_ttl_data(_In_ sai_object_id_t        sai_tunnel_id,
                                                 _Out_ sx_tunnel_ttl_data_t *sx_tunnel_ttl_data)
{
    sai_status_t          sai_status;
    sx_tunnel_direction_e sx_tunnel_direction;
    uint32_t              tunnel_db_idx = 0;

    SX_LOG_ENTER();

    if (!sx_tunnel_ttl_data) {
        SX_LOG_ERR("NULL sx_tunnel_ttl_data\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    sx_tunnel_direction = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr.direction;

    if (SX_TUNNEL_DIRECTION_ENCAP == sx_tunnel_ttl_data->direction) {
        if ((SX_TUNNEL_DIRECTION_ENCAP == sx_tunnel_direction) ||
            (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_direction)) {
            memcpy(sx_tunnel_ttl_data, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_encap_ttl_data_attrib,
                   sizeof(sx_tunnel_ttl_data_t));
        } else {
            SX_LOG_ERR("Error getting encap ttl data from decap tunnel from sai tunnel id %" PRIx64 "\n",
                       sai_tunnel_id);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    } else if (SX_TUNNEL_DIRECTION_DECAP == sx_tunnel_ttl_data->direction) {
        if ((SX_TUNNEL_DIRECTION_DECAP == sx_tunnel_direction) ||
            (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_direction)) {
            memcpy(sx_tunnel_ttl_data, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_decap_ttl_data_attrib,
                   sizeof(sx_tunnel_ttl_data_t));
        } else {
            SX_LOG_ERR("Error getting decap ttl data from encap tunnel from sai tunnel id %" PRIx64 "\n",
                       sai_tunnel_id);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *  Callers need to lock around this method
 */
static sai_status_t mlnx_sai_reserve_tunnel_db_item(_In_ sai_tunnel_type_t sai_tunnel_type,
                                                    _Out_ uint32_t        *tunnel_db_idx)
{
    uint32_t ii;
    uint32_t idx_start = 0;
    uint32_t idx_end = MAX_TUNNEL_DB_SIZE;

    SX_LOG_ENTER();

    if (!tunnel_db_idx) {
        SX_LOG_ERR("NULL tunnel_db_idx\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (sai_tunnel_type) {
    case SAI_TUNNEL_TYPE_IPINIP:
    case SAI_TUNNEL_TYPE_IPINIP_GRE:
        idx_start = MLNX_MAX_TUNNEL_NVE;
        idx_end = MAX_TUNNEL_DB_SIZE;
        break;

    case SAI_TUNNEL_TYPE_VXLAN:
        idx_start = 0;
        idx_end = MLNX_MAX_TUNNEL_NVE;
        break;

    default:
        SX_LOG_ERR("Unsupported tunnel type: %d\n", sai_tunnel_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    for (ii = idx_start; ii < idx_end; ii++) {
        if (!g_sai_tunnel_db_ptr->tunnel_entry_db[ii].is_used) {
            g_sai_tunnel_db_ptr->tunnel_entry_db[ii].is_used = true;
            *tunnel_db_idx = ii;
            SX_LOG_DBG("tunnel db: reserved slot:%d\n", ii);
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_TABLE_FULL;
}

/*
 *  Callers need to lock around this method
 */
static sai_status_t mlnx_sai_tunnel_create_tunnel_object_id(_In_ sai_tunnel_type_t sai_tunnel_type,
                                                            _Out_ sai_object_id_t *sai_tunnel_id)
{
    sai_status_t sai_status;
    uint32_t     tunnel_db_idx;

    SX_LOG_ENTER();
    if (!sai_tunnel_id) {
        SX_LOG_ERR("NULL sai_tunnel_id\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_reserve_tunnel_db_item(sai_tunnel_type,
                                                                            &tunnel_db_idx))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL, tunnel_db_idx, NULL, sai_tunnel_id))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_get_sx_vrid_from_sx_rif(_In_ sx_router_interface_t sdk_rif_id,
                                                     _Out_ sx_router_id_t      *sdk_vrid)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_status_t                 sdk_status = SX_STATUS_ERROR;
    sx_router_interface_param_t sdk_intf_params;
    sx_interface_attributes_t   sdk_intf_attribs;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (sdk_status =
             sx_api_router_interface_get(gh_sdk, sdk_rif_id, sdk_vrid, &sdk_intf_params, &sdk_intf_attribs))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error getting sdk vrid from sdk rif id %d, sx status: %s\n", sdk_rif_id,
                   SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_fill_tunnel_ttl_data(_In_ uint32_t               attr_count,
                                                  _In_ const sai_attribute_t *attr_list,
                                                  _In_ sai_tunnel_type_t      sai_tunnel_type,
                                                  _Out_ sx_tunnel_ttl_data_t *sdk_encap_ttl_data_attrib,
                                                  _Out_ sx_tunnel_ttl_data_t *sdk_decap_ttl_data_attrib,
                                                  _Out_ bool                 *has_encap_attr,
                                                  _Out_ bool                 *has_decap_attr)
{
    sai_status_t                 sai_status = SAI_STATUS_FAILURE;
    sai_status_t                 sai_encap_ttl_mode_status = SAI_STATUS_FAILURE;
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    const bool                   is_ipinip = (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
                                             (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type);
    bool is_spc1;

    sai_db_read_lock();
    is_spc1 = mlnx_chip_is_spc();
    sai_db_unlock();


    sai_encap_ttl_mode_status = find_attrib_in_list(attr_count,
                                                    attr_list,
                                                    SAI_TUNNEL_ATTR_ENCAP_TTL_MODE,
                                                    &attr,
                                                    &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_encap_ttl_mode_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL:
            if (!is_ipinip && is_spc1) {
                SX_LOG_ERR("Uniform model is not supported for non-ipinip type on Spectrum 1\n");
                SX_LOG_EXIT();
                return SAI_STATUS_NOT_SUPPORTED;
            }
            sdk_encap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_COPY_E;
            break;

        case SAI_TUNNEL_TTL_MODE_PIPE_MODEL:
            sdk_encap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_SET_E;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel ttl type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;
        }
        *has_encap_attr = true;
    } else {
        if (!is_ipinip && is_spc1) {
            sdk_encap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_SET_E;
            SX_LOG_WRN(
                "TTL uniform model is not supported for non-ipinip type on Spectrum 1, using default settings in switch\n");
        } else {
            sdk_encap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_COPY_E;
        }
    }

    sdk_encap_ttl_data_attrib->direction = SX_TUNNEL_DIRECTION_ENCAP;

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_TTL_VAL, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (sdk_encap_ttl_data_attrib->ttl_cmd) {
        case SX_TUNNEL_TTL_CMD_COPY_E:
            SX_LOG_ERR("Tunnel encap ttl val can only be set for pipe model\n");
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;

        case SX_TUNNEL_TTL_CMD_SET_E:
            sdk_encap_ttl_data_attrib->ttl_value = attr->u8;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel ttl type %d\n", sdk_encap_ttl_data_attrib->ttl_cmd);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;
        }
    } else if (sdk_encap_ttl_data_attrib->ttl_cmd == SX_TUNNEL_TTL_CMD_SET_E) {
        /* According to SAI spec and meta data check, TTL Val is mandatory for Pipe mode.
         * We only get here for VXLAN encap, where the default (non-spec) value is pipe,
         * without necessity to supply the TTL value
         * For COPY command, the application can't supply TTL Val using SAI API
         * The value should remain as 0, and SDK will use default for non IP packets
         * where value can't be copied on encap, as discussed in #3135761 */
        SX_LOG_NTC("ttl val is not specified, using default value 255\n");
        sdk_encap_ttl_data_attrib->ttl_value = 255;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_DECAP_TTL_MODE, &attr, &attr_idx);
    if (is_ipinip && (SAI_STATUS_SUCCESS != sai_status)) {
        SX_LOG_ERR(
            "Failed to obtain required attribute SAI_TUNNEL_ATTR_DECAP_TTL_MODE for SAI_TUNNEL_TYPE_IPINIP or SAI_TUNNEL_TYPE_IPINIP_GRE tunnel type\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    *has_decap_attr = true;

    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL:
            /*sdk_decap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_COPY_E;*/
            SX_LOG_ERR("Unsupported SAI tunnel ttl type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;

        case SAI_TUNNEL_TTL_MODE_PIPE_MODEL:
            sdk_decap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_SET_E;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel ttl type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;
        }
        *has_decap_attr = true;
    } else {
        SX_LOG_WRN("TTL uniform model is not supported, using default settings in switch\n");
        sdk_decap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_SET_E;
    }

    sdk_decap_ttl_data_attrib->direction = SX_TUNNEL_DIRECTION_DECAP;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_fill_tunnel_decap_standard_ecn(_Inout_ sx_tunnel_cos_data_t *sdk_decap_cos_data)
{
    /* Based on RFC 6040 */
    const uint8_t non_ect = 0;
    const uint8_t ect1 = 1;
    const uint8_t ect0 = 2;
    const uint8_t ce = 3;

    SX_LOG_ENTER();

    if (NULL == sdk_decap_cos_data) {
        SX_LOG_ERR("Null pointer sdk_decap_cos_data\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    /* SX_TRAP_PRIORITY_LOW:  triggers TRAP_ID_DECAP_ECN0, default action FORWARD
    *  SX_TRAP_PRIORITY_HIGH: triggers TRAP_ID_DECAP_ECN1, default action DROP */

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][non_ect].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][non_ect].egress_ecn = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].egress_ecn = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].trap_enable = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].egress_ecn = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].trap_enable = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].egress_ecn = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].trap_enable = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].trap_attr.prio = SX_TRAP_PRIORITY_HIGH;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][non_ect].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][non_ect].egress_ecn = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect1].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect1].egress_ecn = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect1].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].egress_ecn = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].trap_enable = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ce].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ce].egress_ecn = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ce].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][non_ect].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][non_ect].egress_ecn = ect0;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect1].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect1].egress_ecn = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect1].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect0].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect0].egress_ecn = ect0;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect0].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ce].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ce].egress_ecn = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ce].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][non_ect].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][non_ect].egress_ecn = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].egress_ecn = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].trap_enable = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect0].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect0].egress_ecn = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect0].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ce].valid = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ce].egress_ecn = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ce].trap_enable = false;

    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sdk_fill_tunnel_ecn_map_from_tunnel_map_entry(_In_ bool                   is_ipinip,
                                                                       _In_ sai_object_id_t        sai_mapper_obj_id,
                                                                       _In_ tunnel_direction_type  sai_tunnel_map_direction,
                                                                       _Out_ sx_tunnel_cos_data_t *sdk_encap_cos_data,
                                                                       _Out_ sx_tunnel_cos_data_t *sdk_decap_cos_data)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_idx = 0;
    uint32_t     ii = 0;
    uint8_t      oecn_key = 0;
    uint8_t      oecn_value = 0;
    uint8_t      uecn_key = 0;
    uint8_t      uecn_value = 0;

    SX_LOG_ENTER();

    if (NULL == sdk_encap_cos_data) {
        SX_LOG_ERR("sdk_encap_cos_data is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (NULL == sdk_decap_cos_data) {
        SX_LOG_ERR("sdk_decap_cos_data is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(sai_mapper_obj_id, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    for (ii = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_head_idx;
         ii != MLNX_TUNNEL_MAP_ENTRY_INVALID;
         ii = g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].next_tunnel_map_entry_idx) {
        if (sai_mapper_obj_id == g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_id) {
            if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
                switch (g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_type) {
                case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
                case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
                    if (is_ipinip) {
                        SX_LOG_ERR("VLAN_ID_TO_VNI or BRIDGE_IF_TO_VNI is not valid for IP in IP\n");
                        SX_LOG_EXIT();
                        return SAI_STATUS_FAILURE;
                    }
                    continue;
                    break;

                case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
                    oecn_key =
                        g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].oecn_key;
                    uecn_value =
                        g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].uecn_value;
                    sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[oecn_key].valid = true;
                    sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[oecn_key].egress_ecn = uecn_value;
                    break;

                default:
                    SX_LOG_ERR("sai tunnel map type for encap should be %d but getting %d\n",
                               SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN,
                               g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_type);
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
                switch (g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_type) {
                case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
                case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
                    if (is_ipinip) {
                        SX_LOG_ERR("VNI_TO_VLAN_ID or VNI_TO_BRIDGE_IF is not valid for IP in IP\n");
                        SX_LOG_EXIT();
                        return SAI_STATUS_FAILURE;
                    }
                    continue;
                    break;

                case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
                    uecn_key =
                        g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].uecn_key;
                    oecn_key =
                        g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].oecn_key;
                    oecn_value =
                        g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].oecn_value;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_key][uecn_key].valid = true;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_key][uecn_key].egress_ecn =
                        oecn_value;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_key][uecn_key].trap_enable = false;
                    break;

                default:
                    SX_LOG_ERR("sai tunnel map type for decap should be %d but getting %d\n",
                               SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN,
                               g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_type);
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            }
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_fill_tunnel_user_defined_ecn(_In_ bool                   is_ipinip,
                                                          _In_ mlnx_tunnel_entry_t   *mlnx_tunnel_db_entry,
                                                          _In_ tunnel_direction_type  sai_tunnel_map_direction,
                                                          _Out_ sx_tunnel_cos_data_t *sdk_encap_cos_data,
                                                          _Out_ sx_tunnel_cos_data_t *sdk_decap_cos_data)
{
    uint32_t          ii = 0;
    sai_object_id_t   sai_mapper_obj_id = SAI_NULL_OBJECT_ID;
    sai_status_t      sai_status = SAI_STATUS_FAILURE;
    uint32_t          tunnel_map_cnt = 0;
    sai_object_type_t sai_obj_type = SAI_OBJECT_TYPE_NULL;

    SX_LOG_ENTER();

    assert((TUNNEL_ENCAP == sai_tunnel_map_direction) || (TUNNEL_DECAP == sai_tunnel_map_direction));

    if (NULL == mlnx_tunnel_db_entry) {
        SX_LOG_ERR("mlnx_tunnel_db_entry is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (NULL == sdk_encap_cos_data) {
        SX_LOG_ERR("sdk_encap_cos_data is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (NULL == sdk_decap_cos_data) {
        SX_LOG_ERR("sdk_decap_cos_data is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_db_write_lock();

    if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
        tunnel_map_cnt = mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt;
    } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
        tunnel_map_cnt = mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt;
    }

    for (ii = 0; ii < tunnel_map_cnt; ii++) {
        if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
            sai_mapper_obj_id = mlnx_tunnel_db_entry->sai_tunnel_map_encap_id_array[ii];
        } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
            sai_mapper_obj_id = mlnx_tunnel_db_entry->sai_tunnel_map_decap_id_array[ii];
        }

        sai_obj_type = sai_object_type_query(sai_mapper_obj_id);

        if (SAI_OBJECT_TYPE_TUNNEL_MAP == sai_obj_type) {
            sai_status = mlnx_sdk_fill_tunnel_ecn_map_from_tunnel_map_entry(is_ipinip,
                                                                            sai_mapper_obj_id,
                                                                            sai_tunnel_map_direction,
                                                                            sdk_encap_cos_data,
                                                                            sdk_decap_cos_data);
            if (SAI_STATUS_SUCCESS != sai_status) {
                sai_db_unlock();
                SX_LOG_ERR("Error fill tunnel ecn map from tunnel map entry\n");
                SX_LOG_EXIT();
                return sai_status;
            }
        } else {
            sai_db_unlock();
            SX_LOG_ERR("Unsupported sai object type %s for tunnel map list\n", SAI_TYPE_STR(sai_obj_type));
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_fill_tunnel_cos_data(_In_ uint32_t               attr_count,
                                                  _In_ const sai_attribute_t *attr_list,
                                                  _In_ sai_tunnel_type_t      sai_tunnel_type,
                                                  _In_ mlnx_tunnel_entry_t   *mlnx_tunnel_db_entry,
                                                  _Out_ sx_tunnel_cos_data_t *sdk_encap_cos_data,
                                                  _Out_ sx_tunnel_cos_data_t *sdk_decap_cos_data,
                                                  _Out_ bool                 *has_encap_attr,
                                                  _Out_ bool                 *has_decap_attr)
{
    sai_status_t                 sai_status = SAI_STATUS_FAILURE;
    sai_status_t                 encap_mapper_sai_status = SAI_STATUS_FAILURE;
    sai_status_t                 decap_mapper_sai_status = SAI_STATUS_FAILURE;
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    uint32_t                     uecn_idx = 0;
    uint32_t                     oecn_idx = 0;
    const bool                   is_ipinip = (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
                                             (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type);

    SX_LOG_ENTER();

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL:
            sdk_encap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_DISABLE_E;
            sdk_encap_cos_data->dscp_action = SX_COS_DSCP_ACTION_COPY_E;
            break;

        case SAI_TUNNEL_DSCP_MODE_PIPE_MODEL:
            sdk_encap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_DISABLE_E;
            sdk_encap_cos_data->dscp_action = SX_COS_DSCP_ACTION_SET_E;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel dscp type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;
        }
        *has_encap_attr = true;
    } else {
        sdk_encap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_DISABLE_E;
        sdk_encap_cos_data->dscp_action = SX_COS_DSCP_ACTION_COPY_E;
    }

    sdk_encap_cos_data->param_type = SX_TUNNEL_COS_PARAM_TYPE_ENCAP_E;
    sdk_encap_cos_data->update_priority_color = false;

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (sdk_encap_cos_data->dscp_action) {
        case SX_COS_DSCP_ACTION_COPY_E:
            SX_LOG_ERR("Tunnel encap dscp val can only be set for pipe model\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;

        case SX_COS_DSCP_ACTION_SET_E:
            sdk_encap_cos_data->dscp_value = attr->u8;
            break;

        default:
            SX_LOG_ERR("Unsupported sdk tunnel dscp action %d\n", sdk_encap_cos_data->dscp_action);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;
        }
    } else {
        switch (sdk_encap_cos_data->dscp_action) {
        case SX_COS_DSCP_ACTION_COPY_E:
            break;

        case SX_COS_DSCP_ACTION_SET_E:
            SX_LOG_ERR("Missing encap DSCP value for encap dscp pipe model\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;

        default:
            SX_LOG_ERR("Unsupported sdk tunnel dscp action %d\n", sdk_encap_cos_data->dscp_action);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;
        }
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_DECAP_DSCP_MODE, &attr, &attr_idx);
    if (is_ipinip && (SAI_STATUS_SUCCESS != sai_status)) {
        SX_LOG_ERR(
            "Failed to obtain required attribute SAI_TUNNEL_ATTR_DECAP_DSCP_MODE for SAI_TUNNEL_TYPEIPINIP or SAI_TUNNEL_TYPE_IPINIP_GRE tunnel type\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL:
            sdk_decap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_DISABLE_E;
            sdk_decap_cos_data->dscp_action = SX_COS_DSCP_ACTION_COPY_E;
            break;

        case SAI_TUNNEL_DSCP_MODE_PIPE_MODEL:
            sdk_decap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_DISABLE_E;
            sdk_decap_cos_data->dscp_action = SX_COS_DSCP_ACTION_PRESERVE_E;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel dscp type %d\n", attr->s32);
            break;
        }
    } else {
        sdk_decap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_DISABLE_E;
        sdk_decap_cos_data->dscp_action = SX_COS_DSCP_ACTION_COPY_E;
    }

    sdk_decap_cos_data->param_type = SX_TUNNEL_COS_PARAM_TYPE_DECAP_E;
    sdk_decap_cos_data->update_priority_color = false;
    sdk_decap_cos_data->prio_color.priority = 0;
    sdk_decap_cos_data->prio_color.color = 0;
    sdk_decap_cos_data->dscp_value = 0;

    encap_mapper_sai_status = find_attrib_in_list(attr_count,
                                                  attr_list,
                                                  SAI_TUNNEL_ATTR_ENCAP_MAPPERS,
                                                  &attr,
                                                  &attr_idx);
    if (SAI_STATUS_SUCCESS == encap_mapper_sai_status) {
        if (MLNX_TUNNEL_MAP_MAX < attr->objlist.count) {
            SX_LOG_ERR("Number of encap mappers should be no more than %d\n", MLNX_TUNNEL_MAP_MAX);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        memcpy(mlnx_tunnel_db_entry->sai_tunnel_map_encap_id_array,
               attr->objlist.list,
               attr->objlist.count * sizeof(sai_object_id_t));
        mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt = attr->objlist.count;

        SX_LOG_DBG("encap map cnt: %d\n", attr->objlist.count);

        *has_encap_attr = true;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_ECN_MODE, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_ENCAP_ECN_MODE_STANDARD:
            if (is_ipinip) {
                if (SAI_STATUS_SUCCESS == encap_mapper_sai_status) {
                    SX_LOG_ERR("Encap mappers are invalid for IPinIP standard ecn mode\n");
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                } else {
                    mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt = 0;
                }
            }
            for (uecn_idx = 0; uecn_idx < COS_ECN_MAX_NUM + 1; uecn_idx++) {
                sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[uecn_idx].valid = true;
                sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[uecn_idx].egress_ecn = uecn_idx;
            }
            break;

        case SAI_TUNNEL_ENCAP_ECN_MODE_USER_DEFINED:
            if (SAI_ERR(encap_mapper_sai_status)) {
                SX_LOG_ERR("Encap mapper should be provided for user defined encap ecn mode\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            sai_status = mlnx_sdk_fill_tunnel_user_defined_ecn(is_ipinip,
                                                               mlnx_tunnel_db_entry,
                                                               TUNNEL_ENCAP,
                                                               sdk_encap_cos_data,
                                                               sdk_decap_cos_data);
            if (SAI_STATUS_SUCCESS != sai_status) {
                SX_LOG_ERR("Error fill user defined encap ECN\n");
                SX_LOG_EXIT();
                return sai_status;
            }
            break;

        default:
            SX_LOG_ERR("Unrecognized encap ecn mode type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;
        }
        *has_encap_attr = true;
    } else {
        if (is_ipinip) {
            if (SAI_STATUS_SUCCESS == encap_mapper_sai_status) {
                SX_LOG_ERR("Encap mappers are invalid for IPinIP standard ecn mode\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            } else {
                mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt = 0;
            }
        }
        for (uecn_idx = 0; uecn_idx < COS_ECN_MAX_NUM + 1; uecn_idx++) {
            sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[uecn_idx].valid = true;
            sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[uecn_idx].egress_ecn = uecn_idx;
        }
    }

    decap_mapper_sai_status = find_attrib_in_list(attr_count,
                                                  attr_list,
                                                  SAI_TUNNEL_ATTR_DECAP_MAPPERS,
                                                  &attr,
                                                  &attr_idx);
    if (SAI_STATUS_SUCCESS == decap_mapper_sai_status) {
        if (MLNX_TUNNEL_MAP_MAX < attr->objlist.count) {
            SX_LOG_ERR("Number of encap mappers should be no more than %d\n", MLNX_TUNNEL_MAP_MAX);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        memcpy(mlnx_tunnel_db_entry->sai_tunnel_map_decap_id_array,
               attr->objlist.list,
               attr->objlist.count * sizeof(sai_object_id_t));
        mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt = attr->objlist.count;

        SX_LOG_DBG("decap map cnt: %d\n", attr->objlist.count);

        *has_decap_attr = true;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_DECAP_ECN_MODE, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_DECAP_ECN_MODE_STANDARD:
            if (is_ipinip) {
                if (SAI_STATUS_SUCCESS == decap_mapper_sai_status) {
                    SX_LOG_ERR("Decap mappers are invalid for IPinIP standard ecn mode\n");
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                } else {
                    mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt = 0;
                }
            }
            if (SAI_STATUS_SUCCESS !=
                (sai_status = mlnx_sdk_fill_tunnel_decap_standard_ecn(sdk_decap_cos_data))) {
                SX_LOG_ERR("Error fill tunnel decap standard ecn");
                SX_LOG_EXIT();
                return sai_status;
            }
            break;

        case SAI_TUNNEL_DECAP_ECN_MODE_COPY_FROM_OUTER:
            if (is_ipinip) {
                if (SAI_STATUS_SUCCESS == decap_mapper_sai_status) {
                    SX_LOG_ERR("Decap mappers are invalid for IPinIP copy from outer ecn mode\n");
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                } else {
                    mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt = 0;
                }
            }
            for (oecn_idx = 0; oecn_idx < COS_ECN_MAX_NUM + 1; oecn_idx++) {
                for (uecn_idx = 0; uecn_idx < COS_ECN_MAX_NUM + 1; uecn_idx++) {
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_idx][uecn_idx].valid = true;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_idx][uecn_idx].egress_ecn =
                        uecn_idx;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_idx][uecn_idx].trap_enable = false;
                }
            }
            break;

        case SAI_TUNNEL_DECAP_ECN_MODE_USER_DEFINED:
            if (SAI_ERR(decap_mapper_sai_status)) {
                SX_LOG_ERR("Decap mapper should be provided for user defined decap ecn mode\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            sai_status = mlnx_sdk_fill_tunnel_user_defined_ecn(is_ipinip,
                                                               mlnx_tunnel_db_entry,
                                                               TUNNEL_DECAP,
                                                               sdk_encap_cos_data,
                                                               sdk_decap_cos_data);
            if (SAI_STATUS_SUCCESS != sai_status) {
                SX_LOG_ERR("Error fill user defined decap ECN\n");
                SX_LOG_EXIT();
                return sai_status;
            }
            break;

        default:
            SX_LOG_ERR("Unrecognized decap ecn mode type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;
        }

        *has_decap_attr = true;
    } else {
        if (is_ipinip) {
            if (SAI_STATUS_SUCCESS == decap_mapper_sai_status) {
                SX_LOG_ERR("Decap mappers are invalid for IPinIP standard ecn mode\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            } else {
                mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt = 0;
            }
        }
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sdk_fill_tunnel_decap_standard_ecn(sdk_decap_cos_data))) {
            SX_LOG_ERR("Error fill tunnel decap standard ecn\n");
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_fill_ipinip_p2p_attrib(_In_ uint32_t                           attr_count,
                                                    _In_ const sai_attribute_t             *attr_list,
                                                    _In_ uint32_t                           tunnel_db_idx,
                                                    _In_ sai_tunnel_type_t                  sai_tunnel_type,
                                                    _Out_ sx_tunnel_ipinip_p2p_attribute_t *sdk_ipinip_p2p_attrib,
                                                    _Out_ sx_tunnel_ttl_data_t             *sdk_encap_ttl_data_attrib,
                                                    _Out_ sx_tunnel_ttl_data_t             *sdk_decap_ttl_data_attrib,
                                                    _Out_ sx_tunnel_cos_data_t             *sdk_encap_cos_data,
                                                    _Out_ sx_tunnel_cos_data_t             *sdk_decap_cos_data,
                                                    _Out_ bool                             *has_encap_attr,
                                                    _Out_ bool                             *has_decap_attr,
                                                    _Out_ sai_object_id_t                  *underlay_rif,
                                                    _Out_ mlnx_tunnel_entry_t              *mlnx_tunnel_db_entry)
{
    sai_status_t                return_status = SAI_STATUS_SUCCESS;
    sai_status_t                status = SAI_STATUS_FAILURE;
    sx_status_t                 sx_status = SX_STATUS_ERROR;
    sx_router_interface_t       sx_rif;
    mlnx_sai_attr_t             mlnx_attr;
    sx_router_id_t              sdk_vrid;
    sx_router_interface_param_t sdk_intf_params;
    sx_interface_attributes_t   sdk_intf_attribs;
    uint32_t                    ii = 0;

    assert((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
           (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type));

    SX_LOG_ENTER();
    find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, &mlnx_attr);
    if (!mlnx_attr.found) {
        SX_LOG_ERR("overlay interface should be specified on creating ip in ip type tunnel\n");
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    status = mlnx_rif_oid_to_sdk_rif_id(mlnx_attr.value->oid, &sx_rif);
    if (SAI_ERR(status)) {
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    sx_status = sx_api_router_interface_get(gh_sdk,
                                            sx_rif,
                                            &sdk_vrid,
                                            &sdk_intf_params,
                                            &sdk_intf_attribs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error getting sdk rif info from sdk rif id %d, sx status: %s\n", sx_rif,
                   SX_STATUS_MSG(sx_status));
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    if (SX_L2_INTERFACE_TYPE_LOOPBACK != sdk_intf_params.type) {
        SX_LOG_ERR("Error: expecting loopback rif, but get type %d, SAI rif oid %" PRIx64 ", sdk rif id %d\n",
                   sdk_intf_params.type, mlnx_attr.value->oid, sx_rif);
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_LOOPBACK_PACKET_ACTION, &mlnx_attr);
    if (mlnx_attr.found) {
        status = mlnx_rif_loopback_action_sai_to_sx(mlnx_attr.value,
                                                    mlnx_attr.index,
                                                    &sdk_intf_attribs);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert packet action.\n");
            return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
            goto exit;
        }
    } else {
        /* Default value is DROP for backward compatibility */
        sai_attribute_value_t value;
        value.s32 = SAI_PACKET_ACTION_DROP;
        status = mlnx_rif_loopback_action_sai_to_sx(&value,
                                                    0,
                                                    &sdk_intf_attribs);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert packet action.\n");
            return_status = SAI_STATUS_FAILURE;
            goto exit;
        }
    }

    sx_status = sx_api_router_interface_set(gh_sdk,
                                            SX_ACCESS_CMD_EDIT,
                                            sdk_vrid,
                                            &sdk_intf_params,
                                            &sdk_intf_attribs,
                                            &sx_rif);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(sx_status));
        return_status = sdk_to_sai(sx_status);
        goto exit;
    }

    for (ii = 0; ii < MAX_TUNNEL_DB_SIZE; ii++) {
        /* overlay_rif is initialized to 0 in SAI tunnel db.
         * Adding (ii !- tunnel_db_idx) to allow the case that overlay rif id ('sx_rif' here) happens to be 0 */
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[ii].is_used && (ii != tunnel_db_idx)) {
            if (sx_rif ==
                g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif) {
                SX_LOG_ERR("Error: overlay rif is already used by tunnel db idx %d\n", ii);
                return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
                goto exit;
            }
        }
    }

    sdk_ipinip_p2p_attrib->overlay_rif = sx_rif;

    find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, &mlnx_attr);
    if (!mlnx_attr.found) {
        SX_LOG_ERR("underlay interface should be specified on creating ip in ip type tunnel\n");
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    status = mlnx_rif_oid_to_sdk_rif_id(mlnx_attr.value->oid, &sx_rif);
    if (SAI_ERR(status)) {
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    sx_status = sx_api_router_interface_get(gh_sdk, sx_rif, &sdk_vrid, &sdk_intf_params, &sdk_intf_attribs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error getting sdk rif info from sdk rif id %d, sx status: %s\n", sx_rif,
                   SX_STATUS_MSG(sx_status));
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    if (SX_L2_INTERFACE_TYPE_LOOPBACK != sdk_intf_params.type) {
        SX_LOG_ERR("Error: expecting loopback rif, but get type %d, SAI rif oid %" PRIx64 ", sdk rif id %d\n",
                   sdk_intf_params.type, mlnx_attr.value->oid, sx_rif);
        return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
        goto exit;
    }

    mlnx_tunnel_fill_ulay_domain_rif(sx_rif,
                                     sdk_vrid,
                                     &sdk_ipinip_p2p_attrib->underlay_rif,
                                     &sdk_ipinip_p2p_attrib->encap.underlay_vrid,
                                     &sdk_ipinip_p2p_attrib->underlay_domain_type);

    *underlay_rif = mlnx_attr.value->oid;

    find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_PEER_MODE, &mlnx_attr);
    if (mlnx_attr.found) {
        if (SAI_TUNNEL_PEER_MODE_P2MP != mlnx_attr.value->s32) {
            SX_LOG_ERR("Only P2MP mode is supported for tunnel peer mode\n");
            return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
            goto exit;
        }
    }

    find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_SRC_IP, &mlnx_attr);
    if (mlnx_attr.found) {
        status = mlnx_translate_sai_ip_address_to_sdk(&mlnx_attr.value->ipaddr,
                                                      &sdk_ipinip_p2p_attrib->encap.underlay_sip);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Error setting src ip on creating tunnel table\n");
            return_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + mlnx_attr.index;
            goto exit;
        }
        *has_encap_attr = true;
    }

    status = mlnx_sdk_fill_tunnel_ttl_data(attr_count,
                                           attr_list,
                                           sai_tunnel_type,
                                           sdk_encap_ttl_data_attrib,
                                           sdk_decap_ttl_data_attrib,
                                           has_encap_attr,
                                           has_decap_attr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error fill sdk tunnel ttl data\n");
        return_status = status;
        goto exit;
    }

    status = mlnx_sdk_fill_tunnel_cos_data(attr_count,
                                           attr_list,
                                           sai_tunnel_type,
                                           mlnx_tunnel_db_entry,
                                           sdk_encap_cos_data,
                                           sdk_decap_cos_data,
                                           has_encap_attr,
                                           has_decap_attr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error fill sdk tunnel cos data\n");
        return_status = status;
        goto exit;
    }

    if (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) {
        find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, &mlnx_attr);
        if (mlnx_attr.found) {
            SX_LOG_ERR("encap gre key valid are only supported for ip in ip gre on create\n");
            return_status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }

        find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, &mlnx_attr);
        if (mlnx_attr.found) {
            SX_LOG_ERR("encap gre key are only supported for ip in ip gre on create\n");
            return_status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
    } else if (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type) {
        sdk_ipinip_p2p_attrib->decap.gre_check_key = false;

        find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, &mlnx_attr);
        if (mlnx_attr.found) {
            if (mlnx_attr.value->booldata) {
                sdk_ipinip_p2p_attrib->encap.gre_mode = SX_TUNNEL_IPINIP_GRE_MODE_ENABLED_WITH_KEY;

                find_attrib(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, &mlnx_attr);
                if (!mlnx_attr.found) {
                    SX_LOG_ERR("gre key is missing when encap gre key valid is set to true\n");
                    return_status = SAI_STATUS_FAILURE;
                    goto exit;
                }

                sdk_ipinip_p2p_attrib->encap.gre_key = mlnx_attr.value->u32;
            } else {
                sdk_ipinip_p2p_attrib->encap.gre_mode = SX_TUNNEL_IPINIP_GRE_MODE_ENABLED;
                sdk_ipinip_p2p_attrib->encap.gre_key = 0;
            }
            *has_encap_attr = true;
        }
    }

exit:
    SX_LOG_EXIT();
    return return_status;
}

static sai_status_t mlnx_sai_fill_sx_ipinip_p2p_tunnel_data(_In_ uint32_t                tunnel_db_idx,
                                                            _In_ sai_tunnel_type_t       sai_tunnel_type,
                                                            _In_ uint32_t                attr_count,
                                                            _In_ const sai_attribute_t  *attr_list,
                                                            _Out_ sx_tunnel_attribute_t *sx_tunnel_attribute,
                                                            _Out_ sx_tunnel_ttl_data_t  *sdk_encap_ttl_data_attrib,
                                                            _Out_ sx_tunnel_ttl_data_t  *sdk_decap_ttl_data_attrib,
                                                            _Out_ sx_tunnel_cos_data_t  *sdk_encap_cos_data,
                                                            _Out_ sx_tunnel_cos_data_t  *sdk_decap_cos_data,
                                                            _Out_ sai_object_id_t       *underlay_rif,
                                                            _Out_ mlnx_tunnel_entry_t   *mlnx_tunnel_db_entry)
{
    sai_status_t                      sai_status;
    bool                              has_encap_attr = false;
    bool                              has_decap_attr = false;
    sx_tunnel_ipinip_p2p_attribute_t *sdk_ipinip_p2p_attrib = NULL;

    SX_LOG_ENTER();

    if (!sx_tunnel_attribute) {
        SX_LOG_ERR("NULL sx_tunnel_attribute\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (!attr_list) {
        SX_LOG_ERR("NULL attr_list\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memset(sx_tunnel_attribute, 0, sizeof(sx_tunnel_attribute_t));

    if (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) {
        sdk_ipinip_p2p_attrib = &sx_tunnel_attribute->attributes.ipinip_p2p;
    } else if (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type) {
        sdk_ipinip_p2p_attrib = &sx_tunnel_attribute->attributes.ipinip_p2p_gre;
    } else {
        SX_LOG_ERR("invalid ip in ip tunnel type %d\n", sai_tunnel_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sdk_fill_ipinip_p2p_attrib(attr_count,
                                                      attr_list,
                                                      tunnel_db_idx,
                                                      sai_tunnel_type,
                                                      sdk_ipinip_p2p_attrib,
                                                      sdk_encap_ttl_data_attrib,
                                                      sdk_decap_ttl_data_attrib,
                                                      sdk_encap_cos_data,
                                                      sdk_decap_cos_data,
                                                      &has_encap_attr,
                                                      &has_decap_attr,
                                                      underlay_rif,
                                                      mlnx_tunnel_db_entry))) {
        SX_LOG_ERR("Error filling sdk ipinip p2p attribute\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (has_encap_attr && !has_decap_attr) {
        sx_tunnel_attribute->direction = SX_TUNNEL_DIRECTION_ENCAP;
    } else if (!has_encap_attr && has_decap_attr) {
        sx_tunnel_attribute->direction = SX_TUNNEL_DIRECTION_DECAP;
    } else if (has_encap_attr && has_decap_attr) {
        sx_tunnel_attribute->direction = SX_TUNNEL_DIRECTION_SYMMETRIC;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_1Qbridge_get(_Out_ sx_bridge_id_t *sx_bridge_id)
{
    SX_LOG_ENTER();

    if (NULL == sx_bridge_id) {
        SX_LOG_ERR("sx_bridge_id is NULL pointer\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    *sx_bridge_id = g_sai_db_ptr->sx_bridge_id;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_is_tunnel_map_entry_bound_to_tunnel(_In_ sx_tunnel_id_t sx_tunnel_id,
                                                             _In_ uint32_t       tunnel_map_entry_idx,
                                                             _Out_ bool         *is_bound)
{
    sai_status_t      sai_status;
    sai_object_id_t   tunnel_map_oid;
    uint32_t          curr_tunnel_idx;
    mlnx_tunnel_map_t mlnx_tunnel_map;
    sx_tunnel_id_t    curr_sx_tunnel_id_ipv4;
    sx_tunnel_id_t    curr_sx_tunnel_id_ipv6;
    sai_tunnel_type_t curr_sai_tunnel_type;
    bool              curr_ipv4_created;
    bool              curr_ipv6_created;
    uint32_t          ii;

    SX_LOG_ENTER();

    *is_bound = false;

    if (MLNX_TUNNEL_MAP_ENTRY_MAX <= tunnel_map_entry_idx) {
        SX_LOG_ERR("Tunnel map entry idx %d should be smaller than %d\n",
                   tunnel_map_entry_idx,
                   MLNX_TUNNEL_MAP_ENTRY_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    tunnel_map_oid = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_id;

    sai_status = mlnx_tunnel_map_db_param_get(tunnel_map_oid, &mlnx_tunnel_map);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Fail to obtain tunnel map db entry from tunnel map oid %" PRIx64 "\n", tunnel_map_oid);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    for (ii = 0; ii < mlnx_tunnel_map.tunnel_cnt; ii++) {
        curr_tunnel_idx = mlnx_tunnel_map.tunnel_idx[ii];
        if (MAX_TUNNEL <= curr_tunnel_idx) {
            SX_LOG_ERR("Tunnel idx %d should be smaller than %d\n", curr_tunnel_idx, MAX_TUNNEL);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        curr_sai_tunnel_type = g_sai_tunnel_db_ptr->tunnel_entry_db[curr_tunnel_idx].sai_tunnel_type;
        curr_sx_tunnel_id_ipv4 = g_sai_tunnel_db_ptr->tunnel_entry_db[curr_tunnel_idx].sx_tunnel_id_ipv4;
        curr_sx_tunnel_id_ipv6 = g_sai_tunnel_db_ptr->tunnel_entry_db[curr_tunnel_idx].sx_tunnel_id_ipv6;
        curr_ipv4_created = g_sai_tunnel_db_ptr->tunnel_entry_db[curr_tunnel_idx].ipv4_created;
        curr_ipv6_created = g_sai_tunnel_db_ptr->tunnel_entry_db[curr_tunnel_idx].ipv6_created;
        switch (curr_sai_tunnel_type) {
        case SAI_TUNNEL_TYPE_IPINIP:
        case SAI_TUNNEL_TYPE_IPINIP_GRE:
            if ((curr_ipv4_created &&
                 (sx_tunnel_id == curr_sx_tunnel_id_ipv4)) ||
                (curr_ipv6_created && (sx_tunnel_id == curr_sx_tunnel_id_ipv6))) {
                *is_bound = true;
            }
            break;

        case SAI_TUNNEL_TYPE_VXLAN:
            if ((curr_ipv4_created && (sx_tunnel_id == curr_sx_tunnel_id_ipv4))) {
                *is_bound = true;
            }
            break;

        default:
            SX_LOG_ERR("Unsupported tunnel type %d for tunnel idx %d\n", curr_sai_tunnel_type, curr_tunnel_idx);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    SX_LOG_EXIT();

    return sai_status;
}

/* This function needs to be guarded by lock */
sai_status_t mlnx_vrid_to_br_rif_get(_In_ sx_router_id_t          sx_vrid,
                                     _In_ sx_tunnel_id_t          sx_vxlan_tunnel,
                                     _Out_ sx_router_interface_t *br_rif,
                                     _Out_ sx_fid_t              *br_fid)
{
    sai_status_t             sai_status;
    sai_object_id_t          vr_oid;
    uint32_t                 vni_id;
    sai_object_id_t          bridge_oid;
    sx_bridge_id_t           sx_bridge_id;
    mlnx_tunnel_map_entry_t *curr_tunnel_map_entry;
    mlnx_bridge_rif_t       *curr_bridge_rif_entry;
    uint32_t                 ii = 0;
    uint32_t                 bmtor_bridge_db_idx = 0;
    bool                     is_bound = false;
    const uint32_t           tunnel_idx = 0;

    SX_LOG_ENTER();

    if (NULL == br_rif) {
        SX_LOG_ERR("Empty pointer br_rif\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (NULL == br_fid) {
        SX_LOG_ERR("Empty pointer br_fid\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_create_object(SAI_OBJECT_TYPE_VIRTUAL_ROUTER,
                                    sx_vrid, NULL, &vr_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error find vr oid for sdk vr id %x\n", sx_vrid);
        SX_LOG_EXIT();
        return sai_status;
    }

    /* Get VR ID to VNI map */
    for (ii = 0; ii < MLNX_TUNNEL_MAP_ENTRY_MAX; ii++) {
        curr_tunnel_map_entry = &(g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii]);
        if (NULL == curr_tunnel_map_entry) {
            SX_LOG_ERR("Tunnel map entry %d is empty\n", ii);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        if (curr_tunnel_map_entry->in_use &&
            (SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI == curr_tunnel_map_entry->tunnel_map_type) &&
            (vr_oid == curr_tunnel_map_entry->vr_id_key)) {
            vni_id = curr_tunnel_map_entry->vni_id_value;
            break;
        }
    }
    if (MLNX_TUNNEL_MAP_ENTRY_MAX == ii) {
        SX_LOG_ERR("Failed to find vr oid key %" PRIx64 " in SAI tunnel map entry db\n", vr_oid);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_is_tunnel_map_entry_bound_to_tunnel(sx_vxlan_tunnel,
                                                          ii,
                                                          &is_bound);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to find if tunnel map entry idx %d is bound to sx tunnel id %x\n",
                   ii, sx_vxlan_tunnel);
        SX_LOG_EXIT();
        return sai_status;
    }
    if (!is_bound) {
        SX_LOG_ERR("tunnel map entry idx %d is not bound to sx tunnel id %x\n",
                   ii, sx_vxlan_tunnel);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    /* Get VNI to bridge */
    bmtor_bridge_db_idx = curr_tunnel_map_entry->pair_per_vxlan_array[tunnel_idx].bmtor_bridge_db_idx;
    if (MLNX_BMTOR_BRIDGE_MAX <= bmtor_bridge_db_idx) {
        SX_LOG_ERR("bmtor bridge db idx %d should be smaller than limit %d\n",
                   bmtor_bridge_db_idx, MLNX_BMTOR_BRIDGE_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    if (vni_id != g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].vni) {
        SX_LOG_ERR("VNI %d does not match BMTOR bridge db idx %d VNI %d\n",
                   vni_id, bmtor_bridge_db_idx, g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].vni);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    bridge_oid = g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].bridge_oid;

    sai_status = mlnx_bridge_oid_to_id(bridge_oid, &sx_bridge_id);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to find sx bridge id using bridge oid %" PRIx64 "\n", bridge_oid);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    /* Get bridge to bridge rif */
    for (ii = 0; ii < MAX_BRIDGE_RIFS; ii++) {
        curr_bridge_rif_entry = &(g_sai_db_ptr->bridge_rifs_db[ii]);
        if (NULL == curr_bridge_rif_entry) {
            SX_LOG_ERR("Bridge rif entry %d is empty\n", ii);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        if (curr_bridge_rif_entry->is_used &&
            (sx_bridge_id == curr_bridge_rif_entry->intf_params.ifc.bridge.bridge)) {
            *br_rif = curr_bridge_rif_entry->sx_data.rif_id;
            *br_fid = sx_bridge_id;
            break;
        }
    }

    if (MAX_BRIDGE_RIFS == ii) {
        SX_LOG_ERR("Failed to find bridge id %d in SAI bridge rif db\n", sx_bridge_id);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_fill_tunnel_map_entry(_In_ uint32_t                tunnel_map_entry_idx,
                                                   _Out_ sx_tunnel_map_entry_t *sx_tunnel_map_entry)
{
    sai_vlan_id_t  vlan_id = 1;
    uint32_t       vni_id = 0;
    sx_bridge_id_t sx_bridge_id = 0;
    sai_status_t   sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    assert(MLNX_TUNNEL_MAP_ENTRY_MAX > tunnel_map_entry_idx);

    if (NULL == sx_tunnel_map_entry) {
        SX_LOG_ERR("sx_tunnel_map_entry is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    switch (g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type) {
    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
        vlan_id = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vlan_id_key;
        vni_id = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vni_id_value;
        break;

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
        vni_id = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vni_id_key;
        vlan_id = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vlan_id_value;
        break;

    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_bridge_oid_to_id(g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].bridge_id_key,
                                       &sx_bridge_id))) {
            SX_LOG_ERR("missing bridge port\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        vni_id = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vni_id_value;
        break;

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_bridge_oid_to_id(g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].bridge_id_value,
                                       &sx_bridge_id))) {
            SX_LOG_ERR("missing bridge port\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        vni_id = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vni_id_key;
        break;

    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
        break;

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
    case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
        break;

    default:
        SX_LOG_ERR("Unsupported SAI tunnel map type %d\n",
                   g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
        break;
    }

    if ((SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI ==
         g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type) ||
        (SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID ==
         g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type)) {
        sx_tunnel_map_entry->params.nve.bridge_id = vlan_id;
        sx_tunnel_map_entry->params.nve.direction = SX_TUNNEL_MAP_DIR_BIDIR;
        if (NVE_8021D_TUNNEL == g_sai_db_ptr->nve_tunnel_type) {
            SX_LOG_ERR("802.1Q tunnel map cannot be applied with 802.1D tunnel map at the same time\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        g_sai_db_ptr->nve_tunnel_type = NVE_8021Q_TUNNEL;
    } else {
        sx_tunnel_map_entry->params.nve.bridge_id = sx_bridge_id;
        sx_tunnel_map_entry->params.nve.direction = SX_TUNNEL_MAP_DIR_BIDIR;
        if (NVE_8021Q_TUNNEL == g_sai_db_ptr->nve_tunnel_type) {
            SX_LOG_ERR("802.1D tunnel map cannot be applied with 802.1Q tunnel map at the same time\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        g_sai_db_ptr->nve_tunnel_type = NVE_8021D_TUNNEL;
    }

    sx_tunnel_map_entry->params.nve.vni = vni_id;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_map_entry_ecn_bind_set(_In_ uint32_t tunnel_map_entry_idx, _In_ bool is_add)
{
    uint32_t              tunnel_map_idx = 0;
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_status_t           sdk_status = SX_STATUS_ERROR;
    sx_tunnel_id_t        sx_tunnel_id_ipv4 = 0;
    sx_tunnel_id_t        sx_tunnel_id_ipv6 = 0;
    uint32_t              ii = 0;
    uint32_t              tunnel_idx = 0;
    uint32_t              tunnel_cnt = 0;
    bool                  is_ipinip;
    sai_tunnel_type_t     sai_tunnel_type;
    mlnx_tunnel_entry_t   mlnx_tunnel_db_entry;
    sx_tunnel_cos_data_t  sdk_encap_cos_data;
    sx_tunnel_cos_data_t  sdk_decap_cos_data;
    sai_tunnel_map_type_t tunnel_map_type;
    tunnel_direction_type tunnel_map_direction;

    tunnel_map_type = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type;
    switch (tunnel_map_type) {
    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
        tunnel_map_direction = TUNNEL_ENCAP;
        break;

    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
        tunnel_map_direction = TUNNEL_DECAP;
        break;

    default:
        SX_LOG_ERR("Unsupported ECN tunnel map type: %d\n", tunnel_map_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    tunnel_cnt = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt;

    for (ii = 0; ii < tunnel_cnt; ii++) {
        tunnel_idx = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_idx[ii];
        sx_tunnel_id_ipv4 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sx_tunnel_id_ipv4;
        sx_tunnel_id_ipv6 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sx_tunnel_id_ipv6;

        memcpy(&sdk_encap_cos_data,
               &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sdk_encap_cos_data,
               sizeof(sdk_encap_cos_data));

        memcpy(&sdk_decap_cos_data,
               &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sdk_decap_cos_data,
               sizeof(sdk_decap_cos_data));

        memcpy(&mlnx_tunnel_db_entry,
               &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx],
               sizeof(mlnx_tunnel_db_entry));

        sai_tunnel_type = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_type;

        is_ipinip = (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
                    (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type);

        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].ipv4_created) {
            sai_db_unlock();
            sai_status = mlnx_sdk_fill_tunnel_user_defined_ecn(is_ipinip,
                                                               &mlnx_tunnel_db_entry,
                                                               tunnel_map_direction,
                                                               &sdk_encap_cos_data,
                                                               &sdk_decap_cos_data);

            sai_db_write_lock();
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error fill tunnel user defined ecn\n");
                SX_LOG_EXIT();
                return sai_status;
            }
            if ((SX_TUNNEL_DIRECTION_ENCAP == mlnx_tunnel_db_entry.sx_tunnel_attr.direction) ||
                (SX_TUNNEL_DIRECTION_SYMMETRIC == mlnx_tunnel_db_entry.sx_tunnel_attr.direction)) {
                if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                             sx_tunnel_id_ipv4,
                                                                             &sdk_encap_cos_data))) {
                    sai_status = sdk_to_sai(sdk_status);
                    SX_LOG_ERR("Error setting sdk tunnel ipv4 %d encap cos, sx status: %s\n",
                               sx_tunnel_id_ipv4, SX_STATUS_MSG(sdk_status));
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            }

            if ((SX_TUNNEL_DIRECTION_DECAP == mlnx_tunnel_db_entry.sx_tunnel_attr.direction) ||
                (SX_TUNNEL_DIRECTION_SYMMETRIC == mlnx_tunnel_db_entry.sx_tunnel_attr.direction)) {
                if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                             sx_tunnel_id_ipv4,
                                                                             &sdk_decap_cos_data))) {
                    sai_status = sdk_to_sai(sdk_status);
                    SX_LOG_ERR("Error setting sdk tunnel ipv4 %d decap cos, sx status: %s\n",
                               sx_tunnel_id_ipv4, SX_STATUS_MSG(sdk_status));
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            }
        }
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].ipv6_created) {
            if ((SX_TUNNEL_DIRECTION_ENCAP == mlnx_tunnel_db_entry.sx_tunnel_attr.direction) ||
                (SX_TUNNEL_DIRECTION_SYMMETRIC == mlnx_tunnel_db_entry.sx_tunnel_attr.direction)) {
                if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                             sx_tunnel_id_ipv6,
                                                                             &sdk_encap_cos_data))) {
                    sai_status = sdk_to_sai(sdk_status);
                    SX_LOG_ERR("Error setting sdk tunnel ipv6 %d encap cos, sx status: %s\n",
                               sx_tunnel_id_ipv6, SX_STATUS_MSG(sdk_status));
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            }

            if ((SX_TUNNEL_DIRECTION_DECAP == mlnx_tunnel_db_entry.sx_tunnel_attr.direction) ||
                (SX_TUNNEL_DIRECTION_SYMMETRIC == mlnx_tunnel_db_entry.sx_tunnel_attr.direction)) {
                if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                             sx_tunnel_id_ipv6,
                                                                             &sdk_decap_cos_data))) {
                    sai_status = sdk_to_sai(sdk_status);
                    SX_LOG_ERR("Error setting sdk tunnel ipv6 %d decap cos, sx status: %s\n",
                               sx_tunnel_id_ipv6, SX_STATUS_MSG(sdk_status));
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            }
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_pair_already_exist(_In_ uint32_t tunnel_map_entry_idx,
                                                                 _In_ uint32_t tunnel_idx,
                                                                 _Out_ bool   *pair_already_exist)
{
    mlnx_tunnel_map_entry_t      curr_tunnel_map_entry;
    mlnx_tunnel_map_entry_t      pair_tunnel_map_entry;
    tunnel_map_entry_pair_info_t curr_pair_info;
    tunnel_map_entry_pair_info_t pair_info;
    uint32_t                     pair_map_idx = 0;

    SX_LOG_ENTER();

    memcpy(&curr_tunnel_map_entry,
           &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(curr_tunnel_map_entry));

    memcpy(&curr_pair_info,
           &curr_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx],
           sizeof(curr_pair_info));

    if (!curr_pair_info.pair_exist) {
        *pair_already_exist = false;
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    pair_map_idx = curr_pair_info.pair_tunnel_map_entry_idx;

    memcpy(&pair_tunnel_map_entry,
           &g_sai_tunnel_db_ptr->tunnel_map_entry_db[pair_map_idx],
           sizeof(pair_tunnel_map_entry));

    memcpy(&pair_info,
           &pair_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx],
           sizeof(pair_info));

    assert(curr_tunnel_map_entry.in_use);
    assert(pair_tunnel_map_entry.in_use);

    if (!pair_info.pair_exist) {
        SX_LOG_ERR("Inconsistent tunnel map pair exist data.\
                    Curr tunnel map entry idx: %d, pair exist: %d.\
                    Pair tunnel map entry idx: %d, pair exist: %d\n",
                   tunnel_map_entry_idx,
                   curr_pair_info.pair_exist,
                   pair_map_idx,
                   pair_info.pair_exist);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (pair_info.pair_already_bound_to_tunnel != curr_pair_info.pair_already_bound_to_tunnel) {
        SX_LOG_ERR("Inconsistent tunnel map pair bound to tunnel data.\
                    Curr tunnel map entry idx: %d, pair exist: %d.\
                    Pair tunnel map entry idx: %d, pair exist: %d\n",
                   tunnel_map_entry_idx,
                   curr_pair_info.pair_already_bound_to_tunnel,
                   pair_map_idx,
                   pair_info.pair_already_bound_to_tunnel);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (pair_info.pair_tunnel_map_entry_idx != tunnel_map_entry_idx) {
        SX_LOG_ERR("Pair already added. Curr tunnel map entry idx: %d, Pair tunnel map entry idx: %d",
                   tunnel_map_entry_idx, pair_map_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    *pair_already_exist = true;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_find_pair(_In_ uint32_t   tunnel_map_entry_idx,
                                                        _In_ uint32_t   tunnel_idx,
                                                        _Out_ bool     *pair_exist,
                                                        _Out_ uint32_t *pair_map_idx)
{
    mlnx_tunnel_map_entry_t curr_tunnel_map_entry;
    mlnx_tunnel_map_entry_t pair_tunnel_map_entry;
    mlnx_tunnel_map_t       curr_tunnel_map;
    sai_status_t            sai_status;
    uint32_t                opposite_dir_tunnel_map_cnt = 0;
    sai_object_id_t        *opposite_dir_tunnel_map_array;
    uint32_t                ii = 0;
    uint32_t                jj = 0;
    sai_object_id_t         tunnel_map_oid;

    SX_LOG_ENTER();

    assert(NULL != pair_exist);
    assert(NULL != pair_map_idx);

    memcpy(&curr_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(curr_tunnel_map_entry));

    assert(curr_tunnel_map_entry.in_use);

    switch (curr_tunnel_map_entry.tunnel_map_type) {
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
        opposite_dir_tunnel_map_cnt = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_encap_cnt;
        opposite_dir_tunnel_map_array = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_encap_id_array;
        break;

    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
    case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
        opposite_dir_tunnel_map_cnt = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_decap_cnt;
        opposite_dir_tunnel_map_array = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_decap_id_array;
        break;

    default:
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].pair_exist =
            false;
        *pair_exist =
            false;
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < opposite_dir_tunnel_map_cnt; ii++) {
        tunnel_map_oid = opposite_dir_tunnel_map_array[ii];

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_map_db_param_get(tunnel_map_oid, &curr_tunnel_map))) {
            SX_LOG_ERR("Fail to get mlnx tunnel map for tunnel map obj id %" PRIx64 "\n", tunnel_map_oid);
            SX_LOG_EXIT();
            return sai_status;
        }
        for (jj = curr_tunnel_map.tunnel_map_entry_head_idx;
             jj != MLNX_TUNNEL_MAP_ENTRY_INVALID;
             jj = g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj].next_tunnel_map_entry_idx) {
            memcpy(&pair_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj],
                   sizeof(pair_tunnel_map_entry));
            assert(pair_tunnel_map_entry.in_use);

            if (SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF == curr_tunnel_map_entry.tunnel_map_type) {
                if ((curr_tunnel_map_entry.bridge_id_value == pair_tunnel_map_entry.bridge_id_key) &&
                    (curr_tunnel_map_entry.vni_id_key == pair_tunnel_map_entry.vni_id_value)) {
                    *pair_map_idx = jj;
                    *pair_exist = true;
                    SX_LOG_EXIT();
                    return SAI_STATUS_SUCCESS;
                }
            } else if (SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI == curr_tunnel_map_entry.tunnel_map_type) {
                if ((curr_tunnel_map_entry.bridge_id_key == pair_tunnel_map_entry.bridge_id_value) &&
                    (curr_tunnel_map_entry.vni_id_value == pair_tunnel_map_entry.vni_id_key)) {
                    *pair_map_idx = jj;
                    *pair_exist = true;
                    SX_LOG_EXIT();
                    return SAI_STATUS_SUCCESS;
                }
            } else if (SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID == curr_tunnel_map_entry.tunnel_map_type) {
                if ((curr_tunnel_map_entry.vr_id_value == pair_tunnel_map_entry.vr_id_key) &&
                    (curr_tunnel_map_entry.vni_id_key == pair_tunnel_map_entry.vni_id_value)) {
                    *pair_map_idx = jj;
                    *pair_exist = true;
                    SX_LOG_EXIT();
                    return SAI_STATUS_SUCCESS;
                }
            } else if (SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI == curr_tunnel_map_entry.tunnel_map_type) {
                if ((curr_tunnel_map_entry.vr_id_key == pair_tunnel_map_entry.vr_id_value) &&
                    (curr_tunnel_map_entry.vni_id_value == pair_tunnel_map_entry.vni_id_key)) {
                    *pair_map_idx = jj;
                    *pair_exist = true;
                    SX_LOG_EXIT();
                    return SAI_STATUS_SUCCESS;
                }
            } else if (SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID == curr_tunnel_map_entry.tunnel_map_type) {
                if ((curr_tunnel_map_entry.vlan_id_value == pair_tunnel_map_entry.vlan_id_key) &&
                    (curr_tunnel_map_entry.vni_id_key == pair_tunnel_map_entry.vni_id_value)) {
                    *pair_map_idx = jj;
                    *pair_exist = true;
                    SX_LOG_EXIT();
                    return SAI_STATUS_SUCCESS;
                }
            } else if (SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI == curr_tunnel_map_entry.tunnel_map_type) {
                if ((curr_tunnel_map_entry.vlan_id_key == pair_tunnel_map_entry.vlan_id_value) &&
                    (curr_tunnel_map_entry.vni_id_value == pair_tunnel_map_entry.vni_id_key)) {
                    *pair_map_idx = jj;
                    *pair_exist = true;
                    SX_LOG_EXIT();
                    return SAI_STATUS_SUCCESS;
                }
            }
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_pair_add(_In_ uint32_t tunnel_map_entry_idx,
                                                       _In_ uint32_t tunnel_idx,
                                                       _In_ uint32_t pair_map_idx)
{
    mlnx_tunnel_map_entry_t      curr_tunnel_map_entry;
    mlnx_tunnel_map_entry_t      pair_tunnel_map_entry;
    tunnel_map_entry_pair_info_t curr_pair_info;
    tunnel_map_entry_pair_info_t pair_info;

    SX_LOG_ENTER();

    memcpy(&curr_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(curr_tunnel_map_entry));
    memcpy(&pair_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[pair_map_idx],
           sizeof(pair_tunnel_map_entry));

    memcpy(&curr_pair_info,
           &curr_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx],
           sizeof(curr_pair_info));
    memcpy(&pair_info,
           &pair_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx],
           sizeof(pair_info));

    if (curr_pair_info.pair_exist != pair_info.pair_exist) {
        SX_LOG_ERR("Inconsistent tunnel map pair exist data.\
                    Curr tunnel map entry idx: %d, pair exist: %d.\
                    Pair tunnel map entry idx: %d, pair exist: %d\n",
                   tunnel_map_entry_idx,
                   curr_pair_info.pair_exist,
                   pair_map_idx,
                   pair_info.pair_exist);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    if (curr_pair_info.pair_exist && pair_info.pair_exist) {
        SX_LOG_ERR("Pair already added. Curr tunnel map entry idx: %d, Pair tunnel map entry idx: %d",
                   tunnel_map_entry_idx, pair_map_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    assert(curr_tunnel_map_entry.in_use);

    pair_info.pair_exist = true;
    pair_info.pair_tunnel_map_entry_idx = tunnel_map_entry_idx;

    curr_pair_info.pair_exist = true;
    curr_pair_info.pair_already_bound_to_tunnel = pair_info.pair_already_bound_to_tunnel;
    curr_pair_info.pair_tunnel_map_entry_idx = pair_map_idx;
    curr_pair_info.bmtor_bridge_db_idx = pair_info.bmtor_bridge_db_idx;

    memcpy(&curr_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx],
           &curr_pair_info,
           sizeof(curr_pair_info));
    memcpy(&pair_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx],
           &pair_info,
           sizeof(pair_info));

    memcpy(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx], &curr_tunnel_map_entry,
           sizeof(curr_tunnel_map_entry));
    memcpy(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[pair_map_idx], &pair_tunnel_map_entry,
           sizeof(pair_tunnel_map_entry));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_bind_status(_In_ uint32_t tunnel_map_entry_idx,
                                                          _In_ uint32_t tunnel_idx,
                                                          _Out_ bool   *already_bind)
{
    mlnx_tunnel_map_entry_t      curr_tunnel_map_entry;
    mlnx_tunnel_map_entry_t      pair_tunnel_map_entry;
    tunnel_map_entry_pair_info_t curr_pair_info;
    tunnel_map_entry_pair_info_t pair_info;
    uint32_t                     pair_map_idx;

    SX_LOG_ENTER();

    memcpy(&curr_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(curr_tunnel_map_entry));
    assert(curr_tunnel_map_entry.in_use);
    memcpy(&curr_pair_info, &curr_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx], sizeof(curr_pair_info));
    if (!curr_pair_info.pair_exist) {
        *already_bind = curr_pair_info.pair_already_bound_to_tunnel;
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }
    pair_map_idx = curr_pair_info.pair_tunnel_map_entry_idx;

    memcpy(&pair_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[pair_map_idx],
           sizeof(pair_tunnel_map_entry));
    memcpy(&pair_info, &pair_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx], sizeof(pair_info));

    assert(curr_pair_info.pair_already_bound_to_tunnel == pair_info.pair_already_bound_to_tunnel);

    *already_bind = pair_info.pair_already_bound_to_tunnel;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_pair_bind_tunnel(_In_ uint32_t tunnel_map_entry_idx,
                                                               _In_ uint32_t tunnel_idx,
                                                               _In_ bool     is_add)
{
    mlnx_tunnel_map_entry_t      curr_tunnel_map_entry;
    tunnel_map_entry_pair_info_t curr_pair_info;

    SX_LOG_ENTER();

    memcpy(&curr_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(curr_tunnel_map_entry));
    assert(curr_tunnel_map_entry.in_use);
    memcpy(&curr_pair_info, &curr_tunnel_map_entry.pair_per_vxlan_array[tunnel_idx], sizeof(curr_pair_info));
    g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
    pair_already_bound_to_tunnel = is_add;

    if (curr_pair_info.pair_exist) {
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[curr_pair_info.pair_tunnel_map_entry_idx].
        pair_per_vxlan_array[tunnel_idx].
        pair_already_bound_to_tunnel = is_add;
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_pair_delete(_In_ uint32_t tunnel_map_entry_idx, _In_ uint32_t tunnel_idx)
{
    mlnx_tunnel_map_entry_t curr_tunnel_map_entry;
    uint32_t                pair_idx;

    SX_LOG_ENTER();

    memcpy(&curr_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(curr_tunnel_map_entry));

    assert(curr_tunnel_map_entry.in_use);

    switch (curr_tunnel_map_entry.tunnel_map_type) {
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
    case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
        break;

    default:
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].pair_exist
        = false;
    g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
    pair_already_bound_to_tunnel = false;
    pair_idx
        = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
          pair_tunnel_map_entry_idx;
    g_sai_tunnel_db_ptr->tunnel_map_entry_db[pair_idx].pair_per_vxlan_array[tunnel_idx].pair_exist
        = false;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_clear_vxlan_bind_info(_In_ uint32_t tunnel_idx)
{
    mlnx_tunnel_map_t curr_tunnel_map;
    sai_status_t      sai_status;
    uint32_t          tunnel_map_cnt = 0;
    sai_object_id_t  *tunnel_map_array = NULL;
    uint32_t          ii = 0;
    uint32_t          jj = 0;
    sai_object_id_t   tunnel_map_oid;
    const bool        is_add = false;
    bool              is_vrf_vni_entry = false;

    SX_LOG_ENTER();

    tunnel_map_cnt = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_encap_cnt;
    tunnel_map_array = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_encap_id_array;

    for (ii = 0; ii < tunnel_map_cnt; ii++) {
        tunnel_map_oid = tunnel_map_array[ii];

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_map_db_param_get(tunnel_map_oid, &curr_tunnel_map))) {
            SX_LOG_ERR("Fail to get mlnx tunnel map for tunnel map obj id %" PRIx64 "\n", tunnel_map_oid);
            SX_LOG_EXIT();
            return sai_status;
        }
        switch (curr_tunnel_map.tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
        case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
            is_vrf_vni_entry = false;
            break;

        case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
            is_vrf_vni_entry = true;
            break;

        default:
            continue;
        }
        for (jj = curr_tunnel_map.tunnel_map_entry_head_idx;
             jj != MLNX_TUNNEL_MAP_ENTRY_INVALID;
             jj = g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj].next_tunnel_map_entry_idx) {
            memset(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj].pair_per_vxlan_array[tunnel_idx], 0,
                   sizeof(g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj].pair_per_vxlan_array[tunnel_idx]));
            if (is_vrf_vni_entry) {
                sai_status = mlnx_tunnel_map_entry_set_bmtor_obj(jj,
                                                                 tunnel_idx,
                                                                 is_add);
                if (SAI_ERR(sai_status)) {
                    SX_LOG_ERR("Error setting bmtor obj using tunnel map entry idx %d and tunnel idx %d, is add: %d\n",
                               jj, tunnel_idx, is_add);
                    SX_LOG_EXIT();
                    return sai_status;
                }
            }
        }
    }

    tunnel_map_cnt = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_decap_cnt;
    tunnel_map_array = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sai_tunnel_map_decap_id_array;

    for (ii = 0; ii < tunnel_map_cnt; ii++) {
        tunnel_map_oid = tunnel_map_array[ii];

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_map_db_param_get(tunnel_map_oid, &curr_tunnel_map))) {
            SX_LOG_ERR("Fail to get mlnx tunnel map for tunnel map obj id %" PRIx64 "\n", tunnel_map_oid);
            SX_LOG_EXIT();
            return sai_status;
        }
        switch (curr_tunnel_map.tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
            is_vrf_vni_entry = false;
            break;

        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
            is_vrf_vni_entry = true;
            break;

        default:
            continue;
        }
        for (jj = curr_tunnel_map.tunnel_map_entry_head_idx;
             jj != MLNX_TUNNEL_MAP_ENTRY_INVALID;
             jj = g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj].next_tunnel_map_entry_idx) {
            memset(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj].pair_per_vxlan_array[tunnel_idx], 0,
                   sizeof(g_sai_tunnel_db_ptr->tunnel_map_entry_db[jj].pair_per_vxlan_array[tunnel_idx]));
            if (is_vrf_vni_entry) {
                sai_status = mlnx_tunnel_map_entry_set_bmtor_obj(jj,
                                                                 tunnel_idx,
                                                                 is_add);
                if (SAI_ERR(sai_status)) {
                    SX_LOG_ERR("Error setting bmtor obj using tunnel map entry idx %d and tunnel idx %d, is add: %d\n",
                               jj, tunnel_idx, is_add);
                    SX_LOG_EXIT();
                    return sai_status;
                }
            }
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/* This function needs to be guarded by lock
 * If user pass SAI tunnel map entry <bridge 1, vni 100> and <vni 100, bridge 1>,
 * only bind <bridge 1, vni 100> once to SDK, because SDK treats these 2 maps as the same,
 * and will return 'entry already exist' error.
 * If user pass SAI tunnel map entry <bridge 1, vni 100> and <bridge 1, vni 200>,
 * SDK will also return 'entry already exist' error.
 * This function deal with <bridge 1, vni 100> and <vni 100, bridge 1> case. */
static sai_status_t mlnx_sai_tunnel_map_entry_bind_vxlan_set(_In_ uint32_t               tunnel_map_entry_idx,
                                                             _In_ uint32_t               tunnel_idx,
                                                             _In_ sx_tunnel_id_t         sx_tunnel_id_ipv4,
                                                             _In_ sx_tunnel_map_entry_t *sx_tunnel_map_entry,
                                                             _In_ bool                   is_add)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_status_t           sdk_status = SX_STATUS_ERROR;
    bool                  pair_already_exist = false;
    bool                  pair_exist = false;
    uint32_t              pair_map_idx = 0;
    bool                  already_bind = false;
    const uint32_t        sx_tunnel_map_entry_cnt = 1;
    const sx_access_cmd_t cmd = is_add ? SX_ACCESS_CMD_ADD : SX_ACCESS_CMD_DELETE;
    sai_tunnel_map_type_t tunnel_map_type;

    sai_status = mlnx_sai_tunnel_map_entry_pair_already_exist(tunnel_map_entry_idx,
                                                              tunnel_idx,
                                                              &pair_already_exist);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error find pair exist info for tunnel map entry idx %d with tunnel idx %d\n",
                   tunnel_map_entry_idx, tunnel_idx);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (!pair_already_exist && is_add) {
        sai_status = mlnx_sai_tunnel_map_entry_find_pair(tunnel_map_entry_idx,
                                                         tunnel_idx,
                                                         &pair_exist,
                                                         &pair_map_idx);

        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error find pair for tunnel map entry idx %d with tunnel idx %d\n",
                       tunnel_map_entry_idx, tunnel_idx);
            SX_LOG_EXIT();
            return sai_status;
        }

        if (pair_exist) {
            sai_status = mlnx_sai_tunnel_map_entry_pair_add(tunnel_map_entry_idx,
                                                            tunnel_idx,
                                                            pair_map_idx);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error add pair map idx %d for tunnel map entry idx %d with tunnel idx %d\n",
                           pair_map_idx, tunnel_map_entry_idx, tunnel_idx);
                SX_LOG_EXIT();
                return sai_status;
            }
        }
    } else if (pair_already_exist && !is_add) {
        sai_status = mlnx_sai_tunnel_map_entry_pair_delete(tunnel_map_entry_idx,
                                                           tunnel_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error delete pair map idx %d for tunnel map entry idx %d with tunnel idx %d\n",
                       pair_map_idx, tunnel_map_entry_idx, tunnel_idx);
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    sai_status = mlnx_sai_tunnel_map_entry_bind_status(tunnel_map_entry_idx,
                                                       tunnel_idx,
                                                       &already_bind);

    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error find bind info for tunnel map entry idx %d with tunnel idx %d\n",
                   tunnel_map_entry_idx, tunnel_idx);
        SX_LOG_EXIT();
        return sai_status;
    }

    if ((is_add && !already_bind) || (!is_add && already_bind && !pair_already_exist)) {
        tunnel_map_type = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type;
        if ((SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID != tunnel_map_type) &&
            (SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI != tunnel_map_type)) {
            if (SX_STATUS_SUCCESS !=
                (sdk_status = sx_api_tunnel_map_set(gh_sdk,
                                                    cmd,
                                                    sx_tunnel_id_ipv4,
                                                    sx_tunnel_map_entry,
                                                    sx_tunnel_map_entry_cnt))) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error editing tunnel map associated with sx tunnel id %d, sx status %s\n",
                           sx_tunnel_id_ipv4, SX_STATUS_MSG(sdk_status));
                SX_LOG_EXIT();
                return sai_status;
            }
        } else {
            sai_status = mlnx_tunnel_map_entry_set_bmtor_obj(tunnel_map_entry_idx,
                                                             tunnel_idx,
                                                             is_add);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error setting bmtor obj using tunnel map entry idx %d and tunnel idx %x, is add: %d\n",
                           tunnel_map_entry_idx, tunnel_idx, is_add);
                SX_LOG_EXIT();
                return sai_status;
            }
        }
    }

    sai_status = mlnx_sai_tunnel_map_entry_pair_bind_tunnel(tunnel_map_entry_idx, tunnel_idx, is_add);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error bind/unbind tunnel map entry idx %d to tunnel idx %d\n",
                   tunnel_map_entry_idx, tunnel_idx);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_bind_tunnel_set(_In_ uint32_t tunnel_map_entry_idx, _In_ bool is_add)
{
    uint32_t                tunnel_map_idx = 0;
    sai_status_t            sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_map_entry_t   sx_tunnel_map_entry;
    sx_tunnel_id_t          sx_tunnel_id_ipv4 = 0;
    sai_object_id_t         sai_tunnel_map_oid = SAI_NULL_OBJECT_ID;
    uint32_t                ii = 0;
    uint32_t                tunnel_idx = 0;
    uint32_t                tunnel_cnt = 0;
    sai_tunnel_map_type_t   tunnel_map_type;
    mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry;

    SX_LOG_ENTER();

    memcpy(&mlnx_tunnel_map_entry, &g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
           sizeof(mlnx_tunnel_map_entry));

    sai_tunnel_map_oid = mlnx_tunnel_map_entry.tunnel_map_id;

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(sai_tunnel_map_oid, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   sai_tunnel_map_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    tunnel_cnt = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt;
    if (0 == tunnel_cnt) {
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    memset(&sx_tunnel_map_entry, 0, sizeof(sx_tunnel_map_entry));
    sx_tunnel_map_entry.type = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sx_tunnel_attr.type;
    sai_status = mlnx_sai_fill_tunnel_map_entry(tunnel_map_entry_idx, &sx_tunnel_map_entry);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error filling tunnel map entry for tunnel map entry idx %d\n",
                   tunnel_map_entry_idx);
        SX_LOG_EXIT();
        return sai_status;
    }

    tunnel_map_type = mlnx_tunnel_map_entry.tunnel_map_type;

    switch (tunnel_map_type) {
    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
        sai_status = mlnx_tunnel_map_entry_ecn_bind_set(tunnel_map_entry_idx, is_add);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error binding ecn tunnel map entry idx %d to tunnel\n",
                       tunnel_map_entry_idx);
            SX_LOG_EXIT();
            return sai_status;
        }
        break;

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
    case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
        for (ii = 0; ii < tunnel_cnt; ii++) {
            tunnel_idx = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_idx[ii];
            sx_tunnel_id_ipv4 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sx_tunnel_id_ipv4;

            sai_status = mlnx_sai_tunnel_map_entry_bind_vxlan_set(tunnel_map_entry_idx,
                                                                  tunnel_idx,
                                                                  sx_tunnel_id_ipv4,
                                                                  &sx_tunnel_map_entry,
                                                                  is_add);

            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error bind tunnel map entry idx %d with vxlan tunnel idx %d\n",
                           tunnel_map_entry_idx, tunnel_idx);
                SX_LOG_EXIT();
                return sai_status;
            }
        }
        break;

    default:
        SX_LOG_ERR("Unexpected tunnel map type: %d\n", tunnel_map_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_entry_vlan_vni_bridge_set(_In_ sai_object_id_t       sai_mapper_obj_id,
                                                                  _In_ tunnel_direction_type sai_tunnel_map_direction,
                                                                  _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                                  _In_ sx_tunnel_id_t        sx_tunnel_id,
                                                                  _In_ sx_access_cmd_t       cmd)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_tunnel_map_entry_t sx_tunnel_map_entry;
    sx_bridge_id_t        sx_bridge_id = 0;
    uint32_t              ii = 0;
    uint32_t              tunnel_map_idx = 0;
    uint32_t              tunnel_idx = 0;
    const bool            is_add = (SX_ACCESS_CMD_ADD == cmd);
    sai_tunnel_map_type_t tunnel_map_type;

    SX_LOG_ENTER();

    assert((SX_ACCESS_CMD_ADD == cmd) || (SX_ACCESS_CMD_DELETE == cmd));

    /* use .1Q bridge as default bridge */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_tunnel_1Qbridge_get(&sx_bridge_id))) {
        SX_LOG_ERR("fail to get sx bridge id\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(sai_mapper_obj_id, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    for (ii = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_head_idx;
         ii != MLNX_TUNNEL_MAP_ENTRY_INVALID;
         ii = g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].next_tunnel_map_entry_idx) {
        if (sai_mapper_obj_id != g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_id) {
            SX_LOG_ERR(
                "tunnel map oid is %" PRIx64 " but tunnel map entry is already bound to tunnel map oid %" PRIx64 "\n",
                sai_mapper_obj_id,
                g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_id);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        tunnel_map_type = g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_type;

        if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
            switch (tunnel_map_type) {
            case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
            case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
            case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
                break;

            case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
                continue;
                break;

            default:
                SX_LOG_ERR("sai tunnel map type for encap should be %d or %d or %d but getting %d\n",
                           SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI,
                           SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI,
                           SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI,
                           g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_type);
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
        } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
            switch (tunnel_map_type) {
            case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
            case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
            case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
                break;

            case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
                continue;
                break;

            default:
                SX_LOG_ERR("sai tunnel map type for decap should be %d or %d or %d but getting %d\n",
                           SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID,
                           SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF,
                           SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID,
                           g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii].tunnel_map_type);
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
        }

        if ((SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID != tunnel_map_type) &&
            (SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI != tunnel_map_type)) {
            sx_tunnel_map_entry.type = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sx_tunnel_attr.type;
            sai_status = mlnx_sai_fill_tunnel_map_entry(ii, &sx_tunnel_map_entry);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error filling tunnel map entry for tunnel map entry idx %d\n",
                           ii);
                SX_LOG_EXIT();
                return sai_status;
            }
        }

        sai_status = mlnx_sai_tunnel_map_entry_bind_vxlan_set(ii,
                                                              tunnel_idx,
                                                              sx_tunnel_id,
                                                              &sx_tunnel_map_entry,
                                                              is_add);

        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error bind tunnel map entry idx %d with vxlan tunnel idx %d\n",
                       ii, tunnel_idx);
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_tunnel_map_vlan_vni_bridge_set(_In_ sai_object_id_t       sai_mapper_obj_id,
                                                            _In_ tunnel_direction_type sai_tunnel_map_direction,
                                                            _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                            _In_ sx_tunnel_id_t        sx_tunnel_id,
                                                            _In_ sx_access_cmd_t       cmd)
{
    sai_status_t      sai_status = SAI_STATUS_FAILURE;
    uint32_t          sai_tunnel_mapper_idx = 0;
    mlnx_tunnel_map_t mlnx_tunnel_map;
    uint32_t          tunnel_idx = 0;

    SX_LOG_ENTER();

    assert((SX_ACCESS_CMD_ADD == cmd) || (SX_ACCESS_CMD_DELETE == cmd));

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_get_sai_tunnel_map_db_idx(sai_mapper_obj_id, &sai_tunnel_mapper_idx))) {
        SX_LOG_ERR("Error getting tunnel mapper db idx from tunnel mapper obj id %" PRIx64 "\n",
                   sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_ACCESS_CMD_ADD == cmd) {
        sai_status = mlnx_tunnel_per_map_array_add(tunnel_idx, sai_mapper_obj_id);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error adding tunnel %d to tunnel list of tunne map oid %" PRIx64 "\n",
                       tunnel_idx,
                       sai_mapper_obj_id);
            SX_LOG_EXIT();
            return sai_status;
        }
    } else if (SX_ACCESS_CMD_DELETE == cmd) {
        assert(0 < g_sai_tunnel_db_ptr->tunnel_map_db[sai_tunnel_mapper_idx].tunnel_cnt);
        sai_status = mlnx_tunnel_per_map_array_delete(tunnel_idx, sai_mapper_obj_id);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error deleting tunnel %d to tunnel list of tunne map oid %" PRIx64 "\n",
                       tunnel_idx,
                       sai_mapper_obj_id);
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_db_param_get(sai_mapper_obj_id, &mlnx_tunnel_map))) {
        SX_LOG_ERR("fail to get mlnx tunnel map for tunnel map obj id %" PRIx64 "\n", sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
        switch (mlnx_tunnel_map.tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
            if (NVE_8021D_TUNNEL == g_sai_db_ptr->nve_tunnel_type) {
                SX_LOG_ERR("802.1Q tunnel map cannot be applied with 802.1D tunnel map at the same time\n");
                return SAI_STATUS_FAILURE;
            }
            g_sai_db_ptr->nve_tunnel_type = NVE_8021Q_TUNNEL;
            break;

        case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
            if (NVE_8021Q_TUNNEL == g_sai_db_ptr->nve_tunnel_type) {
                SX_LOG_ERR("802.1Q tunnel map cannot be applied with 802.1D tunnel map at the same time\n");
                return SAI_STATUS_FAILURE;
            }
            g_sai_db_ptr->nve_tunnel_type = NVE_8021D_TUNNEL;
            break;

        case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
            SX_LOG_DBG("Tunnel map type is OECN to UECN for encap\n");
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
            break;

        case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
            SX_LOG_DBG("Tunnel map type is VR to VNI for encap\n");
            break;

        default:
            SX_LOG_ERR("sai tunnel map type for encap should be %d or %d or %d but getting %d\n",
                       SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI,
                       SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI,
                       SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI,
                       mlnx_tunnel_map.tunnel_map_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
        switch (mlnx_tunnel_map.tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
            if (NVE_8021D_TUNNEL == g_sai_db_ptr->nve_tunnel_type) {
                SX_LOG_ERR("802.1Q tunnel map cannot be applied with 802.1D tunnel map at the same time\n");
                return SAI_STATUS_FAILURE;
            }
            g_sai_db_ptr->nve_tunnel_type = NVE_8021Q_TUNNEL;
            break;

        case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
            if (NVE_8021Q_TUNNEL == g_sai_db_ptr->nve_tunnel_type) {
                SX_LOG_ERR("802.1Q tunnel map cannot be applied with 802.1D tunnel map at the same time\n");
                return SAI_STATUS_FAILURE;
            }
            g_sai_db_ptr->nve_tunnel_type = NVE_8021D_TUNNEL;
            break;

        case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
            SX_LOG_DBG("Tunnel map type is UECN OECN to OECN for decap\n");
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
            break;

        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
            SX_LOG_DBG("Tunnel map type is VNI to VR for decap\n");
            break;

        default:
            SX_LOG_ERR("sai tunnel map type for decap should be %d or %d or %d but getting %d\n",
                       SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID,
                       SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF,
                       SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID,
                       mlnx_tunnel_map.tunnel_map_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_tunnel_map_entry_vlan_vni_bridge_set(sai_mapper_obj_id,
                                                                    sai_tunnel_map_direction,
                                                                    sai_tunnel_obj_id,
                                                                    sx_tunnel_id,
                                                                    cmd))) {
        SX_LOG_ERR("Error getting vlan vni id from sai tunnel map obj %" PRIx64 "\n ", sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_sai_create_vxlan_tunnel_map_list(_In_ sai_object_id_t      *sai_tunnel_mapper_list,
                                                          _In_ uint32_t              sai_tunnel_mapper_cnt,
                                                          _In_ tunnel_direction_type sai_tunnel_map_direction,
                                                          _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                          _In_ sx_access_cmd_t       cmd)
{
    sai_object_id_t       sai_mapper_obj_id = SAI_NULL_OBJECT_ID;
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    uint32_t              tunnel_db_idx = 0;
    uint32_t              ii = 0;
    sx_tunnel_map_entry_t sx_tunnel_map_entry;
    sx_tunnel_id_t        sx_tunnel_id = 0;
    sai_object_type_t     sai_obj_type = SAI_OBJECT_TYPE_NULL;

    SX_LOG_ENTER();

    memset(&sx_tunnel_map_entry, 0, sizeof(sx_tunnel_map_entry_t));

    if (0 == sai_tunnel_mapper_cnt) {
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    sx_tunnel_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4;

    for (ii = 0; ii < sai_tunnel_mapper_cnt; ii++) {
        sai_mapper_obj_id = sai_tunnel_mapper_list[ii];

        sai_obj_type = sai_object_type_query(sai_mapper_obj_id);

        if (SAI_OBJECT_TYPE_TUNNEL_MAP == sai_obj_type) {
            if (SAI_STATUS_SUCCESS !=
                (sai_status = mlnx_sai_tunnel_map_vlan_vni_bridge_set(sai_mapper_obj_id,
                                                                      sai_tunnel_map_direction,
                                                                      sai_tunnel_obj_id,
                                                                      sx_tunnel_id,
                                                                      cmd))) {
                SX_LOG_ERR("Error getting vlan vni id from sai tunnel map obj %" PRIx64 "\n ", sai_mapper_obj_id);
                SX_LOG_EXIT();
                return sai_status;
            }
        } else {
            SX_LOG_ERR("Unsupported sai object type %s for tunnel map list\n", SAI_TYPE_STR(sai_obj_type));
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_fill_sx_vxlan_tunnel_data(_In_ sai_tunnel_type_t       sai_tunnel_type,
                                                       _In_ uint32_t                attr_count,
                                                       _In_ const sai_attribute_t  *attr_list,
                                                       _Out_ sx_tunnel_attribute_t *sx_tunnel_attribute,
                                                       _Out_ sx_tunnel_ttl_data_t  *sdk_encap_ttl_data_attrib,
                                                       _Out_ sx_tunnel_ttl_data_t  *sdk_decap_ttl_data_attrib,
                                                       _Out_ sx_tunnel_cos_data_t  *sdk_encap_cos_data,
                                                       _Out_ sx_tunnel_cos_data_t  *sdk_decap_cos_data,
                                                       _Out_ mlnx_tunnel_entry_t   *mlnx_tunnel_db_entry)
{
    sai_status_t                 sai_status;
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    bool                         has_encap_attr = false;
    bool                         has_decap_attr = false;
    sx_router_interface_t        sx_rif;
    sx_router_id_t               sdk_vrid;

    SX_LOG_ENTER();

    if (!sx_tunnel_attribute) {
        SX_LOG_ERR("NULL sx_tunnel_attribute\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (!attr_list) {
        SX_LOG_ERR("NULL attr_list\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memset(sx_tunnel_attribute, 0, sizeof(sx_tunnel_attribute_t));
    memset(mlnx_tunnel_db_entry, 0, sizeof(mlnx_tunnel_entry_t));

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, &attr, &attr_idx))) {
        SX_LOG_ERR("Overlay interface is not valid for vxlan tunnel\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, &attr, &attr_idx))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_rif_oid_to_sdk_rif_id(attr->oid, &sx_rif))) {
            SX_LOG_ERR("underlay interface %" PRIx64 " is not rif type\n", attr->oid);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_get_sx_vrid_from_sx_rif(sx_rif, &sdk_vrid))) {
            SX_LOG_ERR("mlnx_sai_get_sx_vrid_from_sx_rif failed\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        mlnx_tunnel_fill_ulay_domain_rif(sx_rif, 0, &sx_tunnel_attribute->attributes.vxlan.decap.underlay_rif, NULL,
                                         &sx_tunnel_attribute->attributes.vxlan.underlay_domain_type);
        mlnx_tunnel_fill_ulay_domain_rif(sx_rif, sdk_vrid, &sx_tunnel_attribute->attributes.vxlan.encap.underlay_rif,
                                         &sx_tunnel_attribute->attributes.vxlan.encap.underlay_vrid,
                                         &sx_tunnel_attribute->attributes.vxlan.underlay_domain_type);

        mlnx_tunnel_db_entry->sai_underlay_rif = attr->oid;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_PEER_MODE, &attr, &attr_idx))) {
        if (SAI_TUNNEL_PEER_MODE_P2MP != attr->s32) {
            SX_LOG_ERR("Only P2MP mode is supported for tunnel peer mode\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_SRC_IP, &attr, &attr_idx))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_translate_sai_ip_address_to_sdk(&attr->ipaddr,
                                                               &sx_tunnel_attribute->attributes.vxlan.encap.
                                                               underlay_sip))) {
            SX_LOG_ERR("Error setting src ip on creating tunnel table\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        has_encap_attr = true;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sdk_fill_tunnel_ttl_data(attr_count,
                                                    attr_list,
                                                    sai_tunnel_type,
                                                    sdk_encap_ttl_data_attrib,
                                                    sdk_decap_ttl_data_attrib,
                                                    &has_encap_attr,
                                                    &has_decap_attr))) {
        SX_LOG_ERR("Error fill sdk tunnel ttl data\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sdk_fill_tunnel_cos_data(attr_count,
                                                    attr_list,
                                                    sai_tunnel_type,
                                                    mlnx_tunnel_db_entry,
                                                    sdk_encap_cos_data,
                                                    sdk_decap_cos_data,
                                                    &has_encap_attr,
                                                    &has_decap_attr))) {
        SX_LOG_ERR("Error fill sdk tunnel cos data\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        SX_LOG_ERR("encap gre key valid is not valid for vxlan tunnel\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        SX_LOG_ERR("encap gre key is not valid for vxlan tunnel\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (has_encap_attr && !has_decap_attr) {
        sx_tunnel_attribute->direction = SX_TUNNEL_DIRECTION_ENCAP;
    } else if (!has_encap_attr && has_decap_attr) {
        sx_tunnel_attribute->direction = SX_TUNNEL_DIRECTION_DECAP;
    } else if (has_encap_attr && has_decap_attr) {
        sx_tunnel_attribute->direction = SX_TUNNEL_DIRECTION_SYMMETRIC;
    }

    sai_db_read_lock();

    sx_tunnel_attribute->attributes.vxlan.nve_log_port = g_sai_db_ptr->sx_nve_log_port;

    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* caller needs to guard this function with lock */
static sai_status_t mlnx_fill_tunnel_db(_In_ sai_object_id_t      sai_tunnel_obj_id,
                                        _In_ mlnx_tunnel_entry_t *mlnx_tunnel_db_entry)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_db_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_underlay_rif = mlnx_tunnel_db_entry->sai_underlay_rif;
    memcpy(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_encap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt * sizeof(sai_object_id_t));
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_cnt =
        mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_cnt =
        mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt;
    memcpy(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_decap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt * sizeof(sai_object_id_t));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by write lock */
static sai_status_t mlnx_create_sdk_tunnel(_In_ sai_object_id_t      sai_tunnel_obj_id,
                                           _In_ sai_ip_addr_family_t outer_ip_type)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_status_t                 sdk_status;
    uint32_t                    tunnel_db_idx = 0;
    sx_tunnel_attribute_t       sx_tunnel_attr;
    sx_tunnel_id_t              sx_tunnel_id_ipv4;
    sx_tunnel_id_t              sx_tunnel_id_ipv6;
    sai_tunnel_type_t           sai_tunnel_type;
    sx_router_interface_state_t rif_state;
    bool                        sdk_tunnel_map_created = false;
    bool                        sdk_tunnel_ipv4_created = false;
    bool                        sdk_tunnel_ipv6_created = false;
    sx_tunnel_map_entry_t       sx_tunnel_map_entry[MLNX_TUNNEL_MAP_MAX];
    sx_tunnel_ttl_data_t        sdk_encap_ttl_data_attrib;
    sx_tunnel_ttl_data_t        sdk_decap_ttl_data_attrib;
    sx_tunnel_cos_data_t        sdk_encap_cos_data;
    sx_tunnel_cos_data_t        sdk_decap_cos_data;
    sx_router_interface_t       sx_overlay_rif_ipv4;
    sx_router_interface_t       sx_overlay_rif_ipv6;
    sx_router_id_t              sx_vrid;
    sx_router_interface_param_t sx_ifc;
    sx_interface_attributes_t   sx_ifc_attr;
    sx_tunnel_type_e            sx_tunnel_type_ipv4;
    sx_tunnel_type_e            sx_tunnel_type_ipv6;
    uint32_t                    ii = 0;
    sai_object_id_t             sai_mapper_obj_id;
    sx_tunnel_hash_data_t       sx_tunnel_hash_data = {0};

    SX_LOG_ENTER();

    if ((SAI_IP_ADDR_FAMILY_IPV4 != outer_ip_type) &&
        (SAI_IP_ADDR_FAMILY_IPV6 != outer_ip_type)) {
        SX_LOG_ERR("Error: unknown IP version %d\n", outer_ip_type);
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        goto cleanup;
    }
    memcpy(&sx_tunnel_attr, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr,
           sizeof(sx_tunnel_attr));
    memcpy(&sdk_encap_ttl_data_attrib, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_encap_ttl_data_attrib,
           sizeof(sx_tunnel_ttl_data_t));
    memcpy(&sdk_decap_ttl_data_attrib, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_decap_ttl_data_attrib,
           sizeof(sx_tunnel_ttl_data_t));
    memcpy(&sdk_encap_cos_data,
           &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_encap_cos_data,
           sizeof(sx_tunnel_cos_data_t));
    memcpy(&sdk_decap_cos_data,
           &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_decap_cos_data,
           sizeof(sx_tunnel_cos_data_t));

    sai_tunnel_type = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_type;

    sai_status = mlnx_convert_sai_tunnel_type_to_sx_ipv4(sai_tunnel_type,
                                                         outer_ip_type,
                                                         &sx_tunnel_type_ipv4);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error converting sai tunnel type %d and SAI ip version %d to sx tunnel type\n",
                   sai_tunnel_type, outer_ip_type);
        goto cleanup;
    }

    sx_tunnel_attr.type = sx_tunnel_type_ipv4;
    /* prevent creating tunnel term table using the same SAI IP in IP IPv4 tunnel */
    if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv4_created) {
        SX_LOG_ERR("IPv4 tunnel already created\n");
        sai_status = SAI_STATUS_FAILURE;
        goto cleanup;
    }

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr.type = sx_tunnel_type_ipv4;

    if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_set(
                                  gh_sdk,
                                  SX_ACCESS_CMD_CREATE,
                                  &sx_tunnel_attr,
                                  &sx_tunnel_id_ipv4))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error creating sdk ipv4 tunnel, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        goto cleanup;
    }

    sdk_tunnel_ipv4_created = true;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv4_created = true;
    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4 = sx_tunnel_id_ipv4;

    if ((SX_TUNNEL_DIRECTION_DECAP == sx_tunnel_attr.direction) &&
        ((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
         (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type))) {
        sx_overlay_rif_ipv4 = sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif;

        sdk_status = sx_api_router_interface_get(gh_sdk, sx_overlay_rif_ipv4,
                                                 &sx_vrid, &sx_ifc, &sx_ifc_attr);
        if (SX_STATUS_SUCCESS != sdk_status) {
            SX_LOG_ERR("Error getting ipv4 overlay sdk rif %d: %s\n",
                       sx_overlay_rif_ipv4, SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }

        sdk_status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_ADD, sx_vrid,
                                                 &sx_ifc, &sx_ifc_attr, &sx_overlay_rif_ipv6);
        if (SX_STATUS_SUCCESS != sdk_status) {
            SX_LOG_ERR("Error setting ipv6 overlay sdk rif: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }

        sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif = sx_overlay_rif_ipv6;

        sai_status = mlnx_convert_sai_tunnel_type_to_sx_ipv6(sai_tunnel_type,
                                                             outer_ip_type,
                                                             &sx_tunnel_type_ipv6);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error converting sai tunnel type %d and SAI ip version %d to sx tunnel type\n",
                       sai_tunnel_type, outer_ip_type);
            goto cleanup;
        }
        sx_tunnel_attr.type = sx_tunnel_type_ipv6;

        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_set(
                                      gh_sdk,
                                      SX_ACCESS_CMD_CREATE,
                                      &sx_tunnel_attr,
                                      &sx_tunnel_id_ipv6))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error creating sdk ipv6 tunnel, sx status: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
        sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif = sx_overlay_rif_ipv4;
        sdk_tunnel_ipv6_created = true;

        if ((SX_TUNNEL_DIRECTION_ENCAP == sx_tunnel_attr.direction) ||
            (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_attr.direction)) {
            if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                         sx_tunnel_id_ipv6,
                                                                         &sdk_encap_cos_data))) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error setting sdk tunnel ipv6 encap cos, sx status: %s\n", SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }
        }

        if ((SX_TUNNEL_DIRECTION_DECAP == sx_tunnel_attr.direction) ||
            (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_attr.direction)) {
            if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                         sx_tunnel_id_ipv6,
                                                                         &sdk_decap_cos_data))) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error setting sdk tunnel ipv6 decap cos, sx status: %s\n", SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }
        }
    }

    if ((SX_TUNNEL_DIRECTION_ENCAP == sx_tunnel_attr.direction) ||
        (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_attr.direction)) {
        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                     sx_tunnel_id_ipv4,
                                                                     &sdk_encap_cos_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting sdk tunnel encap cos, sx status: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
        /* TTL setting is shared with all SDK tunnels of the same type (IP in IP or VXLAN,
         * regardless of IPv4 or IPv6),
         * thus only need to set on IPv4 tunnel */
        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_ttl_set(gh_sdk,
                                                                     sx_tunnel_id_ipv4,
                                                                     &sdk_encap_ttl_data_attrib))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting sdk tunnel encap ttl, sx status: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
    }

    if ((SX_TUNNEL_DIRECTION_DECAP == sx_tunnel_attr.direction) ||
        (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_attr.direction)) {
        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                     sx_tunnel_id_ipv4,
                                                                     &sdk_decap_cos_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting sdk tunnel decap cos, sx status: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
        /* Setting decap ttl is not allowed in current SDK
         * Current behavior is pipe model for decap in SDK */
        /*if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_ttl_set(gh_sdk,
         *                                                            sx_tunnel_id_ipv4,
         *                                                            &sdk_decap_ttl_data_attrib))) {
         *   sai_status = sdk_to_sai(sdk_status);
         *   SX_LOG_ERR("Error setting sdk tunnel decap ttl, sx status: %s\n", SX_STATUS_MSG(sdk_status));
         *   goto cleanup;
         *  }*/
    }

    if (SAI_TUNNEL_TYPE_VXLAN == sai_tunnel_type) {
        sdk_tunnel_map_created = true;
        sai_status = mlnx_sai_create_vxlan_tunnel_map_list(
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_id_array,
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_cnt,
            TUNNEL_ENCAP,
            sai_tunnel_obj_id,
            SX_ACCESS_CMD_ADD);
        if (SAI_STATUS_SUCCESS != sai_status) {
            SX_LOG_ERR("Failed to create sai vxlan encap tunnel map list\n");
            goto cleanup;
        }

        sai_status = mlnx_sai_create_vxlan_tunnel_map_list(
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_id_array,
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_cnt,
            TUNNEL_DECAP,
            sai_tunnel_obj_id,
            SX_ACCESS_CMD_ADD);
        if (SAI_STATUS_SUCCESS != sai_status) {
            SX_LOG_ERR("Failed to create sai vxlan decap tunnel map list\n");
            goto cleanup;
        }


        sdk_status = sx_api_fdb_port_learn_mode_set(gh_sdk,
                                                    g_sai_db_ptr->sx_nve_log_port,
                                                    SX_FDB_LEARN_MODE_DONT_LEARN);
        if (SX_STATUS_SUCCESS != sdk_status) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting nve log port learn mode to don't learn: %s\n",
                       SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
    } else {
        for (ii = 0; ii < g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_cnt; ii++) {
            sai_mapper_obj_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_id_array[ii];
            sai_status = mlnx_tunnel_per_map_array_add(tunnel_db_idx,
                                                       sai_mapper_obj_id);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error adding tunnel %d to tunnel list of tunne map oid %" PRIx64 "\n",
                           tunnel_db_idx,
                           sai_mapper_obj_id);
                SX_LOG_EXIT();
                return sai_status;
            }
        }

        for (ii = 0; ii < g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_cnt; ii++) {
            sai_mapper_obj_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_id_array[ii];
            sai_status = mlnx_tunnel_per_map_array_add(tunnel_db_idx, sai_mapper_obj_id);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error adding tunnel %d to tunnel list of tunne map oid %" PRIx64 "\n",
                           tunnel_db_idx,
                           sai_mapper_obj_id);
                SX_LOG_EXIT();
                return sai_status;
            }
        }
    }

    SX_LOG_NTC("created tunnel:0x%" PRIx64 "\n", sai_tunnel_obj_id);

    memset(&rif_state, 0, sizeof(sx_router_interface_state_t));

    rif_state.ipv4_enable = true;
    rif_state.ipv6_enable = true;

    if ((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
        (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type)) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status =
                 sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif,
                                                   &rif_state))) {
            SX_LOG_ERR("Failed to set overlay router interface %d state - %s.\n",
                       sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif,
                       SX_STATUS_MSG(sdk_status));
            sai_status = sdk_to_sai(sdk_status);
            goto cleanup;
        }
        if (mlnx_chip_is_spc2or3or4()) {
            if (SX_STATUS_SUCCESS !=
                (sdk_status =
                     sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif,
                                                       &rif_state))) {
                SX_LOG_ERR("Failed to set underlay router interface %d state - %s.\n",
                           sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif,
                           SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
        }
        if (sdk_tunnel_ipv6_created) {
            sdk_status = sx_api_router_interface_state_set(gh_sdk, sx_overlay_rif_ipv6,
                                                           &rif_state);
            if (SX_STATUS_SUCCESS != sdk_status) {
                SX_LOG_ERR("Failed to set ipv6 overlay router interface %d state - %s.\n",
                           sx_overlay_rif_ipv6, SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
        }
    } else if (SAI_TUNNEL_TYPE_VXLAN == sai_tunnel_type) {
        if (g_sai_db_ptr->vxlan_srcport_range_enabled) {
            sx_tunnel_hash_data.hash_field_type = SX_TUNNEL_HASH_FIELD_TYPE_UDP_SPORT_E;
            sx_tunnel_hash_data.hash_cmd = SX_TUNNEL_HASH_CMD_CALCULATE_E;
            sdk_status = sx_api_tunnel_hash_set(gh_sdk,
                                                sx_tunnel_id_ipv4,
                                                &sx_tunnel_hash_data);
            if (SX_STATUS_SUCCESS != sdk_status) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error setting src port hash for sdk vxlan tunnel %x, sx status: %s\n",
                           sx_tunnel_id_ipv4,
                           SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }
        }

        if (mlnx_chip_is_spc2or3or4()) {
            if (SX_STATUS_SUCCESS !=
                (sdk_status =
                     sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.vxlan.encap.underlay_rif,
                                                       &rif_state))) {
                SX_LOG_ERR("Failed to set underlay router interface %d state - %s.\n",
                           sx_tunnel_attr.attributes.vxlan.encap.underlay_rif,
                           SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
            if (SX_STATUS_SUCCESS !=
                (sdk_status =
                     sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.vxlan.decap.underlay_rif,
                                                       &rif_state))) {
                SX_LOG_ERR("Failed to set underlay router interface %d state - %s.\n",
                           sx_tunnel_attr.attributes.vxlan.decap.underlay_rif,
                           SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
        }
    }

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4 = sx_tunnel_id_ipv4;

    if ((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
        (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type)) {
        if (sdk_tunnel_ipv6_created) {
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv6_created = true;
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv6 = sx_tunnel_id_ipv6;
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_overlay_rif_ipv6 = sx_overlay_rif_ipv6;
        }
    }


    SX_LOG_EXIT();
    return sai_status;

cleanup:
    if (sdk_tunnel_map_created) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status =
                 sx_api_tunnel_map_set(gh_sdk,
                                       SX_ACCESS_CMD_DELETE_ALL,
                                       sx_tunnel_id_ipv4,
                                       sx_tunnel_map_entry,
                                       0))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error deleting all tunnel map associated with sx tunnel id %d, sx status %s\n",
                       sx_tunnel_id_ipv4, SX_STATUS_MSG(sdk_status));
        }
        if (SAI_TUNNEL_TYPE_VXLAN == sai_tunnel_type) {
            sai_status = mlnx_sai_tunnel_map_entry_clear_vxlan_bind_info(tunnel_db_idx);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error cleanup pair info for tunnel idx %d\n", tunnel_db_idx);
                goto cleanup;
            }
        }
    }

    if (sdk_tunnel_ipv6_created) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_set(gh_sdk,
                                            SX_ACCESS_CMD_DESTROY,
                                            &sx_tunnel_attr,
                                            &sx_tunnel_id_ipv6))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n", sx_tunnel_id_ipv6, SX_STATUS_MSG(
                           sdk_status));
        }

        sdk_status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_DELETE, sx_vrid,
                                                 &sx_ifc, &sx_ifc_attr, &sx_overlay_rif_ipv6);
        if (SX_STATUS_SUCCESS != sdk_status) {
            SX_LOG_ERR("Error setting ipv6 overlay sdk rif: %s\n", SX_STATUS_MSG(sdk_status));
            SX_LOG_EXIT();
            return sai_status;
        }

        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv6_created = false;
    }

    if (sdk_tunnel_ipv4_created) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_set(gh_sdk,
                                            SX_ACCESS_CMD_DESTROY,
                                            &sx_tunnel_attr,
                                            &sx_tunnel_id_ipv4))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n", sx_tunnel_id_ipv4, SX_STATUS_MSG(
                           sdk_status));
        }

        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv4_created = false;
    }
    SX_LOG_EXIT();
    return sai_status;
}

/* This function needs to be guarded by write lock */
static sai_status_t mlnx_remove_sdk_ipinip_tunnel(_In_ uint32_t tunnel_db_idx)
{
    sx_tunnel_attribute_t       sx_tunnel_attr;
    sx_router_interface_param_t sx_ifc;
    sx_interface_attributes_t   sx_ifc_attr;
    sx_router_interface_state_t rif_state;
    sx_router_interface_t       sx_overlay_rif_ipv6;
    sx_router_id_t              sx_vrid = 0;
    sx_status_t                 sdk_status = SX_STATUS_ERROR;
    sai_status_t                sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    memcpy(&sx_tunnel_attr, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr,
           sizeof(sx_tunnel_attr));

    sx_overlay_rif_ipv6 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_overlay_rif_ipv6;
    if (0 == g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].term_table_cnt) {
        memset(&rif_state, 0, sizeof(sx_router_interface_state_t));
        rif_state.ipv4_enable = false;
        rif_state.ipv6_enable = false;
        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv6_created) {
            sdk_status = sx_api_router_interface_get(gh_sdk, sx_overlay_rif_ipv6,
                                                     &sx_vrid, &sx_ifc, &sx_ifc_attr);
            if (SX_STATUS_SUCCESS != sdk_status) {
                SX_LOG_ERR("Error getting ipv6 overlay sdk rif %d: %s\n",
                           sx_overlay_rif_ipv6, SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }

            if (SX_STATUS_SUCCESS !=
                (sdk_status =
                     sx_api_router_interface_state_set(gh_sdk, sx_overlay_rif_ipv6,
                                                       &rif_state))) {
                SX_LOG_ERR("Failed to set overlay router interface state to down - %s.\n", SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
            if (SX_STATUS_SUCCESS !=
                (sdk_status = sx_api_tunnel_set(gh_sdk,
                                                SX_ACCESS_CMD_DESTROY,
                                                &sx_tunnel_attr,
                                                &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv6)))
            {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n",
                           g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv6,
                           SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }

            sdk_status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_DELETE, sx_vrid,
                                                     &sx_ifc, &sx_ifc_attr, &sx_overlay_rif_ipv6);
            if (SX_STATUS_SUCCESS != sdk_status) {
                SX_LOG_ERR("Error setting ipv6 overlay sdk rif: %s\n", SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }

            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv6_created = false;
        }

        if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv4_created) {
            if (SX_STATUS_SUCCESS !=
                (sdk_status =
                     sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif,
                                                       &rif_state))) {
                SX_LOG_ERR("Failed to set overlay router interface state to down - %s.\n", SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
            if (mlnx_chip_is_spc2or3or4()) {
                if (!is_underlay_rif_used_by_other_tunnels(tunnel_db_idx,
                                                           sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif)) {
                    if (SX_STATUS_SUCCESS !=
                        (sdk_status =
                             sx_api_router_interface_state_set(gh_sdk,
                                                               sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif,
                                                               &rif_state))) {
                        SX_LOG_ERR("Failed to set underlay router interface state to down - %s.\n",
                                   SX_STATUS_MSG(sdk_status));
                        sai_status = sdk_to_sai(sdk_status);
                        goto cleanup;
                    }
                }
            }
            if (SX_STATUS_SUCCESS !=
                (sdk_status = sx_api_tunnel_set(gh_sdk,
                                                SX_ACCESS_CMD_DESTROY,
                                                &sx_tunnel_attr,
                                                &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4)))
            {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n",
                           g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4,
                           SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv4_created = false;
        }
    }

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_parsing_depth_increase(void)
{
    sx_status_t    sx_status;
    const uint16_t parsing_depth = 128;

    if (g_sai_db_ptr->port_parsing_depth_set_for_tunnel) {
        return SAI_STATUS_SUCCESS;
    }

    sx_status = sx_api_port_parsing_depth_set(gh_sdk, parsing_depth);
    if (SX_ERR(sx_status)) {
        SX_LOG_WRN("Warning: not able to set port parsing depth: %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    g_sai_db_ptr->port_parsing_depth_set_for_tunnel = true;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_apply_vxlan_sport(_In_ uint32_t tunnel_db_idx)
{
    sai_status_t                      status;
    sai_tunnel_vxlan_udp_sport_mode_t sport_mode = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode;
    int32_t                           sport_base = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base;
    int8_t                            sport_mask = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask;

    if (sport_mode == SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_USER_DEFINED) {
        status = mlnx_vxlan_srcport_user_defined_set(tunnel_db_idx, sport_base, sport_mask, false);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Error setting VxLAN UDP SRC port mode USER_DEFINED for sdk vxlan tunnel %x\n",
                       g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4);
            return status;
        }
    } else {
        status = mlnx_vxlan_srcport_set_hash(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4,
                                             SAI_TUNNEL_HASH_CMD_CALCULATE, 0xC000);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Error setting VxLAN UDP SRC port mode EPHEMERAL for sdk vxlan tunnel %x\n",
                       g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4);
            return status;
        }
    }

    return status;
}

static sai_status_t mlnx_create_tunnel(_Out_ sai_object_id_t     * sai_tunnel_obj_id,
                                       _In_ sai_object_id_t        switch_id,
                                       _In_ uint32_t               attr_count,
                                       _In_ const sai_attribute_t* attr_list)
{
    SX_LOG_ENTER();
    sai_status_t                      sai_status;
    const sai_attribute_value_t      *attr;
    uint32_t                          attr_idx;
    char                              list_str[MAX_LIST_VALUE_STR_LEN] = { 0 };
    sx_status_t                       sdk_status;
    sx_tunnel_attribute_t             sx_tunnel_attr;
    sai_tunnel_type_t                 sai_tunnel_type;
    bool                              sai_db_created = false;
    mlnx_tunnel_entry_t               mlnx_tunnel_db_entry;
    uint32_t                          tunnel_db_idx = 0;
    mlnx_tunnel_entry_t               sai_tunnel_db_entry;
    sx_tunnel_ttl_data_t              sdk_encap_ttl_data_attrib;
    sx_tunnel_ttl_data_t              sdk_decap_ttl_data_attrib;
    sx_tunnel_cos_data_t              sdk_encap_cos_data;
    sx_tunnel_cos_data_t              sdk_decap_cos_data;
    sai_object_id_t                   underlay_rif = SAI_NULL_OBJECT_ID;
    sx_tunnel_general_params_t        sx_tunnel_general_params;
    sai_object_id_t                   tunnel_obj_id = SAI_NULL_OBJECT_ID;
    sai_tunnel_vxlan_udp_sport_mode_t sport_mode = SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL;
    bool                              sport_mode_configured = false;
    int32_t                           sport_base = -1;
    int8_t                            sport_mask = -1;
    sai_ip_address_t                  src_ip = {0};
    bool                              src_ip_provided = false;
    bool                              is_tunnel_created = false;

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_TUNNEL, tunnel_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_TUNNEL, MAX_LIST_VALUE_STR_LEN, list_str))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_NTC("Create tunnel attribs, %s\n", list_str);

    memset(&sx_tunnel_attr, 0, sizeof(sx_tunnel_attr));
    memset(&sdk_encap_ttl_data_attrib, 0, sizeof(sx_tunnel_ttl_data_t));
    memset(&sdk_decap_ttl_data_attrib, 0, sizeof(sx_tunnel_ttl_data_t));
    memset(&sdk_encap_cos_data, 0, sizeof(sx_tunnel_cos_data_t));
    memset(&sdk_decap_cos_data, 0, sizeof(sx_tunnel_cos_data_t));

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_TYPE, &attr, &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_tunnel_type = attr->s32;

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MODE, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        sport_mode = attr->s32;
        sport_mode_configured = true;
    }
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        sport_base = attr->u16;
    }
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT_MASK, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        if (attr->u8 > 8) {
            SX_LOG_ERR(
                "Wrong VxLAN UDP SRC port mask attribute value! Supported values are [0..8].\n");
            return SAI_STATUS_FAILURE;
        }
        sport_mask = attr->u8;
    }
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_SRC_IP, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        src_ip = attr->ipaddr;
        src_ip_provided = true;
    }

    if (g_sai_db_ptr->vxlan_srcport_range_enabled && sport_mode_configured) {
        SX_LOG_ERR("VxLAN tunnel attributes can not be configured when VxLAN SRC port range feature is enabled!\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_db_write_lock();

    /* saving user configured VxLAN UDP SRC port attributes */
    if (!g_sai_db_ptr->vxlan_srcport_range_enabled) {
        if (sport_mode_configured == true) {
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.is_configured = true;
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mode = sport_mode;
            if (sport_base == -1) {
                g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_base = 0;
            } else {
                g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_base = sport_base;
            }

            if (sport_mask == -1) {
                g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mask = 0;
            } else {
                g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mask = sport_mask;
            }
        } else {
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.is_configured = false;
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mode =
                SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL;
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_base = 0;
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mask = 0;
        }

        /* if user does not configure VxLAN UDP SRC port attributes - check if switch tunnel is created */
        if (g_sai_db_ptr->switch_tunnel[SAI_TUNNEL_TYPE_VXLAN].switch_tunnel_id != SAI_NULL_OBJECT_ID) {
            if (!sport_mode_configured) {
                sport_mode = g_sai_db_ptr->switch_tunnel[SAI_TUNNEL_TYPE_VXLAN].src_port_mode;
            }
            if (sport_mask == -1) {
                sport_mask = g_sai_db_ptr->switch_tunnel[SAI_TUNNEL_TYPE_VXLAN].src_port_mask;
            }
            if (sport_base == -1) {
                sport_base = g_sai_db_ptr->switch_tunnel[SAI_TUNNEL_TYPE_VXLAN].src_port_base;
            }
        } else {
            if (sport_mask == -1) {
                sport_mask = 0;
            }
            if (sport_base == -1) {
                sport_base = 0;
            }
        }

        if (sport_base & (0xFF >> (8 - sport_mask))) {
            SX_LOG_ERR("Wrong VxLAN UDP SRC port base and mask combination (0x%X:0x%x)\n", sport_base,
                       (0xFF >> (8 - sport_mask)));
            sai_db_unlock();
            goto cleanup;
        }
    }

    sai_status = mlnx_sai_tunnel_create_tunnel_object_id(sai_tunnel_type, &tunnel_obj_id);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error create tunnel object id\n");
        sai_db_unlock();
        goto cleanup;
    }
    sai_db_created = true;

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(tunnel_obj_id, &tunnel_db_idx))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", tunnel_obj_id);
        goto cleanup;
    }
    sai_db_unlock();

    switch (sai_tunnel_type) {
    case SAI_TUNNEL_TYPE_IPINIP:
    case SAI_TUNNEL_TYPE_IPINIP_GRE:
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       mlnx_sai_fill_sx_ipinip_p2p_tunnel_data(
                                           tunnel_db_idx,
                                           sai_tunnel_type,
                                           attr_count,
                                           attr_list,
                                           &sx_tunnel_attr,
                                           &sdk_encap_ttl_data_attrib,
                                           &sdk_decap_ttl_data_attrib,
                                           &sdk_encap_cos_data,
                                           &sdk_decap_cos_data,
                                           &underlay_rif,
                                           &mlnx_tunnel_db_entry))) {
            SX_LOG_ERR("Failed to fill sx ipinip p2p tunnel data\n");
            goto cleanup;
        }
        break;

    case SAI_TUNNEL_TYPE_VXLAN:
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       mlnx_sai_fill_sx_vxlan_tunnel_data(
                                           sai_tunnel_type,
                                           attr_count,
                                           attr_list,
                                           &sx_tunnel_attr,
                                           &sdk_encap_ttl_data_attrib,
                                           &sdk_decap_ttl_data_attrib,
                                           &sdk_encap_cos_data,
                                           &sdk_decap_cos_data,
                                           &mlnx_tunnel_db_entry))) {
            SX_LOG_ERR("Failed to fill sx vxlan tunnel data\n");
            goto cleanup;
        }
        break;

    case SAI_TUNNEL_TYPE_MPLS:
        SX_LOG_ERR("Tunnel MPLS type is not supported yet\n");
        sai_status = SAI_STATUS_NOT_IMPLEMENTED;
        goto cleanup;
        break;

    default:
        SX_LOG_EXIT();
        sai_status = SAI_STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    sai_status = mlnx_convert_sai_tunnel_type_to_sx_ipv4(sai_tunnel_type,
                                                         src_ip_provided ? src_ip.addr_family : SAI_IP_ADDR_FAMILY_IPV4,
                                                         &sx_tunnel_attr.type);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error converting sai tunnel type %d and SAI ip version 4 to sx tunnel type\n",
                   sai_tunnel_type);
        sai_status = SAI_STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    sai_db_write_lock();

    if (!g_sai_db_ptr->tunnel_module_initialized) {
        memset(&sx_tunnel_general_params, 0, sizeof(sx_tunnel_general_params_t));
        if (g_sai_db_ptr->vxlan_srcport_range_enabled) {
            sx_tunnel_general_params.nve.encap_sport = 0xFA;
        } else if (sport_mode == SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL) {
            sx_tunnel_general_params.nve.encap_sport = 0xC0;
        } else {
            sx_tunnel_general_params.nve.encap_sport = sport_base >> 8;
        }
        sdk_status = sx_api_tunnel_init_set(gh_sdk, &sx_tunnel_general_params);
        if (SX_STATUS_SUCCESS != sdk_status) {
            sai_db_unlock();
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Failed to init tunnel: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
        g_sai_db_ptr->tunnel_module_initialized = true;
    }

    /* IP in IP GRE with IPv6 header might be too long.
     * VXLAN IPv6 also need to be handled in the future. */
    if (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type) {
        mlnx_parsing_depth_increase();
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_tunnel_db_entry(tunnel_obj_id, &sai_tunnel_db_entry))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting sai tunnel db entry for sai tunnel obj id %" PRIx64 "\n", tunnel_obj_id);
        goto cleanup;
    }

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_type = sai_tunnel_type;

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_fill_tunnel_db(tunnel_obj_id, &mlnx_tunnel_db_entry))) {
        sai_db_unlock();
        SX_LOG_ERR("Failed to fill in tunnel db for sai tunnel obj id %" PRIx64 "\n", tunnel_obj_id);
        goto cleanup;
    }

    memcpy(&g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr, &sx_tunnel_attr,
           sizeof(sx_tunnel_attr));
    memcpy(&g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_encap_ttl_data_attrib, &sdk_encap_ttl_data_attrib,
           sizeof(sx_tunnel_ttl_data_t));
    memcpy(&g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_decap_ttl_data_attrib, &sdk_decap_ttl_data_attrib,
           sizeof(sx_tunnel_ttl_data_t));
    memcpy(&g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_encap_cos_data,
           &sdk_encap_cos_data,
           sizeof(sx_tunnel_cos_data_t));
    memcpy(&g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sdk_decap_cos_data,
           &sdk_decap_cos_data,
           sizeof(sx_tunnel_cos_data_t));

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_type = sai_tunnel_type;

    g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mode = sport_mode;

    if (sport_mode == SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_USER_DEFINED) {
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_mask = sport_mask;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].src_port_base = sport_base;
    }

    /* create ipinip decap or vxlan tunnel after tunnel term table is created */
    if ((((sai_tunnel_type == SAI_TUNNEL_TYPE_IPINIP) || (sai_tunnel_type == SAI_TUNNEL_TYPE_IPINIP_GRE)) &&
         (SX_TUNNEL_DIRECTION_DECAP != sx_tunnel_attr.direction)) ||
        ((sai_tunnel_type == SAI_TUNNEL_TYPE_VXLAN) && src_ip_provided)) {
        /* ipinip encap, or ipinip bidirectional, create only one ipv4 sdk tunnel */
        sai_status = mlnx_create_sdk_tunnel(tunnel_obj_id,
                                            src_ip_provided ? src_ip.addr_family : SAI_IP_ADDR_FAMILY_IPV4);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error creating sdk tunnel\n");
            sai_db_unlock();
            goto cleanup;
        }
        is_tunnel_created = true;
    }

    if ((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
        (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type)) {
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_underlay_rif = underlay_rif;
    }

    if ((SAI_TUNNEL_TYPE_VXLAN == sai_tunnel_type) && !g_sai_db_ptr->vxlan_srcport_range_enabled) {
        if (is_tunnel_created) {
            sai_status = mlnx_tunnel_apply_vxlan_sport(tunnel_db_idx);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Failed to apply VxLAN src port configuration.\n");
                sai_db_unlock();
                goto cleanup;
            }
        }
    }

    sai_db_unlock();

    *sai_tunnel_obj_id = tunnel_obj_id;
    SX_LOG_NTC("created tunnel:0x%" PRIx64 "\n", *sai_tunnel_obj_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;

cleanup:
    sai_db_write_lock();
    if (sai_db_created) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_object_to_type(tunnel_obj_id, SAI_OBJECT_TYPE_TUNNEL, &tunnel_db_idx,
                                              NULL))) {
            SX_LOG_ERR("Invalid sai tunnel obj id: 0x%" PRIx64 "\n", tunnel_obj_id);
        } else {
            if (tunnel_db_idx >= MAX_TUNNEL_DB_SIZE) {
                SX_LOG_ERR("tunnel db index: %d out of bounds:%d\n", tunnel_db_idx, MAX_TUNNEL_DB_SIZE);
                sai_status = SAI_STATUS_FAILURE;
            } else {
                memset(&g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx], 0, sizeof(mlnx_tunnel_entry_t));
            }
        }
    }
    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

static bool is_underlay_rif_used_by_other_tunnels(_In_ uint32_t tunnel_db_idx, _In_ sx_router_interface_t sx_rif)
{
    assert(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].is_used);


    for (uint32_t ii = 0; ii < MAX_TUNNEL_DB_SIZE; ii++) {
        if (ii == tunnel_db_idx) {
            continue;
        }
        if (!g_sai_tunnel_db_ptr->tunnel_entry_db[ii].is_used) {
            continue;
        }

        if ((SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE == g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.type) ||
            (SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4 == g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.type)) {
            if (g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif == sx_rif) {
                return true;
            }
        }

        if ((SX_TUNNEL_TYPE_NVE_VXLAN == g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.type) ||
            (SX_TUNNEL_TYPE_NVE_VXLAN_IPV6 == g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.type)) {
            if (g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.attributes.vxlan.encap.underlay_rif ==
                sx_rif) {
                return true;
            }

            if (g_sai_tunnel_db_ptr->tunnel_entry_db[ii].sx_tunnel_attr.attributes.vxlan.decap.underlay_rif ==
                sx_rif) {
                return true;
            }
        }
    }

    return false;
}

static sai_status_t mlnx_remove_tunnel(_In_ const sai_object_id_t sai_tunnel_obj_id)
{
    sai_status_t                sai_status = SAI_STATUS_FAILURE;
    sx_status_t                 sdk_status = SX_STATUS_ERROR;
    uint32_t                    tunnel_db_idx = 0;
    sx_tunnel_id_t              sx_tunnel_id = 0;
    sx_tunnel_attribute_t       sx_tunnel_attr;
    sx_router_interface_state_t rif_state;
    sx_tunnel_map_entry_t       sx_tunnel_map_entry;
    sai_object_id_t             sai_tunnel_map_id = 0;
    uint32_t                    ii = 0;
    uint32_t                    sai_tunnel_map_idx = 0;
    sx_router_interface_t       sx_overlay_rif_ipv6;
    bool                        ipv4_created = false;
    bool                        ipv6_created = false;
    sx_router_id_t              sx_vrid = 0;
    sx_router_interface_param_t sx_ifc;
    sx_interface_attributes_t   sx_ifc_attr;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_tunnel_obj_id, SAI_OBJECT_TYPE_TUNNEL, &tunnel_db_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai tunnel obj id: 0x%" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (tunnel_db_idx >= MAX_TUNNEL_DB_SIZE) {
        SX_LOG_ERR("tunnel db index: %d out of bounds:%d\n", tunnel_db_idx, MAX_TUNNEL_DB_SIZE);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_db_write_lock();

    if (!g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].is_used) {
        SX_LOG_ERR("Tunnel db ind %d cannot be removed because it is not used\n", tunnel_db_idx);
        sai_status = SAI_STATUS_FAILURE;
        goto cleanup;
    }

    sx_tunnel_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv4;
    sx_overlay_rif_ipv6 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_overlay_rif_ipv6;
    ipv4_created = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv4_created;
    ipv6_created = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv6_created;

    memset(&sx_tunnel_attr, 0, sizeof(sx_tunnel_attribute_t));

    memcpy(&sx_tunnel_attr, &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr,
           sizeof(sx_tunnel_attr));
    memset(&rif_state, 0, sizeof(sx_router_interface_state_t));

    rif_state.ipv4_enable = false;
    rif_state.ipv6_enable = false;

    if ((SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE == sx_tunnel_attr.type) ||
        (SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4 == sx_tunnel_attr.type)) {
        if (ipv4_created) {
            if (SX_STATUS_SUCCESS !=
                (sdk_status =
                     sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif,
                                                       &rif_state))) {
                SX_LOG_ERR("Failed to set overlay router interface state to down - %s.\n", SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
            if (mlnx_chip_is_spc2or3or4()) {
                if (!is_underlay_rif_used_by_other_tunnels(tunnel_db_idx,
                                                           sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif)) {
                    if (SX_STATUS_SUCCESS !=
                        (sdk_status =
                             sx_api_router_interface_state_set(gh_sdk,
                                                               sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif,
                                                               &rif_state))) {
                        SX_LOG_ERR("Failed to set underlay router interface state to down - %s.\n",
                                   SX_STATUS_MSG(sdk_status));
                        sai_status = sdk_to_sai(sdk_status);
                        goto cleanup;
                    }
                }
            }
        }
        if (ipv6_created) {
            if (SX_STATUS_SUCCESS !=
                (sdk_status =
                     sx_api_router_interface_state_set(gh_sdk, sx_overlay_rif_ipv6,
                                                       &rif_state))) {
                SX_LOG_ERR("Failed to set overlay router interface state to down - %s.\n", SX_STATUS_MSG(sdk_status));
                sai_status = sdk_to_sai(sdk_status);
                goto cleanup;
            }
        }
    } else if ((SX_TUNNEL_TYPE_NVE_VXLAN == sx_tunnel_attr.type) ||
               (SX_TUNNEL_TYPE_NVE_VXLAN_IPV6 == sx_tunnel_attr.type)) {
        if (g_sai_db_ptr->nve_tunnel_type != NVE_TUNNEL_UNKNOWN) {
            sdk_status = sx_api_fdb_port_learn_mode_set(gh_sdk,
                                                        g_sai_db_ptr->sx_nve_log_port,
                                                        SX_FDB_LEARN_MODE_AUTO_LEARN);
            if (SX_STATUS_SUCCESS != sdk_status) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error setting nve log port learn mode to auto learn: %s\n",
                           SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }
            g_sai_db_ptr->nve_tunnel_type = NVE_TUNNEL_UNKNOWN;
        }

        if (mlnx_chip_is_spc2or3or4()) {
            if (!is_underlay_rif_used_by_other_tunnels(tunnel_db_idx,
                                                       sx_tunnel_attr.attributes.vxlan.encap.underlay_rif)) {
                if (SX_STATUS_SUCCESS !=
                    (sdk_status =
                         sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.vxlan.encap.underlay_rif,
                                                           &rif_state))) {
                    SX_LOG_ERR("Failed to set underlay router interface state to down - %s.\n",
                               SX_STATUS_MSG(sdk_status));
                    sai_status = sdk_to_sai(sdk_status);
                    goto cleanup;
                }
            }

            if (!is_underlay_rif_used_by_other_tunnels(tunnel_db_idx,
                                                       sx_tunnel_attr.attributes.vxlan.decap.underlay_rif)) {
                if (SX_STATUS_SUCCESS !=
                    (sdk_status =
                         sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.vxlan.decap.underlay_rif,
                                                           &rif_state))) {
                    SX_LOG_ERR("Failed to set underlay router interface state to down - %s.\n",
                               SX_STATUS_MSG(sdk_status));
                    sai_status = sdk_to_sai(sdk_status);
                    goto cleanup;
                }
            }
        }
    }

    if ((0 != g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_cnt) ||
        (0 != g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_cnt)) {
        if ((SX_TUNNEL_TYPE_NVE_VXLAN == sx_tunnel_attr.type) ||
            (SX_TUNNEL_TYPE_NVE_VXLAN_IPV6 == sx_tunnel_attr.type)) {
            if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_map_set(
                                          gh_sdk,
                                          SX_ACCESS_CMD_DELETE_ALL,
                                          sx_tunnel_id,
                                          &sx_tunnel_map_entry,
                                          0))) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error deleting all tunnel map associated with sx tunnel id %d, sx status %s\n",
                           sx_tunnel_id, SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }
            sai_status = mlnx_sai_tunnel_map_entry_clear_vxlan_bind_info(tunnel_db_idx);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error cleanup pair info for tunnel idx %d\n", tunnel_db_idx);
                goto cleanup;
            }
        }

        for (ii = 0; ii < g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_cnt; ii++) {
            sai_tunnel_map_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_id_array[ii];
            if (SAI_STATUS_SUCCESS !=
                (sai_status =
                     mlnx_get_sai_tunnel_map_db_idx(sai_tunnel_map_id, &sai_tunnel_map_idx))) {
                SX_LOG_ERR("Error getting tunnel mapper db idx from tunnel mapper obj id %" PRIx64 "\n",
                           sai_tunnel_map_id);
                goto cleanup;
            }

            assert(0 < g_sai_tunnel_db_ptr->tunnel_map_db[sai_tunnel_map_idx].tunnel_cnt);
            sai_status = mlnx_tunnel_per_map_array_delete(tunnel_db_idx, sai_tunnel_map_id);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error deleting tunnel %d to tunnel list of tunne map oid %" PRIx64 "\n",
                           tunnel_db_idx,
                           sai_tunnel_map_id);
                goto cleanup;
            }
        }

        for (ii = 0; ii < g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_cnt; ii++) {
            sai_tunnel_map_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_id_array[ii];
            if (SAI_STATUS_SUCCESS !=
                (sai_status =
                     mlnx_get_sai_tunnel_map_db_idx(sai_tunnel_map_id, &sai_tunnel_map_idx))) {
                SX_LOG_ERR("Error getting tunnel mapper db idx from tunnel mapper obj id %" PRIx64 "\n",
                           sai_tunnel_map_id);
                goto cleanup;
            }

            assert(0 < g_sai_tunnel_db_ptr->tunnel_map_db[sai_tunnel_map_idx].tunnel_cnt);
            sai_status = mlnx_tunnel_per_map_array_delete(tunnel_db_idx, sai_tunnel_map_id);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error deleting tunnel %d to tunnel list of tunne map oid %" PRIx64 "\n",
                           tunnel_db_idx,
                           sai_tunnel_map_id);
                goto cleanup;
            }
        }

        memset(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_id_array, 0,
               sizeof(sai_object_id_t) * MLNX_TUNNEL_MAP_MAX);
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_encap_cnt = 0;
        memset(g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_id_array, 0,
               sizeof(sai_object_id_t) * MLNX_TUNNEL_MAP_MAX);
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_map_decap_cnt = 0;
    }

    if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.is_acl_created) {
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.is_configured = false;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mode =
            SAI_TUNNEL_VXLAN_UDP_SPORT_MODE_EPHEMERAL;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_base = 0;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].init_vxlan_sport_config.src_port_mask = 0;
        sai_status = mlnx_vxlan_udp_srcport_acl_remove(tunnel_db_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error deleting UDP VxLAN src port ACL %u \n",
                       g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].vxlan_acl.acl);
            goto cleanup;
        }
    }

    if (ipv4_created) {
        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_set(
                                      gh_sdk,
                                      SX_ACCESS_CMD_DESTROY,
                                      &sx_tunnel_attr,
                                      &sx_tunnel_id))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n", sx_tunnel_id, SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
    }

    if (ipv6_created) {
        sx_tunnel_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv6;
        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_set(
                                      gh_sdk,
                                      SX_ACCESS_CMD_DESTROY,
                                      &sx_tunnel_attr,
                                      &sx_tunnel_id))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n", sx_tunnel_id, SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
        sdk_status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_DELETE, sx_vrid,
                                                 &sx_ifc, &sx_ifc_attr, &sx_overlay_rif_ipv6);
        if (SX_STATUS_SUCCESS != sdk_status) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting ipv6 overlay sdk rif: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
    }
    memset(&g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx], 0, sizeof(mlnx_tunnel_entry_t));

    SX_LOG_NTC("removed tunnel:0x%" PRIx64 "\n", sai_tunnel_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_set_tunnel_attribute(_In_ const sai_object_id_t  sai_tunnel_obj_id,
                                              _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_key_to_str(sai_tunnel_obj_id, key_str);
    sai_status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_TUNNEL, tunnel_vendor_attribs, attr);

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_get_tunnel_attribute(_In_ const sai_object_id_t sai_tunnel_obj_id,
                                              _In_ uint32_t              attr_count,
                                              _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_key_to_str(sai_tunnel_obj_id, key_str);
    sai_status =
        sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_TUNNEL, tunnel_vendor_attribs, attr_count, attr_list);

    SX_LOG_EXIT();
    return sai_status;
}

/* caller of this function should use read lock to guard the call */
static sai_status_t mlnx_create_empty_tunneltable(_Out_ uint32_t *internal_tunneltable_idx)
{
    uint32_t idx = 0;

    SX_LOG_ENTER();

    assert(NULL != g_sai_tunnel_db_ptr);

    for (idx = 0; idx < MLNX_TUNNELTABLE_SIZE; idx++) {
        if (!g_sai_tunnel_db_ptr->tunneltable_db[idx].in_use) {
            *internal_tunneltable_idx = idx;
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR(
        "Not enough resources for sai tunnel table entry, at most %d sai tunnel table entrys can be created\n",
        MLNX_TUNNELTABLE_SIZE);

    SX_LOG_EXIT();
    return SAI_STATUS_INSUFFICIENT_RESOURCES;
}

static sai_status_t mlnx_get_tunnel_term_table_entry_attribute_on_create(
    _In_ uint32_t                       attr_count,
    _In_ const sai_attribute_t         *attr_list,
    _Out_ const sai_attribute_value_t **tunneltable_vr_id,
    _Out_ const sai_attribute_value_t **tunneltable_type,
    _Out_ const sai_attribute_value_t **tunneltable_dst_ip,
    _Out_ const sai_attribute_value_t **tunneltable_src_ip,
    _Out_ const sai_attribute_value_t **tunneltable_tunnel_type,
    _Out_ const sai_attribute_value_t **tunneltable_tunnel_id)
{
    char         list_str[MAX_LIST_VALUE_STR_LEN];
    uint32_t     idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                                    tunnel_term_table_entry_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Tunnel table: metadata check failed\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_attr_list_to_str(attr_count,
                         attr_list,
                         SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                         MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create tunnel table attributes: %s\n", list_str);

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID, tunneltable_vr_id,
                                     &idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE, tunneltable_type,
                                     &idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP,
                                     tunneltable_dst_ip,
                                     &idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP,
                                     tunneltable_src_ip,
                                     &idx);
    if ((SAI_STATUS_SUCCESS != sai_status) && (SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P == (*tunneltable_type)->s32)) {
        SX_LOG_ERR("Tunnel table src ip is missing on creating P2P tunnel table entry\n");
        SX_LOG_EXIT();
        return sai_status;
    } else if ((SAI_STATUS_SUCCESS == sai_status) &&
               (SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P != (*tunneltable_type)->s32)) {
        SX_LOG_ERR("Tunnel table src ip should not exist on creating non-P2P tunnel table entry\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE,
                                     tunneltable_tunnel_type,
                                     &idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID,
                                     tunneltable_tunnel_id,
                                     &idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
/* caller needs to make sure all the passed in attribute value pointer are not null */
static sai_status_t mlnx_set_tunnel_table_param(_In_ const sai_attribute_value_t   *tunneltable_vr_id,
                                                _In_ const sai_attribute_value_t   *tunneltable_type,
                                                _In_ const sai_attribute_value_t   *tunneltable_dst_ip,
                                                _In_ const sai_attribute_value_t   *tunneltable_src_ip,
                                                _In_ const sai_attribute_value_t   *tunneltable_tunnel_type,
                                                _In_ const sai_attribute_value_t   *tunneltable_tunnel_id,
                                                _Out_ sx_tunnel_decap_entry_key_t  *sdk_tunnel_decap_key,
                                                _Out_ sx_tunnel_decap_entry_data_t *sdk_tunnel_decap_data)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     sdk_vr_id = 0;

    SX_LOG_ENTER();

    assert(NULL != tunneltable_vr_id);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(tunneltable_vr_id->oid, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &sdk_vr_id, NULL))) {
        SX_LOG_ERR("Invalid sai virtual router id %" PRIx64 "\n", tunneltable_vr_id->oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    sdk_tunnel_decap_key->underlay_vrid = (sx_router_id_t)sdk_vr_id;

    assert(NULL != tunneltable_type);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_convert_sai_tunneltable_type_to_sx(tunneltable_type->s32,
                                                              &sdk_tunnel_decap_key->type))) {
        SX_LOG_ERR("Error converting sai tunnel table entry type %d to sdk tunnel table type\n",
                   tunneltable_type->s32);
        SX_LOG_EXIT();
        return sai_status;
    }

    assert(NULL != tunneltable_dst_ip);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_translate_sai_ip_address_to_sdk(&tunneltable_dst_ip->ipaddr,
                                                           &sdk_tunnel_decap_key->underlay_dip))) {
        SX_LOG_ERR("Error setting dst ip on creating tunnel table\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P == tunneltable_type->s32) {
        assert(NULL != tunneltable_src_ip);
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_translate_sai_ip_address_to_sdk(&tunneltable_src_ip->ipaddr,
                                                               &sdk_tunnel_decap_key->underlay_sip))) {
            SX_LOG_ERR("Error setting src ip on creating tunnel table\n");
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    assert(NULL != tunneltable_tunnel_type);

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_convert_sai_tunnel_type_to_sx_ipv4(tunneltable_tunnel_type->s32,
                                                     tunneltable_dst_ip->ipaddr.addr_family,
                                                     &sdk_tunnel_decap_key->tunnel_type))) {
        SX_LOG_ERR("Error converting sai tunnel type %d to sdk tunnel type\n", tunneltable_tunnel_type->s32);
        SX_LOG_EXIT();
        return sai_status;
    }

    assert(NULL != tunneltable_tunnel_id);

    sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(tunneltable_tunnel_id->oid, &sdk_tunnel_decap_data->tunnel_id);

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error converting sai tunnel id %" PRIx64 " to sx tunnel id\n", tunneltable_tunnel_id->oid);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sdk_tunnel_decap_data->action = SX_ROUTER_ACTION_FORWARD;
    sdk_tunnel_decap_data->counter_id = SX_FLOW_COUNTER_ID_INVALID;
    /* sdk_tunnel_decap_data->trap_attr is ignored when action is set to forward */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_tunnel_term_table_entry(_Out_ sai_object_id_t      *sai_tunnel_term_table_entry_obj_id,
                                                        _In_ sai_object_id_t        switch_id,
                                                        _In_ uint32_t               attr_count,
                                                        _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *tunneltable_vr_id = NULL, *tunneltable_type = NULL, *tunneltable_dst_ip = NULL,
                                *tunneltable_src_ip = NULL;
    const sai_attribute_value_t *tunneltable_tunnel_type = NULL, *tunneltable_tunnel_id = NULL;
    uint32_t                     internal_tunneltable_idx = 0;
    sx_tunnel_decap_entry_key_t  sdk_tunnel_decap_key;
    sx_tunnel_decap_entry_data_t sdk_tunnel_decap_data;

    memset(&sdk_tunnel_decap_key, 0, sizeof(sx_tunnel_decap_entry_key_t));
    memset(&sdk_tunnel_decap_data, 0, sizeof(sx_tunnel_decap_entry_data_t));
    sai_status_t     sai_status = SAI_STATUS_FAILURE;
    sx_status_t      sdk_status = SX_STATUS_ERROR;
    bool             cleanup_sdk = false;
    bool             cleanup_sdk_ipv6 = false;
    bool             cleanup_db = false;
    uint32_t         tunnel_db_idx = 0;
    bool             is_ipinip_decap = false;
    bool             tunnel_lazy_created = false;
    sx_tunnel_id_t   sx_tunnel_id_ipv4;
    sx_tunnel_id_t   sx_tunnel_id_ipv6;
    sx_tunnel_type_e sx_tunnel_type_ipv4;
    sx_tunnel_type_e sx_tunnel_type_ipv6;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_tunnel_term_table_entry_attribute_on_create(attr_count, attr_list,
                                                                           &tunneltable_vr_id, &tunneltable_type,
                                                                           &tunneltable_dst_ip, &tunneltable_src_ip,
                                                                           &tunneltable_tunnel_type,
                                                                           &tunneltable_tunnel_id))) {
        SX_LOG_ERR("Failed to get sai tunnel term table entry attribute on create\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();
    sai_status = mlnx_get_sai_tunnel_db_idx(tunneltable_tunnel_id->oid, &tunnel_db_idx);
    is_ipinip_decap =
        (SX_TUNNEL_DIRECTION_DECAP == g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr.direction) &&
        ((SAI_TUNNEL_TYPE_IPINIP == tunneltable_tunnel_type->s32) ||
         (SAI_TUNNEL_TYPE_IPINIP_GRE == tunneltable_tunnel_type->s32));
    /* create ipinip decap tunnel after tunnel term table is created */
    if (is_ipinip_decap ||
        !g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].ipv4_created) {
        /* ipinip encap, or ipinip bidirection, or vxlan, create only one ipv4 sdk tunnel */
        if (0 == g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].term_table_cnt) {
            if (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_type == SAI_TUNNEL_TYPE_VXLAN) {
                g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_attr.attributes.vxlan.encap.underlay_sip.
                version =
                    tunneltable_dst_ip->ipaddr.addr_family ==
                    SAI_IP_ADDR_FAMILY_IPV4 ? SX_IP_VERSION_IPV4 : SX_IP_VERSION_IPV6;
            }
            sai_status = mlnx_create_sdk_tunnel(tunneltable_tunnel_id->oid, tunneltable_dst_ip->ipaddr.addr_family);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Error creating sdk tunnel\n");
                sai_db_unlock();
                SX_LOG_EXIT();
                return sai_status;
            }
        }
        tunnel_lazy_created = true;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].term_table_cnt++;
    }

    if (tunnel_lazy_created && (SAI_TUNNEL_TYPE_VXLAN == tunneltable_tunnel_type->s32) &&
        !g_sai_db_ptr->vxlan_srcport_range_enabled) {
        sai_status = mlnx_tunnel_apply_vxlan_sport(tunnel_db_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to apply VxLAN srcport configuration.\n");
            goto cleanup;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_set_tunnel_table_param(tunneltable_vr_id, tunneltable_type, tunneltable_dst_ip, tunneltable_src_ip,
                                         tunneltable_tunnel_type, tunneltable_tunnel_id,
                                         &sdk_tunnel_decap_key, &sdk_tunnel_decap_data))) {
        SX_LOG_ERR("Failed to set tunnel table param for internal tunnel table idx %d\n", internal_tunneltable_idx);
        goto cleanup;
    }

    if (SX_STATUS_SUCCESS !=
        (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_CREATE,
                                                    &sdk_tunnel_decap_key,
                                                    &sdk_tunnel_decap_data))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error setting tunnel table entry on create, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        goto cleanup;
    }
    sx_tunnel_type_ipv4 = sdk_tunnel_decap_key.tunnel_type;
    sx_tunnel_id_ipv4 = sdk_tunnel_decap_data.tunnel_id;
    cleanup_sdk = true;

    if (is_ipinip_decap) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_convert_sx_tunnel_type_ipv4_to_ipv6(sx_tunnel_type_ipv4,
                                                          &sx_tunnel_type_ipv6))) {
            SX_LOG_ERR("Error converting sx tunnel type ipv4 %d to sdk tunnel type ipv6\n", sx_tunnel_type_ipv4);
            goto cleanup;
        }

        sdk_tunnel_decap_key.tunnel_type = sx_tunnel_type_ipv6;
        sx_tunnel_id_ipv6 = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv6;
        sdk_tunnel_decap_data.tunnel_id = sx_tunnel_id_ipv6;
        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_CREATE,
                                                        &sdk_tunnel_decap_key,
                                                        &sdk_tunnel_decap_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting tunnel table entry on create, sx status: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }
        cleanup_sdk_ipv6 = true;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_empty_tunneltable(&internal_tunneltable_idx))) {
        SX_LOG_ERR("Failed to create empty tunnel table entry\n");
        cleanup_sdk = true;
        goto cleanup;
    }

    SX_LOG_DBG("Created internal tunnel table entry idx: %d\n", internal_tunneltable_idx);

    memset(&g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx], 0, sizeof(mlnx_tunneltable_t));

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, internal_tunneltable_idx, NULL,
                                sai_tunnel_term_table_entry_obj_id))) {
        SX_LOG_ERR("Error creating sai tunnel table entry id from internal tunnel table entry id %d\n",
                   internal_tunneltable_idx);
        cleanup_db = true;
        cleanup_sdk = true;
        goto cleanup;
    }

    if (tunnel_lazy_created) {
        g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx].tunnel_db_idx = tunnel_db_idx;
        g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx].tunnel_lazy_created = true;
    }

    g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx].in_use = true;
    sdk_tunnel_decap_key.tunnel_type = sx_tunnel_type_ipv4;
    memcpy(&g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx].sdk_tunnel_decap_key_ipv4,
           &sdk_tunnel_decap_key,
           sizeof(sx_tunnel_decap_entry_key_t));

    SX_LOG_NTC("Created SAI tunnel table entry obj id: %" PRIx64 "\n", *sai_tunnel_term_table_entry_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;

cleanup:
    if (cleanup_db) {
        memset(&g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx], 0,
               sizeof(mlnx_tunneltable_t));
    }

    if (cleanup_sdk) {
        sdk_tunnel_decap_key.tunnel_type = sx_tunnel_type_ipv4;
        sdk_tunnel_decap_data.tunnel_id = sx_tunnel_id_ipv4;
        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_DESTROY,
                                                        &sdk_tunnel_decap_key,
                                                        &sdk_tunnel_decap_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting tunnel table entry on create, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        }
    }
    if (cleanup_sdk_ipv6) {
        sdk_tunnel_decap_key.tunnel_type = sx_tunnel_type_ipv6;
        sdk_tunnel_decap_data.tunnel_id = sx_tunnel_id_ipv6;
        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_DESTROY,
                                                        &sdk_tunnel_decap_key,
                                                        &sdk_tunnel_decap_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting tunnel table entry on create, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        }
    }

    if (tunnel_lazy_created) {
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].term_table_cnt--;
        sai_status = mlnx_remove_sdk_ipinip_tunnel(tunnel_db_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error removing sdk ipinip tunnel %d\n", tunnel_db_idx);
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

static sai_status_t mlnx_remove_tunnel_term_table_entry(_In_ const sai_object_id_t sai_tunnel_term_table_entry_obj_id)
{
    sai_status_t                 sai_status = SAI_STATUS_FAILURE;
    sx_status_t                  sdk_status = SX_STATUS_ERROR;
    uint32_t                     internal_tunneltable_idx = 0;
    sx_tunnel_decap_entry_key_t  sdk_tunnel_decap_key;
    sx_tunnel_decap_entry_data_t sdk_tunnel_decap_data;
    uint32_t                     tunnel_db_idx = 0;
    sx_tunnel_type_e             sx_tunnel_type_ipv4;
    sx_tunnel_type_e             sx_tunnel_type_ipv6;

    memset(&sdk_tunnel_decap_data, 0, sizeof(sx_tunnel_decap_entry_data_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_tunnel_term_table_entry_obj_id, SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                                 &internal_tunneltable_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai tunnel table entry obj id: %" PRIx64 "\n", sai_tunnel_term_table_entry_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    sai_status = mlnx_tunnel_term_table_entry_sdk_param_get(sai_tunnel_term_table_entry_obj_id, &sdk_tunnel_decap_key);

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n",
                   sai_tunnel_term_table_entry_obj_id);
        goto cleanup;
    }

    sx_tunnel_type_ipv4 = sdk_tunnel_decap_key.tunnel_type;

    if (SX_STATUS_SUCCESS !=
        (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_DESTROY,
                                                    &sdk_tunnel_decap_key,
                                                    &sdk_tunnel_decap_data))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error setting tunnel table entry on removal, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        goto cleanup;
    }

    if (g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx].tunnel_lazy_created &&
        (g_sai_tunnel_db_ptr->tunnel_entry_db[g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx].
                                              tunnel_db_idx].sai_tunnel_type != SAI_TUNNEL_TYPE_VXLAN)) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_convert_sx_tunnel_type_ipv4_to_ipv6(sx_tunnel_type_ipv4,
                                                          &sx_tunnel_type_ipv6))) {
            SX_LOG_ERR("Error converting sx tunnel type ipv4 %d to sdk tunnel type ipv6\n", sx_tunnel_type_ipv4);
            goto cleanup;
        }

        sdk_tunnel_decap_key.tunnel_type = sx_tunnel_type_ipv6;
        sdk_tunnel_decap_data.tunnel_id = g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sx_tunnel_id_ipv6;

        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_DESTROY,
                                                        &sdk_tunnel_decap_key,
                                                        &sdk_tunnel_decap_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting tunnel table entry ipv6 on removal: sx status: %s\n", SX_STATUS_MSG(sdk_status));
            goto cleanup;
        }

        tunnel_db_idx = g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx].tunnel_db_idx;
        g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].term_table_cnt--;

        sai_status = mlnx_remove_sdk_ipinip_tunnel(tunnel_db_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error removing sdk ipinip tunnel %d\n", tunnel_db_idx);
            goto cleanup;
        }
    }

    memset(&g_sai_tunnel_db_ptr->tunneltable_db[internal_tunneltable_idx], 0,
           sizeof(mlnx_tunneltable_t));

    SX_LOG_NTC("Removed SAI tunnel table entry obj id %" PRIx64 "\n", sai_tunnel_term_table_entry_obj_id);
    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_set_tunnel_map_attribute(_In_ const sai_object_id_t  sai_tunnel_map_obj_id,
                                                  _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_map_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_map_key_to_str(sai_tunnel_map_obj_id, key_str);

    sai_status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_TUNNEL_MAP, tunnel_map_vendor_attribs, attr);

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_get_tunnel_map_attribute(_In_ const sai_object_id_t sai_tunnel_map_obj_id,
                                                  _In_ uint32_t              attr_count,
                                                  _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_map_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_map_key_to_str(sai_tunnel_map_obj_id, key_str);

    sai_status =
        sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_TUNNEL_MAP, tunnel_map_vendor_attribs, attr_count,
                           attr_list);

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_set_tunnel_term_table_entry_attribute(
    _In_ const sai_object_id_t  sai_tunnel_term_table_entry_obj_id,
    _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_term_table_entry_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_term_table_entry_key_to_str(sai_tunnel_term_table_entry_obj_id, key_str);

    sai_status = sai_set_attribute(&key,
                                   key_str,
                                   SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                                   tunnel_term_table_entry_vendor_attribs,
                                   attr);

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_get_tunnel_term_table_entry_attribute(
    _In_ const sai_object_id_t sai_tunnel_term_table_entry_obj_id,
    _In_ uint32_t              attr_count,
    _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_term_table_entry_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_term_table_entry_key_to_str(sai_tunnel_term_table_entry_obj_id, key_str);

    sai_status = sai_get_attributes(&key,
                                    key_str,
                                    SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                                    tunnel_term_table_entry_vendor_attribs,
                                    attr_count,
                                    attr_list);

    SX_LOG_EXIT();
    return sai_status;
}

/* caller of this function should use read lock to guard the call */
static sai_status_t mlnx_create_empty_tunnel_map_entry(_Out_ uint32_t *tunnel_map_entry_idx)
{
    uint32_t     idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    for (idx = MLNX_TUNNEL_MAP_ENTRY_MIN; idx < MLNX_TUNNEL_MAP_ENTRY_MAX; idx++) {
        if (!g_sai_tunnel_db_ptr->tunnel_map_entry_db[idx].in_use) {
            *tunnel_map_entry_idx = idx;
            sai_status = SAI_STATUS_SUCCESS;
            goto cleanup;
        }
    }

    SX_LOG_ERR(
        "Not enough resources for sai tunnel map entry, at most %d sai tunnel map entry objs can be created\n",
        MLNX_TUNNEL_MAP_ENTRY_MAX);
    sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;

cleanup:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_init_tunnel_map_entry_param(_In_ uint32_t                  attr_count,
                                                     _In_ const sai_attribute_t    *attr_list,
                                                     _Out_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry)
{
    const sai_attribute_value_t *tunnel_map_type = NULL, *tunnel_map = NULL;
    const sai_attribute_value_t *oecn_key = NULL, *oecn_value = NULL;
    const sai_attribute_value_t *uecn_key = NULL, *uecn_value = NULL;
    const sai_attribute_value_t *vlan_id_key = NULL, *vlan_id_value = NULL;
    const sai_attribute_value_t *vni_id_key = NULL, *vni_id_value = NULL;
    const sai_attribute_value_t *bridge_id_key = NULL, *bridge_id_value = NULL;
    const sai_attribute_value_t *vr_id_key = NULL, *vr_id_value = NULL;
    uint32_t                     attr_idx = 0;
    uint32_t                     tunnel_map_idx = 0;
    sai_status_t                 sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE,
                                     &tunnel_map_type,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    mlnx_tunnel_map_entry->tunnel_map_type = tunnel_map_type->s32;

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY,
                                     &oecn_key, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->oecn_key = oecn_key->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE,
                                     &oecn_value, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->oecn_value = oecn_value->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY,
                                     &uecn_key, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->uecn_key = uecn_key->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE,
                                     &uecn_value, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->uecn_value = uecn_value->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY,
                                     &vlan_id_key, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vlan_id_key = vlan_id_key->u16;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE,
                                     &vlan_id_value, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vlan_id_value = vlan_id_value->u16;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY,
                                     &vni_id_key, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vni_id_key = vni_id_key->u32;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE,
                                     &vni_id_value, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vni_id_value = vni_id_value->u32;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY,
                                     &bridge_id_key, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->bridge_id_key = bridge_id_key->oid;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE,
                                     &bridge_id_value, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->bridge_id_value = bridge_id_value->oid;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY,
                                     &vr_id_key, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vr_id_key = vr_id_key->oid;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE,
                                     &vr_id_value, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vr_id_value = vr_id_value->oid;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP,
                                     &tunnel_map,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS ==
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(tunnel_map->oid, &tunnel_map_idx))) {
        if ((sai_tunnel_map_type_t)(tunnel_map_type->s32) !=
            g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_type) {
            sai_db_unlock();
            SX_LOG_ERR("Tunnel map oid %" PRIx64 " Claimed tunnel map type is %d but actual tunnel map type is %d\n",
                       tunnel_map->oid,
                       tunnel_map_type->s32,
                       g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_type);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        mlnx_tunnel_map_entry->tunnel_map_id = tunnel_map->oid;
    } else {
        sai_db_unlock();
        SX_LOG_ERR("Error getting tunnel map idx from SAI tunnel map oid %" PRIx64 "\n", tunnel_map->oid);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }

    sai_db_unlock();

    mlnx_tunnel_map_entry->in_use = true;

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/* Caller needs to guard this function with lock */
static sai_status_t mlnx_tunnel_per_map_array_add(_In_ uint32_t tunnel_idx, _In_ sai_object_id_t tunnel_map_oid)
{
    uint32_t     tunnel_map_idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_cnt = 0;
    uint32_t     ii = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(tunnel_map_oid, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   tunnel_map_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    tunnel_cnt = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt;

    if (MAX_TUNNEL <= tunnel_cnt) {
        SX_LOG_ERR("This tunnel map is already bound to %d tunnels, it can be bound to at most %d tunnels\n",
                   tunnel_cnt,
                   MAX_TUNNEL);
        SX_LOG_EXIT();
        return sai_status;
    }

    for (ii = 0; ii < tunnel_cnt; ii++) {
        if (tunnel_idx == g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_idx[ii]) {
            SX_LOG_ERR("This tunnel map idx %d is already bound to tunnel %d\n",
                       tunnel_map_idx, tunnel_idx);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_idx[tunnel_cnt] = tunnel_idx;
    g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt++;

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/* Caller needs to guard this function with lock */
static sai_status_t mlnx_tunnel_per_map_array_delete(_In_ uint32_t tunnel_idx, _In_ sai_object_id_t tunnel_map_oid)
{
    uint32_t     tunnel_map_idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_cnt = 0;
    uint32_t     ii = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(tunnel_map_oid, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   tunnel_map_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    tunnel_cnt = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt;
    for (ii = 0; ii < tunnel_cnt; ii++) {
        if (tunnel_idx == g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_idx[ii]) {
            g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_cnt--;
            tunnel_cnt--;
            g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_idx[ii] =
                g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_idx[tunnel_cnt];
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Not able to find tunnel idx %d from bound tunnel list of tunnel map obj id %" PRIx64 "\n",
               tunnel_idx, tunnel_map_oid);

    SX_LOG_EXIT();

    return SAI_STATUS_FAILURE;
}

/* Caller needs to guard this function with lock */
static sai_status_t mlnx_tunnel_map_entry_list_add(_In_ mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry,
                                                   _In_ uint32_t                tunnel_map_entry_idx)
{
    uint32_t     tunnel_map_idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_entry_tail_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(mlnx_tunnel_map_entry.tunnel_map_id, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   mlnx_tunnel_map_entry.tunnel_map_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    tunnel_map_entry_tail_idx = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_tail_idx;

    if (MLNX_TUNNEL_MAP_ENTRY_INVALID ==
        g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_head_idx) {
        assert(MLNX_TUNNEL_MAP_ENTRY_INVALID == tunnel_map_entry_tail_idx);
        g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_head_idx = tunnel_map_entry_idx;
    } else {
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_tail_idx].next_tunnel_map_entry_idx =
            tunnel_map_entry_idx;
    }

    g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].prev_tunnel_map_entry_idx =
        tunnel_map_entry_tail_idx;

    g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].next_tunnel_map_entry_idx =
        MLNX_TUNNEL_MAP_ENTRY_INVALID;

    g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_tail_idx = tunnel_map_entry_idx;

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/* Caller needs to guard this function with lock */
static sai_status_t mlnx_tunnel_map_entry_list_delete(_In_ mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry,
                                                      _In_ uint32_t                tunnel_map_entry_idx)
{
    uint32_t     tunnel_map_idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    uint32_t     prev_tunnel_map_entry_idx = 0;
    uint32_t     next_tunnel_map_entry_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(mlnx_tunnel_map_entry.tunnel_map_id, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   mlnx_tunnel_map_entry.tunnel_map_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    prev_tunnel_map_entry_idx =
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].prev_tunnel_map_entry_idx;

    next_tunnel_map_entry_idx =
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].next_tunnel_map_entry_idx;

    if (MLNX_TUNNEL_MAP_ENTRY_INVALID ==
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].prev_tunnel_map_entry_idx) {
        assert(tunnel_map_entry_idx == g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_head_idx);

        g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_head_idx = next_tunnel_map_entry_idx;
    } else {
        assert(tunnel_map_entry_idx != g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_head_idx);
    }

    if (MLNX_TUNNEL_MAP_ENTRY_INVALID ==
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].next_tunnel_map_entry_idx) {
        assert(tunnel_map_entry_idx == g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_tail_idx);

        g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_tail_idx = prev_tunnel_map_entry_idx;
    } else {
        assert(tunnel_map_entry_idx != g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_tail_idx);
    }

    g_sai_tunnel_db_ptr->tunnel_map_entry_db[prev_tunnel_map_entry_idx].next_tunnel_map_entry_idx =
        next_tunnel_map_entry_idx;

    g_sai_tunnel_db_ptr->tunnel_map_entry_db[next_tunnel_map_entry_idx].prev_tunnel_map_entry_idx =
        prev_tunnel_map_entry_idx;

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/* caller of this function should use read lock to guard the call */
static sai_status_t mlnx_create_empty_bmtor_bridge_entry(_Out_ uint32_t *bmtor_bridge_db_idx)
{
    uint32_t     idx = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    for (idx = 0; idx < MLNX_BMTOR_BRIDGE_MAX; idx++) {
        if (!g_sai_tunnel_db_ptr->bmtor_bridge_db[idx].in_use) {
            *bmtor_bridge_db_idx = idx;
            sai_status = SAI_STATUS_SUCCESS;
            goto cleanup;
        }
    }

    SX_LOG_ERR(
        "Not enough resources for bmtor bridge entry, at most %d bmtor bridge objs can be used\n",
        MLNX_BMTOR_BRIDGE_MAX);
    sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;

cleanup:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_create_bmtor_internal_obj(_In_ sai_object_id_t       vrf_oid,
                                                   _In_ uint32_t              vni,
                                                   _In_ sai_object_id_t       tunnel_oid,
                                                   _In_ bool                  is_default,
                                                   _Out_ mlnx_bmtor_bridge_t *bmtor_bridge_entry)
{
    sai_status_t          sai_status;
    sai_object_id_t       bridge_oid, rif_oid;
    sai_object_id_t       bridge_bport_oid, tunnel_bport_oid;
    sai_object_id_t       switch_oid;
    sx_tunnel_id_t        sx_tunnel_id;
    sx_bridge_id_t        sx_bridge_id;
    sx_tunnel_map_entry_t sx_tunnel_map_entry = {0};
    const uint32_t        sx_tunnel_map_entry_cnt = 1;
    sx_status_t           sdk_status;
    mlnx_object_id_t      mlnx_switch_id = {0};
    sai_attribute_t       attr[5];
    sx_vlan_attrib_t      vlan_attrib_p;

    SX_LOG_ENTER();

    if (NULL == bmtor_bridge_entry) {
        SX_LOG_ERR("bmtor_bridge_entry is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_SWITCH, &mlnx_switch_id, &switch_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error creating switch oid\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    attr[0].id = SAI_BRIDGE_ATTR_TYPE;
    attr[0].value.s32 = SAI_BRIDGE_TYPE_1D;
    sai_status = mlnx_bridge_api.create_bridge(&bridge_oid, switch_oid, 1, attr);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to create SAI bridge\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_bridge_oid_to_id(bridge_oid, &sx_bridge_id);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to obtain sx bridge id from SAI bridge oid %" PRIx64 "\n", bridge_oid);
        SX_LOG_EXIT();
        return sai_status;
    }
    memset(&vlan_attrib_p, 0, sizeof(vlan_attrib_p));
    if (is_default) {
        vlan_attrib_p.flood_to_router = true;
    } else {
        vlan_attrib_p.flood_to_router = false;
    }
    sdk_status = sx_api_vlan_attrib_set(gh_sdk, sx_bridge_id, &vlan_attrib_p);
    if (SX_ERR(sdk_status)) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error setting vlan attribute for fid %d: %s\n",
                   sx_bridge_id, SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }

    attr[0].id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr[0].value.oid = vrf_oid;
    attr[1].id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr[1].value.s32 = SAI_ROUTER_INTERFACE_TYPE_BRIDGE;
    attr[2].id = SAI_ROUTER_INTERFACE_ATTR_BRIDGE_ID;
    attr[2].value.oid = bridge_oid;
    sai_status = mlnx_router_interface_api.create_router_interface(&rif_oid, switch_oid, 3, attr);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to create SAI rif\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    attr[0].id = SAI_BRIDGE_PORT_ATTR_TYPE;
    attr[0].value.s32 = SAI_BRIDGE_PORT_TYPE_1D_ROUTER;
    attr[1].id = SAI_BRIDGE_PORT_ATTR_RIF_ID;
    attr[1].value.oid = rif_oid;
    attr[2].id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
    attr[2].value.oid = bridge_oid;
    attr[3].id = SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE;
    attr[3].value.s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE;
    sai_status = mlnx_bridge_api.create_bridge_port(&bridge_bport_oid, switch_oid, 4, attr);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to create SAI bridge port\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    attr[0].id = SAI_BRIDGE_PORT_ATTR_TYPE;
    attr[0].value.s32 = SAI_BRIDGE_PORT_TYPE_TUNNEL;
    attr[1].id = SAI_BRIDGE_PORT_ATTR_TUNNEL_ID;
    attr[1].value.oid = tunnel_oid;
    attr[2].id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
    attr[2].value.oid = bridge_oid;
    attr[3].id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE;
    attr[3].value.booldata = true;
    attr[4].id = SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE;
    attr[4].value.s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE;
    sai_status = mlnx_bridge_api.create_bridge_port(&tunnel_bport_oid, switch_oid, 5, attr);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to create SAI tunnel bridge port\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(tunnel_oid, &sx_tunnel_id);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to obtain sx tunnel id from SAI tunnel oid %" PRIx64 "\n", tunnel_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_get_tunnel_type_by_tunnel_id(tunnel_oid, &sx_tunnel_map_entry.type);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get tunnel type.\n");
        return sai_status;
    }
    sx_tunnel_map_entry.params.nve.bridge_id = sx_bridge_id;
    sx_tunnel_map_entry.params.nve.vni = vni;
    sx_tunnel_map_entry.params.nve.direction = SX_TUNNEL_MAP_DIR_BIDIR;
    sdk_status = sx_api_tunnel_map_set(gh_sdk,
                                       SX_ACCESS_CMD_ADD,
                                       sx_tunnel_id,
                                       &sx_tunnel_map_entry,
                                       sx_tunnel_map_entry_cnt);
    if (SX_STATUS_SUCCESS != sdk_status) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error adding tunnel map for tunnel %x with bridge %x, vni %d, sx status %s\n",
                   sx_tunnel_id,
                   sx_bridge_id,
                   vni,
                   SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }

    bmtor_bridge_entry->connected_vrf_oid = vrf_oid;
    bmtor_bridge_entry->bridge_oid = bridge_oid;
    bmtor_bridge_entry->rif_oid = rif_oid;
    bmtor_bridge_entry->bridge_bport_oid = bridge_bport_oid;
    bmtor_bridge_entry->tunnel_bport_oid = tunnel_bport_oid;
    bmtor_bridge_entry->tunnel_id = tunnel_oid;
    bmtor_bridge_entry->sx_vxlan_tunnel_id = sx_tunnel_id;
    bmtor_bridge_entry->vni = vni;
    bmtor_bridge_entry->is_default = is_default;
    bmtor_bridge_entry->counter = 0;
    bmtor_bridge_entry->in_use = true;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_remove_bmtor_internal_obj(_In_ mlnx_bmtor_bridge_t *bmtor_bridge_entry)
{
    sai_status_t          sai_status;
    sx_bridge_id_t        sx_bridge_id;
    sx_tunnel_map_entry_t sx_tunnel_map_entry = {0};
    const uint32_t        sx_tunnel_map_entry_cnt = 1;
    sx_status_t           sdk_status;

    SX_LOG_ENTER();

    if (NULL == bmtor_bridge_entry) {
        SX_LOG_ERR("bmtor_bridge_entry is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_bridge_oid_to_id(bmtor_bridge_entry->bridge_oid, &sx_bridge_id);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to obtain sx bridge id from SAI bridge oid 0x%" PRIx64 "\n",
                   bmtor_bridge_entry->bridge_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_get_tunnel_type_by_tunnel_id(bmtor_bridge_entry->tunnel_id, &sx_tunnel_map_entry.type);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get tunnel type.\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    sx_tunnel_map_entry.params.nve.bridge_id = sx_bridge_id;
    sx_tunnel_map_entry.params.nve.vni = bmtor_bridge_entry->vni;
    sx_tunnel_map_entry.params.nve.direction = SX_TUNNEL_MAP_DIR_BIDIR;
    sdk_status = sx_api_tunnel_map_set(gh_sdk,
                                       SX_ACCESS_CMD_DELETE,
                                       bmtor_bridge_entry->sx_vxlan_tunnel_id,
                                       &sx_tunnel_map_entry,
                                       sx_tunnel_map_entry_cnt);
    if (SX_STATUS_SUCCESS != sdk_status) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error deleting tunnel map for tunnel 0x%x with bridge 0x%x, vni %d, sx status %s\n",
                   bmtor_bridge_entry->sx_vxlan_tunnel_id,
                   sx_bridge_id,
                   bmtor_bridge_entry->vni,
                   SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_bridge_api.remove_bridge_port(bmtor_bridge_entry->tunnel_bport_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to remove SAI tunnel bridge port 0x%" PRIx64 "\n", bmtor_bridge_entry->tunnel_bport_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_bridge_api.remove_bridge_port(bmtor_bridge_entry->bridge_bport_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to remove SAI bridge port 0x%" PRIx64 "\n", bmtor_bridge_entry->bridge_bport_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_router_interface_api.remove_router_interface(bmtor_bridge_entry->rif_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to remove SAI rif 0x%" PRIx64 "\n", bmtor_bridge_entry->rif_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_bridge_api.remove_bridge(bmtor_bridge_entry->bridge_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to remove SAI bridge 0x%" PRIx64 "\n", bmtor_bridge_entry->bridge_oid);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* This function needs to be guarded by lock */
static sai_status_t mlnx_tunnel_map_entry_set_bmtor_obj(_In_ uint32_t tunnel_map_entry_idx,
                                                        _In_ uint32_t tunnel_idx,
                                                        _In_ bool     is_add)
{
    sai_status_t        sai_status;
    sai_object_id_t     vrf_oid, tunnel_oid;
    uint32_t            vni;
    mlnx_bmtor_bridge_t bmtor_bridge_entry;
    uint32_t            bmtor_bridge_db_idx;
    bool                is_default = true;
    uint32_t            pair_tunnel_map_entry_idx = 0;

    SX_LOG_ENTER();

    switch (g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type) {
    case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
        vrf_oid = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vr_id_key;
        vni = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vni_id_value;
        break;

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
        vrf_oid = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vr_id_value;
        vni = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vni_id_key;
        break;

    default:
        SX_LOG_ERR("Unsupported tunnel map type %d to create bmtor obj\n",
                   g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL, tunnel_idx, NULL, &tunnel_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error getting tunnel oid using tunnel db idx %d\n", tunnel_idx);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (is_add) {
        sai_db_unlock();

        sai_status = mlnx_create_bmtor_internal_obj(vrf_oid, vni, tunnel_oid, is_default, &bmtor_bridge_entry);
        if (SAI_ERR(sai_status)) {
            sai_db_write_lock();
            SX_LOG_ERR(
                "Failed to create bmtor internal obj using vrf oid %" PRIx64 ", vni %d and tunnel oid %" PRIx64 "\n",
                vrf_oid,
                vni,
                tunnel_oid);
            SX_LOG_EXIT();
            return sai_status;
        }

        sai_db_write_lock();

        sai_status = mlnx_create_empty_bmtor_bridge_entry(&bmtor_bridge_db_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error creating empty bmtor bridge entry\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        memcpy(&(g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx]),
               &bmtor_bridge_entry,
               sizeof(bmtor_bridge_entry));
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
        bmtor_bridge_db_idx = bmtor_bridge_db_idx;
        if (g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].pair_exist)
        {
            pair_tunnel_map_entry_idx
                = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
                  pair_tunnel_map_entry_idx;
            g_sai_tunnel_db_ptr->tunnel_map_entry_db[pair_tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
            bmtor_bridge_db_idx = bmtor_bridge_db_idx;
        }
    } else {
        bmtor_bridge_db_idx =
            g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
            bmtor_bridge_db_idx;
        if (!g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].in_use) {
            SX_LOG_DBG(
                "bmtor internal obj does not exist at bmtor bridge db idx %d for tunnel map entry idx %d and tunnel idx %d\n",
                bmtor_bridge_db_idx,
                tunnel_map_entry_idx,
                tunnel_idx);
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        memcpy(&bmtor_bridge_entry,
               &(g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx]),
               sizeof(bmtor_bridge_entry));

        sai_db_unlock();

        sai_status = mlnx_remove_bmtor_internal_obj(&bmtor_bridge_entry);
        if (SAI_ERR(sai_status)) {
            sai_db_write_lock();
            SX_LOG_ERR(
                "Failed to remove bmtor internal obj at bmtor bridge db idx %d for tunnel map entry idx %d and tunnel idx %d\n",
                bmtor_bridge_db_idx,
                tunnel_map_entry_idx,
                tunnel_idx);
            SX_LOG_EXIT();
            return sai_status;
        }

        sai_db_write_lock();

        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
        bmtor_bridge_db_idx = 0;
        g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].in_use
            = false;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Create tunnel map item
 *
 * @param[out] tunnel_map_entry_id Tunnel map item id
 * @param[in] switch_id Switch Id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_tunnel_map_entry(_Out_ sai_object_id_t      *sai_tunnel_map_entry_obj_id,
                                                 _In_ sai_object_id_t        switch_id,
                                                 _In_ uint32_t               attr_count,
                                                 _In_ const sai_attribute_t *attr_list)
{
    char                    list_str[MAX_LIST_VALUE_STR_LEN];
    sai_status_t            sai_status = SAI_STATUS_SUCCESS;
    sai_status_t            sai_cleanup_status = SAI_STATUS_SUCCESS;
    uint32_t                tunnel_map_entry_idx = 0;
    mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry;
    bool                    is_add = true;
    bool                    tunnel_map_entry_created = false;
    bool                    tunnel_map_entry_list_added = false;
    bool                    tunnel_map_entry_bound = false;
    uint32_t                tunnel_map_idx = 0;

    memset(&mlnx_tunnel_map_entry, 0, sizeof(mlnx_tunnel_map_entry_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY,
                                    tunnel_map_entry_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Tunnel map entry: metadata check failed\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create tunnel map entry attributes: %s\n", list_str);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_init_tunnel_map_entry_param(attr_count, attr_list, &mlnx_tunnel_map_entry))) {
        SX_LOG_ERR("Fail to set tunnel map entry param on create\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_get_sai_tunnel_map_db_idx(mlnx_tunnel_map_entry.tunnel_map_id, &tunnel_map_idx);
    /* mlnx_get_sai_tunnel_map_db_idx has been called in mlnx_init_tunnel_map_entry_param */
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_db_write_lock();

    g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_cnt++;

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_empty_tunnel_map_entry(&tunnel_map_entry_idx))) {
        SX_LOG_ERR("Failed to create empty tunnel map entry\n");
        goto cleanup;
    }
    tunnel_map_entry_created = true;

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, tunnel_map_entry_idx, NULL,
                                sai_tunnel_map_entry_obj_id))) {
        memset(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx], 0,
               sizeof(mlnx_tunnel_map_entry_t));
        SX_LOG_ERR("Error creating sai tunnel map entry obj id from tunnel map entry idx %d\n",
                   tunnel_map_entry_idx);
        goto cleanup;
    }

    memcpy(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx], &mlnx_tunnel_map_entry,
           sizeof(mlnx_tunnel_map_entry_t));

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_tunnel_map_entry_list_add(mlnx_tunnel_map_entry,
                                            tunnel_map_entry_idx))) {
        SX_LOG_ERR("Error adding idx %d to tunnel map entry list\n", tunnel_map_entry_idx);
        goto cleanup;
    }
    tunnel_map_entry_list_added = true;

    SX_LOG_NTC("Created tunnel map entry obj id: %" PRIx64 "\n", *sai_tunnel_map_entry_obj_id);

    sai_status = mlnx_sai_tunnel_map_entry_bind_tunnel_set(tunnel_map_entry_idx, is_add);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error binding tunnel map entry idx %d to tunnel\n", tunnel_map_entry_idx);
        goto cleanup;
    }
    tunnel_map_entry_bound = true;

    sai_status = SAI_STATUS_SUCCESS;
    goto cleanup_exit;

cleanup:
    if (tunnel_map_entry_bound) {
        is_add = false;
        sai_cleanup_status = mlnx_sai_tunnel_map_entry_bind_tunnel_set(tunnel_map_entry_idx, is_add);
        if (SAI_ERR(sai_cleanup_status)) {
            SX_LOG_ERR("Error unbinding tunnel map entry idx %d to tunnel\n", tunnel_map_entry_idx);
            goto cleanup_exit;
        }
    }
    if (tunnel_map_entry_list_added) {
        if (SAI_STATUS_SUCCESS !=
            (sai_cleanup_status =
                 mlnx_tunnel_map_entry_list_delete(mlnx_tunnel_map_entry,
                                                   tunnel_map_entry_idx))) {
            SX_LOG_ERR("Error deleting idx %d to tunnel map entry list\n", tunnel_map_entry_idx);
            goto cleanup_exit;
        }
    }
    if (tunnel_map_entry_created) {
        memset(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx], 0,
               sizeof(mlnx_tunnel_map_entry_t));
    }
    g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_cnt--;
cleanup_exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

/**
 * @brief Remove tunnel map item
 *
 * @param[in] tunnel_map_entry_id Tunnel map item id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_tunnel_map_entry(_In_ sai_object_id_t sai_tunnel_map_entry_obj_id)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    uint32_t              tunnel_map_idx = 0;
    uint32_t              tunnel_map_entry_idx = 0;
    sai_tunnel_map_type_t tunnel_map_type;
    const bool            is_add = false;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_tunnel_map_entry_obj_id, SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, &tunnel_map_entry_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai tunnel map entry obj id: %" PRIx64 "\n", sai_tunnel_map_entry_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (MLNX_TUNNEL_MAP_ENTRY_MAX <= tunnel_map_entry_idx) {
        SX_LOG_ERR("tunnel map idx %d is bigger than upper bound %d\n", tunnel_map_entry_idx, MLNX_TUNNEL_MAP_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_db_write_lock();

    if (!(g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].in_use)) {
        SX_LOG_ERR("Invalid sai tunnel map entry obj id: %" PRIx64 "\n", sai_tunnel_map_entry_obj_id);
        sai_status = SAI_STATUS_INVALID_OBJECT_ID;
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             mlnx_get_sai_tunnel_map_db_idx(g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].
                                            tunnel_map_id,
                                            &tunnel_map_idx))) {
        assert(0 < g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_cnt);
        g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_entry_cnt--;
    } else {
        SX_LOG_ERR("Error getting tunnel map idx from SAI tunnel map oid %" PRIx64 "\n",
                   g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_id);
        sai_status = SAI_STATUS_FAILURE;
        goto cleanup;
    }

    tunnel_map_type = g_sai_tunnel_db_ptr->tunnel_map_db[tunnel_map_idx].tunnel_map_type;

    /* Non-ECN map: delete SDK tunnel map first, then remove tunnel map db   */
    if ((SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN != tunnel_map_type) &&
        (SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN != tunnel_map_type)) {
        sai_status = mlnx_sai_tunnel_map_entry_bind_tunnel_set(tunnel_map_entry_idx, is_add);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error unbinding tunnel map entry idx %d to tunnel\n", tunnel_map_entry_idx);
            goto cleanup;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_entry_list_delete(g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx],
                                                        tunnel_map_entry_idx))) {
        SX_LOG_ERR("Error deleting idx %d from tunnel map entry list\n", tunnel_map_entry_idx);
        goto cleanup;
    }

    /* ECN map: remove tunnel map db first, then reset whole COS setting   */
    if ((SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN == tunnel_map_type) ||
        (SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN == tunnel_map_type)) {
        sai_status = mlnx_sai_tunnel_map_entry_bind_tunnel_set(tunnel_map_entry_idx, is_add);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error unbinding tunnel map entry idx %d to tunnel\n", tunnel_map_entry_idx);
            goto cleanup;
        }
    }

    memset(&g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx], 0, sizeof(mlnx_tunnel_map_entry_t));

    SX_LOG_NTC("Removed SAI tunnel map entry obj id %" PRIx64 "\n", sai_tunnel_map_entry_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_tunnel_get_bmtor_entry_idx(_In_ sai_object_id_t tunnel_id,
                                                    _In_ uint32_t        vni,
                                                    _In_ sai_object_id_t vrf,
                                                    _Out_ uint32_t      *tunnel_map_entry_idx,
                                                    _Out_ uint32_t      *bmtor_bridge_db_idx)
{
    sai_status_t             sai_status;
    sx_tunnel_id_t           sx_vxlan_tunnel;
    mlnx_tunnel_map_entry_t *curr_tunnel_map_entry;
    uint32_t                 ii = 0;
    uint32_t                 curr_bmtor_bridge_db_idx = 0;
    uint32_t                 tunnel_idx = 0;
    bool                     vrf_key_match = false;
    bool                     vrf_value_match = false;
    bool                     vni_key_match = false;
    bool                     vni_value_match = false;

    SX_LOG_ENTER();

    if (NULL == tunnel_map_entry_idx) {
        SX_LOG_ERR("tunnel_map_entry_idx is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (NULL == bmtor_bridge_db_idx) {
        SX_LOG_ERR("bmtor_bridge_db_idx is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(tunnel_id, &sx_vxlan_tunnel);
    if (SAI_ERR(sai_status)) {
        SX_LOG_DBG("Failed to find sx tunnel id from SAI tunnel oid %" PRIx64 "\n", tunnel_id);
    }

    sai_status = mlnx_get_sai_tunnel_db_idx(tunnel_id, &tunnel_idx);
    if (SAI_ERR(sai_status)) {
        SX_LOG_DBG("Failed to find tunnel idx from SAI tunnel oid %" PRIx64 "\n", tunnel_id);
    }

    /* Get VR ID to VNI map */
    for (ii = 0; ii < MLNX_TUNNEL_MAP_ENTRY_MAX; ii++) {
        curr_tunnel_map_entry = &(g_sai_tunnel_db_ptr->tunnel_map_entry_db[ii]);
        if (NULL == curr_tunnel_map_entry) {
            SX_LOG_DBG("Tunnel map entry %d is empty\n", ii);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        if (0 == vni) {
            vrf_key_match = (SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI == curr_tunnel_map_entry->tunnel_map_type) &&
                            (vrf == curr_tunnel_map_entry->vr_id_key);
            vrf_value_match =
                (SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID == curr_tunnel_map_entry->tunnel_map_type) &&
                (vrf == curr_tunnel_map_entry->vr_id_value);
            if (curr_tunnel_map_entry->in_use &&
                (vrf_key_match || vrf_value_match)) {
                curr_bmtor_bridge_db_idx = curr_tunnel_map_entry->pair_per_vxlan_array[tunnel_idx].bmtor_bridge_db_idx;
                if (MLNX_BMTOR_BRIDGE_MAX <= curr_bmtor_bridge_db_idx) {
                    SX_LOG_DBG("bmtor bridge db idx %d should be smaller than limit %d\n",
                               curr_bmtor_bridge_db_idx, MLNX_BMTOR_BRIDGE_MAX);
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }

                if (g_sai_tunnel_db_ptr->bmtor_bridge_db[curr_bmtor_bridge_db_idx].is_default) {
                    break;
                }
            }
        } else {
            vni_key_match = (SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID == curr_tunnel_map_entry->tunnel_map_type) &&
                            (vni == curr_tunnel_map_entry->vni_id_key);
            vni_value_match =
                (SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI == curr_tunnel_map_entry->tunnel_map_type) &&
                (vni == curr_tunnel_map_entry->vni_id_value);
            if (curr_tunnel_map_entry->in_use &&
                (vni_key_match || vni_value_match)) {
                break;
            }
        }
    }
    if (MLNX_TUNNEL_MAP_ENTRY_MAX == ii) {
        SX_LOG_DBG("Failed to find vr oid key %" PRIx64 " in SAI tunnel map entry db\n", vrf);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    /* Get VNI to bridge */
    curr_bmtor_bridge_db_idx = curr_tunnel_map_entry->pair_per_vxlan_array[tunnel_idx].bmtor_bridge_db_idx;
    if (MLNX_BMTOR_BRIDGE_MAX <= curr_bmtor_bridge_db_idx) {
        SX_LOG_DBG("bmtor bridge db idx %d should be smaller than limit %d\n",
                   curr_bmtor_bridge_db_idx, MLNX_BMTOR_BRIDGE_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    *tunnel_map_entry_idx = ii;
    *bmtor_bridge_db_idx = curr_bmtor_bridge_db_idx;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_tunnel_get_bridge_and_rif(_In_ sai_object_id_t         tunnel_id,
                                            _In_ uint32_t                vni,
                                            _In_ sai_object_id_t         vrf,
                                            _Out_ sx_router_interface_t *br_rif,
                                            _Out_ sx_fid_t              *br_fid)
{
    sai_status_t       sai_status;
    sai_object_id_t    bridge_oid;
    sx_bridge_id_t     sx_bridge_id;
    mlnx_bridge_rif_t *curr_bridge_rif_entry;
    uint32_t           tunnel_map_entry_idx = 0;
    uint32_t           ii = 0;
    uint32_t           bmtor_bridge_db_idx = 0;

    SX_LOG_ENTER();

    if (NULL == br_rif) {
        SX_LOG_ERR("Empty pointer br_rif\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (NULL == br_fid) {
        SX_LOG_ERR("Empty pointer br_fid\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_tunnel_get_bmtor_entry_idx(tunnel_id, vni, vrf, &tunnel_map_entry_idx, &bmtor_bridge_db_idx);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error getting bmtor entry idx using tunnel id %" PRIx64 ", vni: %d, vrf: %" PRIx64 "\n",
                   tunnel_id, vni, vrf);
        SX_LOG_EXIT();
        return sai_status;
    }

    bridge_oid = g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].bridge_oid;

    sai_status = mlnx_bridge_oid_to_id(bridge_oid, &sx_bridge_id);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to find sx bridge id using bridge oid %" PRIx64 "\n", bridge_oid);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    /* Get bridge to bridge rif */
    for (ii = 0; ii < MAX_BRIDGE_RIFS; ii++) {
        curr_bridge_rif_entry = &(g_sai_db_ptr->bridge_rifs_db[ii]);
        if (NULL == curr_bridge_rif_entry) {
            SX_LOG_ERR("Bridge rif entry %d is empty\n", ii);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        if (curr_bridge_rif_entry->is_used &&
            (sx_bridge_id == curr_bridge_rif_entry->intf_params.ifc.bridge.bridge)) {
            *br_rif = curr_bridge_rif_entry->sx_data.rif_id;
            *br_fid = sx_bridge_id;
            break;
        }
    }

    if (MAX_BRIDGE_RIFS == ii) {
        SX_LOG_ERR("Failed to find bridge id %d in SAI bridge rif db\n", sx_bridge_id);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_tunnel_bridge_counter_update(_In_ sai_object_id_t tunnel_id,
                                               _In_ uint32_t        vni,
                                               _In_ sai_object_id_t vrf,
                                               _In_ int32_t         diff)
{
    const bool          is_default = false;
    mlnx_bmtor_bridge_t bmtor_bridge_entry;
    uint32_t            bmtor_bridge_db_idx;
    uint32_t            tunnel_map_entry_idx = 0;
    uint32_t            pair_tunnel_map_entry_idx = 0;
    uint32_t            tunnel_idx = 0;
    sai_status_t        sai_status;

    SX_LOG_ENTER();

    sai_status = mlnx_get_sai_tunnel_db_idx(tunnel_id, &tunnel_idx);
    if (SAI_ERR(sai_status)) {
        SX_LOG_DBG("Failed to find tunnel idx from SAI tunnel oid %" PRIx64 "\n", tunnel_id);
    }

    sai_status = mlnx_tunnel_get_bmtor_entry_idx(tunnel_id, vni, vrf,
                                                 &tunnel_map_entry_idx, &bmtor_bridge_db_idx);
    if (SAI_ERR(sai_status)) {
        sai_db_unlock();
        sai_status = mlnx_create_bmtor_internal_obj(vrf, vni, tunnel_id, is_default, &bmtor_bridge_entry);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR(
                "Failed to create bmtor internal obj using VRF %" PRIx64 ", VNI %d and tunnel oid %" PRIx64 "\n",
                vrf,
                vni,
                tunnel_id);
            sai_db_write_lock();
            SX_LOG_EXIT();
            return sai_status;
        }
        sai_db_write_lock();

        sai_status = mlnx_create_empty_bmtor_bridge_entry(&bmtor_bridge_db_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error creating empty bmtor bridge entry\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        memcpy(&(g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx]),
               &bmtor_bridge_entry,
               sizeof(bmtor_bridge_entry));

        sai_status = mlnx_create_empty_tunnel_map_entry(&tunnel_map_entry_idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to create empty tunnel map entry\n");
            SX_LOG_EXIT();
            return sai_status;
        }

        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
        bmtor_bridge_db_idx = bmtor_bridge_db_idx;
        if (g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].pair_exist)
        {
            pair_tunnel_map_entry_idx
                = g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
                  pair_tunnel_map_entry_idx;
            g_sai_tunnel_db_ptr->tunnel_map_entry_db[pair_tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
            bmtor_bridge_db_idx = bmtor_bridge_db_idx;
        }
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].in_use = true;
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].tunnel_map_type =
            SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI;
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vr_id_key = vrf;
        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].vni_id_value = vni;
    } else {
        memcpy(&bmtor_bridge_entry, &(g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx]),
               sizeof(bmtor_bridge_entry));
    }
    g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].counter += diff;
    bmtor_bridge_entry.counter += diff;
    if ((0 == bmtor_bridge_entry.counter) && (bmtor_bridge_entry.is_default == false)) {
        if (!bmtor_bridge_entry.in_use) {
            SX_LOG_DBG("bmtor internal obj does not exist at bmtor bridge db idx %d\n",
                       bmtor_bridge_db_idx);
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        sai_db_unlock();

        sai_status = mlnx_remove_bmtor_internal_obj(&bmtor_bridge_entry);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Error removing bmtor internal obj\n");
            SX_LOG_EXIT();
            sai_db_write_lock();
            return sai_status;
        }

        sai_db_write_lock();

        g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].pair_per_vxlan_array[tunnel_idx].
        bmtor_bridge_db_idx = 0;
        g_sai_tunnel_db_ptr->bmtor_bridge_db[bmtor_bridge_db_idx].in_use
            = false;
        if (0 != vni) {
            g_sai_tunnel_db_ptr->tunnel_map_entry_db[tunnel_map_entry_idx].in_use = false;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Set tunnel map item attribute
 *
 * @param[in] tunnel_map_entry_id Tunnel map item id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_tunnel_map_entry_attribute(_In_ sai_object_id_t        sai_tunnel_map_entry_obj_id,
                                                        _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_map_entry_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_map_entry_key_to_str(sai_tunnel_map_entry_obj_id, key_str);

    sai_status = sai_set_attribute(&key,
                                   key_str,
                                   SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY,
                                   tunnel_map_entry_vendor_attribs,
                                   attr);

    SX_LOG_EXIT();
    return sai_status;
}

/**
 * @brief Get tunnel map item attributes
 *
 * @param[in] tunnel_map_entry_id Tunnel map item id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_tunnel_map_entry_attribute(_In_ sai_object_id_t     sai_tunnel_map_entry_obj_id,
                                                        _In_ uint32_t            attr_count,
                                                        _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = sai_tunnel_map_entry_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    tunnel_map_entry_key_to_str(sai_tunnel_map_entry_obj_id, key_str);

    sai_status =
        sai_get_attributes(&key,
                           key_str,
                           SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY,
                           tunnel_map_entry_vendor_attribs,
                           attr_count,
                           attr_list);

    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_tunnel_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_tunnel_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

static sai_status_t mlnx_tunnel_stats_get(_In_ sai_object_id_t      tunnel_id,
                                          _In_ uint32_t             number_of_counters,
                                          _In_ const sai_stat_id_t *counter_ids,
                                          _In_ bool                 clear,
                                          _Out_ uint64_t           *counters)
{
    sx_status_t         sx_status;
    sai_status_t        status;
    sx_access_cmd_t     sx_cmd;
    sx_tunnel_id_t      sx_tunnel_id;
    sx_tunnel_counter_t sx_tunnel_counter;
    uint32_t            ii;
    char                key_str[MAX_KEY_STR_LEN];

    assert(counter_ids);

    memset(&sx_tunnel_counter, 0, sizeof(sx_tunnel_counter));

    SX_LOG_ENTER();

    tunnel_key_to_str(tunnel_id, key_str);
    SX_LOG_DBG("Get tunnel stats %s\n", key_str);

    sx_cmd = clear ? SX_ACCESS_CMD_READ_CLEAR : SX_ACCESS_CMD_READ;

    sai_db_read_lock();

    status = mlnx_sai_tunnel_to_sx_tunnel_id(tunnel_id, &sx_tunnel_id);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_EXIT();
        return status;
    }

    sai_db_unlock();

    sx_status = sx_api_tunnel_counter_get(gh_sdk, sx_cmd, sx_tunnel_id, &sx_tunnel_counter);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s sx tunnel %u counter - %s\n", SX_ACCESS_CMD_STR(sx_cmd), sx_tunnel_id,
                   SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }

    if (NULL != counters) {
        for (ii = 0; ii < number_of_counters; ii++) {
            switch (counter_ids[ii]) {
            case SAI_TUNNEL_STAT_IN_PACKETS:
                counters[ii] = sx_tunnel_counter.counter.nve.decapsulated_pkts;
                break;

            case SAI_TUNNEL_STAT_OUT_PACKETS:
                counters[ii] = sx_tunnel_counter.counter.nve.encapsulated_pkts;
                break;

            case SAI_TUNNEL_STAT_IN_OCTETS:
            case SAI_TUNNEL_STAT_OUT_OCTETS:
                SX_LOG_INF("Tunnel counter %d (item %u) not implemented\n", counter_ids[ii], ii);
                return SAI_STATUS_NOT_IMPLEMENTED;

            default:
                SX_LOG_ERR("Invalid tunnel counter %d\n", counter_ids[ii]);
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Get tunnel statistics counters extended.
 *
 * @param[in] tunnel_id Tunnel id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t mlnx_get_tunnel_stats_ext(_In_ sai_object_id_t      tunnel_id,
                                       _In_ uint32_t             number_of_counters,
                                       _In_ const sai_stat_id_t *counter_ids,
                                       _In_ sai_stats_mode_t     mode,
                                       _Out_ uint64_t           *counters)
{
    sai_status_t    status;
    sx_access_cmd_t cmd;
    bool            clear;

    SX_LOG_ENTER();

    if (number_of_counters == 0) {
        SX_LOG_ERR("Number of counters is 0\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (counter_ids == NULL) {
        SX_LOG_ERR("Counter IDs is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (counters == NULL) {
        SX_LOG_ERR("Counters is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_stats_mode_to_sdk(mode, &cmd))) {
        SX_LOG_ERR("Mode %d is invalid\n", mode);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    clear = (mode == SAI_STATS_MODE_READ_AND_CLEAR);

    status = mlnx_tunnel_stats_get(tunnel_id, number_of_counters, counter_ids, clear, counters);

    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Get tunnel statistics counters.
 *
 * @param[in] tunnel_id Tunnel id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_get_tunnel_stats(_In_ sai_object_id_t      tunnel_id,
                                          _In_ uint32_t             number_of_counters,
                                          _In_ const sai_stat_id_t *counter_ids,
                                          _Out_ uint64_t           *counters)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = mlnx_get_tunnel_stats_ext(tunnel_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);

    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Clear tunnel statistics counters.
 *
 * @param[in] tunnel_id Tunnel id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_clear_tunnel_stats(_In_ sai_object_id_t      tunnel_id,
                                            _In_ uint32_t             number_of_counters,
                                            _In_ const sai_stat_id_t *counter_ids)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = mlnx_tunnel_stats_get(tunnel_id, number_of_counters, counter_ids, true, NULL);

    SX_LOG_EXIT();
    return status;
}

const sai_tunnel_api_t mlnx_tunnel_api = {
    mlnx_create_tunnel_map,
    mlnx_remove_tunnel_map,
    mlnx_set_tunnel_map_attribute,
    mlnx_get_tunnel_map_attribute,
    mlnx_create_tunnel,
    mlnx_remove_tunnel,
    mlnx_set_tunnel_attribute,
    mlnx_get_tunnel_attribute,
    mlnx_get_tunnel_stats,
    mlnx_get_tunnel_stats_ext,
    mlnx_clear_tunnel_stats,
    mlnx_create_tunnel_term_table_entry,
    mlnx_remove_tunnel_term_table_entry,
    mlnx_set_tunnel_term_table_entry_attribute,
    mlnx_get_tunnel_term_table_entry_attribute,
    mlnx_create_tunnel_map_entry,
    mlnx_remove_tunnel_map_entry,
    mlnx_set_tunnel_map_entry_attribute,
    mlnx_get_tunnel_map_entry_attribute,
    NULL,
    NULL,
};
