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

#undef  __MODULE__
#define __MODULE__ SAI_TUNNEL

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_sai_get_tunnel_attribs(_In_ sai_object_id_t         sai_tunnel_id,
                                                _Out_ sx_tunnel_attribute_t *sx_tunnel_attr);
static sai_status_t mlnx_sai_get_tunnel_cos_data(_In_ sai_object_id_t        sai_tunnel_id,
                                                 _Out_ sx_tunnel_cos_data_t *sx_tunnel_cos_data);
static sai_status_t mlnx_convert_sai_tunnel_type_to_sx(_In_ sai_tunnel_type_t  sai_type,
                                                       _Out_ sx_tunnel_type_e *sx_type);
static sai_status_t mlnx_convert_sx_tunnel_type_to_sai(_In_ sx_tunnel_type_e    sx_tunnel_attr,
                                                       _Out_ sai_tunnel_type_t *sai_type);
static sai_status_t mlnx_sai_tunnel_to_sx_tunnel_id(_In_ sai_object_id_t  sai_tunnel_id,
                                                    _Out_ sx_tunnel_id_t *sx_tunnel_id);
static sai_status_t mlnx_sai_get_sai_rif_id(_In_ sai_object_id_t        sai_tunnel_id,
                                            _In_ tunnel_rif_type        sai_tunnel_rif_type,
                                            _In_ sx_tunnel_attribute_t *sx_tunnel_attr,
                                            _Out_ sai_object_id_t      *sai_rif);
static sai_status_t mlnx_sai_create_vxlan_tunnel_map_list(_In_ sai_object_id_t      *sai_tunnel_mapper_list,
                                                          _In_ uint32_t              sai_tunnel_mapper_cnt,
                                                          _In_ tunnel_direction_type sai_tunnel_map_type,
                                                          _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                          _In_ sx_access_cmd_t       cmd);
static sai_status_t mlnx_tunnel_map_attr_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_tunnel_map_attr_map_to_value_list_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_tunnel_mappers_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);

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
};

/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t tunnel_map_vendor_attribs[] = {
    { SAI_TUNNEL_MAP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_attr_type_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_tunnel_map_attr_map_to_value_list_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};

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
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
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
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_encap_ecn_mode_get, NULL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_MAPPERS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_tunnel_mappers_get, (void*)TUNNEL_ENCAP,
      mlnx_tunnel_mappers_set, (void*)TUNNEL_ENCAP },
    { SAI_TUNNEL_ATTR_DECAP_ECN_MODE,
      { true, false, true, true },
      { true, false, true, true },
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
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};

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

/* caller needs to guard this function with lock */
static sai_status_t mlnx_get_sai_tunnel_map_db_idx(_In_ sai_object_id_t sai_tunnel_map_obj_id,
                                                   _Out_ uint32_t      *tunnel_mapper_db_idx)
{
    sai_status_t sai_status     = SAI_STATUS_FAILURE;
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

    if (!g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].in_use) {
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
    sai_status_t sai_status     = SAI_STATUS_FAILURE;
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

    if (!g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].in_use) {
        SX_LOG_ERR("Non-exist tunnel map idx: %d\n", tunnel_map_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    memcpy(mlnx_tunnel_map, &g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx], sizeof(mlnx_tunnel_map_t));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_map_db_param_get_from_db(_In_ const sai_object_id_t sai_tunnel_map_obj_id,
                                                         _Out_ mlnx_tunnel_map_t   *mlnx_tunnel_map)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    assert(NULL != g_sai_db_ptr);

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

static sai_status_t mlnx_tunnel_map_attr_map_to_value_list_get(_In_ const sai_object_key_t   *key,
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

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_fill_tunnelmaplist(mlnx_tunnel_map.tunnel_map_list,
                                              mlnx_tunnel_map.tunnel_map_list_count,
                                              &value->tunnelmap))) {
        SX_LOG_ERR("fail to fill tunnel map list\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard this function with lock */
static sai_status_t mlnx_get_sai_tunnel_map_entry_db_idx(_In_ sai_object_id_t sai_tunnel_map_entry_obj_id,
                                                         _Out_ uint32_t      *tunnel_map_entry_db_idx)
{
    sai_status_t sai_status           = SAI_STATUS_FAILURE;
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

    if (!g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].in_use) {
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
    sai_status_t sai_status           = SAI_STATUS_FAILURE;
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

    if (!g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].in_use) {
        SX_LOG_ERR("Non-exist tunnel map entry idx: %d\n", tunnel_map_entry_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    memcpy(mlnx_tunnel_map_entry, &g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx],
           sizeof(mlnx_tunnel_map_entry_t));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_tunnel_map_entry_db_param_get_from_db(
    _In_ const sai_object_id_t     sai_tunnel_map_entry_obj_id,
    _Out_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry)
{
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    assert(NULL != g_sai_db_ptr);

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
           (MLNX_BRIDGE_ID_VALUE == (long)arg));

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
    if (!g_sai_db_ptr->tunnel_db[*tunnel_db_idx].is_used) {
        SX_LOG_ERR("tunnel db index:%d item marked as not used\n", *tunnel_db_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return sai_status;
}

/* caller needs to guard this function with lock */
static sai_status_t mlnx_get_tunnel_db_entry(_In_ sai_object_id_t     sai_tunnel_id,
                                             _Out_ tunnel_db_entry_t *sai_tunnel_db_entry)
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

    memcpy(sai_tunnel_db_entry, &g_sai_db_ptr->tunnel_db[tunnel_db_idx], sizeof(tunnel_db_entry_t));

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
    tunnel_db_entry_t     sai_tunnel_db_entry;

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
            *sai_rif = sai_tunnel_db_entry.sai_vxlan_overlay_rif;
            if (SAI_NULL_OBJECT_ID == *sai_rif) {
                SX_LOG_ERR("Overlay rif is not valid for .1D bridge vxlan tunnel\n");
                sai_db_unlock();
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
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
            (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_ROUTER_INTERFACE,
                                             sdk_rif,
                                             NULL,
                                             sai_rif))) {
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
    SX_LOG_ENTER();

    assert((TUNNEL_ENCAP == (long)arg) || (TUNNEL_DECAP == (long)arg));

    value->s32 = SAI_TUNNEL_TTL_MODE_PIPE_MODEL;

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
        if ((SX_COS_DSCP_REWRITE_PRESERVE_E == sx_tunnel_cos_data.dscp_rewrite) &&
            (SX_COS_DSCP_ACTION_COPY_E == sx_tunnel_cos_data.dscp_action)) {
            value->s32 = SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
        } else if ((SX_COS_DSCP_REWRITE_ENABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
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
        if ((SX_COS_DSCP_REWRITE_PRESERVE_E == sx_tunnel_cos_data.dscp_rewrite) &&
            (SX_COS_DSCP_ACTION_COPY_E == sx_tunnel_cos_data.dscp_action)) {
            value->s32 = SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
        } else if ((SX_COS_DSCP_REWRITE_PRESERVE_E == sx_tunnel_cos_data.dscp_rewrite) &&
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

    if ((SX_COS_DSCP_REWRITE_PRESERVE_E == sx_tunnel_cos_data.dscp_rewrite) &&
        (SX_COS_DSCP_ACTION_COPY_E == sx_tunnel_cos_data.dscp_action)) {
        SX_LOG_ERR("dscp value is not valid for dscp uniform model\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    } else if ((SX_COS_DSCP_REWRITE_ENABLE_E == sx_tunnel_cos_data.dscp_rewrite) &&
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
    const uint8_t non_ect     = 0;
    const uint8_t ect0        = 1;
    const uint8_t ect1        = 2;
    const uint8_t ce          = 3;
    bool          is_standard = true;

    SX_LOG_ENTER();

    if (NULL == sx_tunnel_cos_ecn_decap_params) {
        SX_LOG_ERR("sx tunnel cos ecn decap params is null\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    is_standard &= ((sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][non_ect].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][ect0].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][ect1].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[non_ect][ce].egress_ecn == non_ect) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][non_ect].egress_ecn == ect0) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][ect0].egress_ecn == ect0) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][ect1].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect0][ce].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][non_ect].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][ect0].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][ect1].egress_ecn == ect1) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ect1][ce].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][non_ect].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][ect0].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][ect1].egress_ecn == ce) &&
                    (sx_tunnel_cos_ecn_decap_params->ecn_decap_map[ce][ce].egress_ecn == ce));

    SX_LOG_EXIT();
    return is_standard ? SAI_STATUS_SUCCESS : SAI_STATUS_FAILURE;
}

static sai_status_t mlnx_tunnel_decap_ecn_mode_is_copy_from_outer(
    _In_ sx_tunnel_cos_ecn_decap_params_t *sx_tunnel_cos_ecn_decap_params)
{
    uint32_t uecn_idx           = 0;
    uint32_t oecn_idx           = 0;
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
    sai_status_t sai_status        = SAI_STATUS_FAILURE;
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
            (sai_status = mlnx_fill_objlist(g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_encap_id_array,
                                            g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_encap_cnt,
                                            &value->objlist))) {
            SX_LOG_ERR("Error filling objlist for sai tunnel obj id %" PRId64 "\n", sai_tunnel_obj_id);
            goto cleanup;
        }
    } else if (TUNNEL_DECAP == (long)arg) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_fill_objlist(g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_decap_id_array,
                                            g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_decap_cnt,
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
    sai_status_t          sai_status   = SAI_STATUS_FAILURE;
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
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_vxlan_mapper_get(key->key.object_id, value, arg))) {
            SX_LOG_ERR("Error getting ipinip ecn mapper\n");
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
    sai_status_t      sai_status        = SAI_STATUS_FAILURE;
    uint32_t          sai_tunnel_db_idx = 0;
    tunnel_db_entry_t old_mlnx_tunnel_db_entry;

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

    sai_db_read_lock();
    sai_status = mlnx_get_tunnel_db_entry(sai_tunnel_obj_id, &old_mlnx_tunnel_db_entry);
    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
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
        SX_LOG_ERR("Error adding vxlan tunnel map for sai tunnel obj %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    if (TUNNEL_ENCAP == (long)arg) {
        g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_encap_cnt = value->objlist.count;
        memcpy(g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_encap_id_array,
               value->objlist.list,
               value->objlist.count * sizeof(sai_object_id_t));
    } else if (TUNNEL_DECAP == (long)arg) {
        g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_decap_cnt = value->objlist.count;
        memcpy(g_sai_db_ptr->tunnel_db[sai_tunnel_db_idx].sai_tunnel_map_decap_id_array,
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
    sai_status_t          sai_status   = SAI_STATUS_FAILURE;
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
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_tunnel_vxlan_mapper_set(key->key.object_id, value, arg))) {
            SX_LOG_ERR("Error getting ipinip ecn mapper\n");
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

static sai_status_t mlnx_convert_sai_tunnel_type_to_sx(_In_ sai_tunnel_type_t  sai_type,
                                                       _Out_ sx_tunnel_type_e *sx_type)
{
    SX_LOG_ENTER();
    switch (sai_type) {
    case SAI_TUNNEL_TYPE_IPINIP:
        *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4;
        break;

    case SAI_TUNNEL_TYPE_IPINIP_GRE:
        *sx_type = SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE;
        break;

    case SAI_TUNNEL_TYPE_VXLAN:
        *sx_type = SX_TUNNEL_TYPE_NVE_VXLAN;
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
    switch (sx_tunnel_type) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
        *sai_type = SAI_TUNNEL_TYPE_IPINIP;
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
        *sai_type = SAI_TUNNEL_TYPE_IPINIP_GRE;
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
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
        if (sdk_tunnel_id == g_sai_db_ptr->tunnel_db[tunnel_idx].sx_tunnel_id) {
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
    sai_status_t sai_status                     = SAI_STATUS_FAILURE;
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

    if (!g_sai_db_ptr->mlnx_tunneltable[internal_tunneltable_entry_idx].in_use) {
        SX_LOG_ERR("Non-exist internal tunnel table entry idx: %d\n", internal_tunneltable_entry_idx);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    memcpy(sdk_tunnel_decap_key,
           &g_sai_db_ptr->mlnx_tunneltable[internal_tunneltable_entry_idx].sdk_tunnel_decap_key,
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
    uint32_t     idx        = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    for (idx = MLNX_TUNNEL_MAP_MIN; idx < MLNX_TUNNEL_MAP_MAX; idx++) {
        if (!g_sai_db_ptr->mlnx_tunnel_map[idx].in_use) {
            *tunnel_map_idx = idx;
            sai_status      = SAI_STATUS_SUCCESS;
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
    const sai_attribute_value_t *tunnel_map_type = NULL, *tunnel_map_list = NULL;
    uint32_t                     attr_idx        = 0;
    sai_status_t                 sai_status      = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ATTR_TYPE, &tunnel_map_type, &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    mlnx_tunnel_map->tunnel_map_type = tunnel_map_type->s32;

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST, &tunnel_map_list,
                                 &attr_idx))) {
        if (tunnel_map_list->tunnelmap.count > MLNX_TUNNEL_MAP_LIST_MAX) {
            SX_LOG_ERR("Tunnel map overflow: size %u is greater than maxium size %u\n",
                       tunnel_map_list->tunnelmap.count, MLNX_TUNNEL_MAP_LIST_MAX);
            SX_LOG_EXIT();
            return SAI_STATUS_BUFFER_OVERFLOW;
        }

        mlnx_tunnel_map->tunnel_map_list_count = tunnel_map_list->tunnelmap.count;
        memcpy(mlnx_tunnel_map->tunnel_map_list, tunnel_map_list->tunnelmap.list,
               tunnel_map_list->tunnelmap.count * sizeof(sai_tunnel_map_t));
    }

    mlnx_tunnel_map->tunnel_cnt = 0;

    mlnx_tunnel_map->in_use = true;

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_tunnel_map(_Out_ sai_object_id_t      *sai_tunnel_map_obj_id,
                                           _In_ sai_object_id_t        switch_id,
                                           _In_ uint32_t               attr_count,
                                           _In_ const sai_attribute_t *attr_list)
{
    char              list_str[MAX_LIST_VALUE_STR_LEN];
    sai_status_t      sai_status     = SAI_STATUS_SUCCESS;
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
    SX_LOG_NTC("SAI Tunnel map attributes: %s\n", list_str);

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
        memset(&g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx], 0,
               sizeof(mlnx_tunnel_map_t));
        SX_LOG_ERR("Error creating sai tunnel map obj id from tunnel map idx %d\n",
                   tunnel_map_idx);
        goto cleanup;
    }

    memcpy(&g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx], &mlnx_tunnel_map, sizeof(mlnx_tunnel_map_t));

    SX_LOG_NTC("Created SAI tunnel map obj id: %" PRIx64 "\n", *sai_tunnel_map_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_remove_tunnel_map(_In_ const sai_object_id_t sai_tunnel_map_obj_id)
{
    sai_status_t sai_status     = SAI_STATUS_FAILURE;
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

    if (g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].in_use) {
        if (0 < g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_cnt) {
            SX_LOG_ERR("This tunnel map is still used by %d other tunnel(s)\n",
                       g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_cnt);
            sai_status = SAI_STATUS_OBJECT_IN_USE;
            goto cleanup;
        }
        if (0 < g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_cnt) {
            SX_LOG_ERR("This tunnel map is still used by %d other tunnel map entry(s)\n",
                       g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_cnt);
            sai_status = SAI_STATUS_OBJECT_IN_USE;
            goto cleanup;
        }
        memset(&g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx], 0, sizeof(mlnx_tunnel_map_t));
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
static sai_status_t mlnx_sai_tunnel_to_sx_tunnel_id(_In_ sai_object_id_t  sai_tunnel_id,
                                                    _Out_ sx_tunnel_id_t *sx_tunnel_id)
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

    *sx_tunnel_id = g_sai_db_ptr->tunnel_db[tunnel_db_idx].sx_tunnel_id;
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
    sai_status_t   sai_status;
    sx_status_t    sx_status;
    sx_tunnel_id_t sx_tunnel_id;

    SX_LOG_ENTER();

    if (!sx_tunnel_attr) {
        SX_LOG_ERR("NULL sx_tunnel_attr\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(sai_tunnel_id, &sx_tunnel_id))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SX_STATUS_SUCCESS != (sx_status = sx_api_tunnel_get(gh_sdk, sx_tunnel_id, sx_tunnel_attr))) {
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_ERR("Error getting sx tunnel for sx tunnel id %d, sx status: %s\n", sx_tunnel_id,
                   SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_EXIT();
    return sai_status;
}

/*
 *  Callers need to lock around this method
 */
static sai_status_t mlnx_sai_get_tunnel_cos_data(_In_ sai_object_id_t        sai_tunnel_id,
                                                 _Out_ sx_tunnel_cos_data_t *sx_tunnel_cos_data)
{
    sai_status_t   sai_status;
    sx_status_t    sx_status;
    sx_tunnel_id_t sx_tunnel_id;

    SX_LOG_ENTER();

    if (!sx_tunnel_cos_data) {
        SX_LOG_ERR("NULL sx_tunnel_cos_data\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(sai_tunnel_id, &sx_tunnel_id))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SX_STATUS_SUCCESS != (sx_status = sx_api_tunnel_cos_get(gh_sdk, sx_tunnel_id, sx_tunnel_cos_data))) {
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_ERR("Error getting sx tunnel cos data for sx tunnel id %d, sx status: %s\n", sx_tunnel_id,
                   SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_EXIT();
    return sai_status;
}

/*
 *  Callers need to lock around this method
 */
static sai_status_t mlnx_sai_reserve_tunnel_db_item(_In_ sx_tunnel_id_t sx_tunnel_id,
                                                    _Out_ uint32_t     *tunnel_db_idx)
{
    uint32_t ii;

    SX_LOG_ENTER();
    if (!tunnel_db_idx) {
        SX_LOG_ERR("NULL tunnel_db_idx\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    for (ii = 0; ii < MAX_TUNNEL_DB_SIZE; ii++) {
        if (!g_sai_db_ptr->tunnel_db[ii].is_used) {
            g_sai_db_ptr->tunnel_db[ii].is_used      = true;
            g_sai_db_ptr->tunnel_db[ii].sx_tunnel_id = sx_tunnel_id;
            *tunnel_db_idx                           = ii;
            SX_LOG_DBG("tunnel db: reserved slot:%d, sx_tunnel_id:%d\n", ii, sx_tunnel_id);
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
static sai_status_t mlnx_sai_tunnel_create_tunnel_object_id(_In_ sx_tunnel_id_t    sx_tunnel_id,
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
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_reserve_tunnel_db_item(sx_tunnel_id, &tunnel_db_idx))) {
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
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    const bool                   is_ipinip = (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
                                             (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type);

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_TTL_MODE, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL:
            /*sdk_encap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_COPY_E;*/
            SX_LOG_ERR("Unsupported SAI tunnel ttl type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
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
        sdk_encap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_COPY_E;
    }

    sdk_encap_ttl_data_attrib->direction = SX_TUNNEL_DIRECTION_ENCAP;

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_TTL_VAL, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        /* switch (sdk_encap_ttl_data_attrib->ttl_cmd) {
         *  case SX_TUNNEL_TTL_CMD_COPY_E:
         *    SX_LOG_ERR("Tunnel encap ttl val can only be set for pipe model\n");
         *    break;
         *  case SX_TUNNEL_TTL_CMD_SET_E:
         *    sdk_encap_ttl_data_attrib->ttl_value = attr->u8;
         *    break;
         *  default:
         *    SX_LOG_ERR("Unsupported SAI tunnel ttl type %d\n", sdk_encap_ttl_data_attrib->ttl_cmd);
         *    SX_LOG_EXIT();
         *    return SAI_STATUS_NOT_SUPPORTED;
         *    break;
         *  }
         *  } else {
         *  switch (sdk_encap_ttl_data_attrib->ttl_cmd) {
         *  case SX_TUNNEL_TTL_CMD_COPY_E:
         *    break;
         *  case SX_TUNNEL_TTL_CMD_SET_E:
         *    SX_LOG_ERR("Missing encap TTL value for encap ttl pipe model\n");
         *    SX_LOG_EXIT();
         *    return SAI_STATUS_FAILURE;
         *    break;
         *  default:
         *    SX_LOG_ERR("Unsupported sdk tunnel ttl cmd%d\n", sdk_encap_ttl_data_attrib->ttl_cmd);
         *    SX_LOG_EXIT();
         *    return SAI_STATUS_NOT_SUPPORTED;
         *    break;
         *  }*/
        SX_LOG_ERR("Unsupported SAI tunnel ttl val\n");
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_SUPPORTED;
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
        sdk_decap_ttl_data_attrib->ttl_cmd = SX_TUNNEL_TTL_CMD_COPY_E;
    }

    sdk_decap_ttl_data_attrib->direction = SX_TUNNEL_DIRECTION_DECAP;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_fill_tunnel_decap_standard_ecn(_Inout_ sx_tunnel_cos_data_t *sdk_decap_cos_data)
{
    const uint8_t non_ect = 0;
    const uint8_t ect0    = 1;
    const uint8_t ect1    = 2;
    const uint8_t ce      = 3;

    SX_LOG_ENTER();

    if (NULL == sdk_decap_cos_data) {
        SX_LOG_ERR("Null pointer sdk_decap_cos_data\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    /* SX_TRAP_PRIORITY_LOW:  triggers TRAP_ID_DECAP_ECN0, default action FORWARD
    *  SX_TRAP_PRIORITY_HIGH: triggers TRAP_ID_DECAP_ECN1, default action DROP */

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][non_ect].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][non_ect].egress_ecn  = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].valid          = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].egress_ecn     = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].trap_enable    = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect0].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].valid          = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].egress_ecn     = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].trap_enable    = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ect1].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].valid          = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].egress_ecn     = non_ect;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].trap_enable    = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[non_ect][ce].trap_attr.prio = SX_TRAP_PRIORITY_HIGH;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][non_ect].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][non_ect].egress_ecn  = ect0;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect0].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect0].egress_ecn  = ect0;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect0].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect1].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect1].egress_ecn  = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ect1].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ce].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ce].egress_ecn  = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect0][ce].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][non_ect].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][non_ect].egress_ecn  = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].valid          = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].egress_ecn     = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].trap_enable    = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect0].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect1].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect1].egress_ecn  = ect1;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ect1].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ce].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ce].egress_ecn  = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ect1][ce].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][non_ect].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][non_ect].egress_ecn  = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][non_ect].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect0].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect0].egress_ecn  = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect0].trap_enable = false;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].valid          = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].egress_ecn     = ce;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].trap_enable    = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ect1].trap_attr.prio = SX_TRAP_PRIORITY_LOW;

    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ce].valid       = true;
    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[ce][ce].egress_ecn  = ce;
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
    sai_status_t sai_status     = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_idx = 0;
    uint32_t     ii             = 0;
    uint8_t      oecn_key       = 0;
    uint8_t      oecn_value     = 0;
    uint8_t      uecn_key       = 0;
    uint8_t      uecn_value     = 0;

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

    for (ii = g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_head_idx;
         ii != MLNX_TUNNEL_MAP_ENTRY_INVALID;
         ii = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].next_tunnel_map_entry_idx) {
        if (sai_mapper_obj_id == g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_id) {
            if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
                switch (g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type) {
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
                        g_sai_db_ptr->mlnx_tunnel_map_entry[ii].oecn_key;
                    uecn_value =
                        g_sai_db_ptr->mlnx_tunnel_map_entry[ii].uecn_value;
                    sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[oecn_key].valid      = true;
                    sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[oecn_key].egress_ecn = uecn_value;
                    break;

                default:
                    SX_LOG_ERR("sai tunnel map type for encap should be %d but getting %d\n",
                               SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN,
                               g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type);
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
                switch (g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type) {
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
                        g_sai_db_ptr->mlnx_tunnel_map_entry[ii].uecn_key;
                    oecn_key =
                        g_sai_db_ptr->mlnx_tunnel_map_entry[ii].oecn_key;
                    oecn_value =
                        g_sai_db_ptr->mlnx_tunnel_map_entry[ii].oecn_value;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_key][uecn_key].valid      = true;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_key][uecn_key].egress_ecn =
                        oecn_value;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_key][uecn_key].trap_enable = false;
                    break;

                default:
                    SX_LOG_ERR("sai tunnel map type for decap should be %d but getting %d\n",
                               SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN,
                               g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type);
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            }
        }
    }

    if (is_ipinip) {
        g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_cnt++;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_fill_tunnel_user_defined_ecn(_In_ bool                   is_ipinip,
                                                          _In_ tunnel_db_entry_t     *mlnx_tunnel_db_entry,
                                                          _In_ tunnel_direction_type  sai_tunnel_map_direction,
                                                          _Out_ sx_tunnel_cos_data_t *sdk_encap_cos_data,
                                                          _Out_ sx_tunnel_cos_data_t *sdk_decap_cos_data)
{
    uint32_t          ii                = 0;
    sai_object_id_t   sai_mapper_obj_id = SAI_NULL_OBJECT_ID;
    sai_status_t      sai_status        = SAI_STATUS_FAILURE;
    uint32_t          tunnel_map_cnt    = 0;
    sai_object_type_t sai_obj_type      = SAI_OBJECT_TYPE_NULL;

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
                                                  _In_ tunnel_db_entry_t     *mlnx_tunnel_db_entry,
                                                  _Out_ sx_tunnel_cos_data_t *sdk_encap_cos_data,
                                                  _Out_ sx_tunnel_cos_data_t *sdk_decap_cos_data,
                                                  _Out_ bool                 *has_encap_attr,
                                                  _Out_ bool                 *has_decap_attr)
{
    sai_status_t                 sai_status              = SAI_STATUS_FAILURE;
    sai_status_t                 encap_mapper_sai_status = SAI_STATUS_FAILURE;
    sai_status_t                 decap_mapper_sai_status = SAI_STATUS_FAILURE;
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    uint32_t                     uecn_idx  = 0;
    uint32_t                     oecn_idx  = 0;
    const bool                   is_ipinip = (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
                                             (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type);

    SX_LOG_ENTER();

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE, &attr, &attr_idx);
    if (SAI_STATUS_SUCCESS == sai_status) {
        switch (attr->s32) {
        case SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL:
            sdk_encap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_PRESERVE_E;
            sdk_encap_cos_data->dscp_action  = SX_COS_DSCP_ACTION_COPY_E;
            break;

        case SAI_TUNNEL_DSCP_MODE_PIPE_MODEL:
            sdk_encap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_ENABLE_E;
            sdk_encap_cos_data->dscp_action  = SX_COS_DSCP_ACTION_SET_E;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel dscp type %d\n", attr->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
            break;
        }
        *has_encap_attr = true;
    } else {
        sdk_encap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_PRESERVE_E;
        sdk_encap_cos_data->dscp_action  = SX_COS_DSCP_ACTION_COPY_E;
    }

    sdk_encap_cos_data->param_type            = SX_TUNNEL_COS_PARAM_TYPE_ENCAP_E;
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
            sdk_decap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_PRESERVE_E;
            sdk_decap_cos_data->dscp_action  = SX_COS_DSCP_ACTION_COPY_E;
            break;

        case SAI_TUNNEL_DSCP_MODE_PIPE_MODEL:
            sdk_decap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_PRESERVE_E;
            sdk_decap_cos_data->dscp_action  = SX_COS_DSCP_ACTION_PRESERVE_E;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel dscp type %d\n", attr->s32);
            break;
        }
    } else {
        sdk_decap_cos_data->dscp_rewrite = SX_COS_DSCP_REWRITE_PRESERVE_E;
        sdk_decap_cos_data->dscp_action  = SX_COS_DSCP_ACTION_COPY_E;
    }

    sdk_decap_cos_data->param_type            = SX_TUNNEL_COS_PARAM_TYPE_DECAP_E;
    sdk_decap_cos_data->update_priority_color = false;
    sdk_decap_cos_data->prio_color.priority   = 0;
    sdk_decap_cos_data->prio_color.color      = 0;
    sdk_decap_cos_data->dscp_value            = 0;

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
                sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[uecn_idx].valid      = true;
                sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[uecn_idx].egress_ecn = uecn_idx;
            }
            break;

        case SAI_TUNNEL_ENCAP_ECN_MODE_USER_DEFINED:
            assert(SAI_STATUS_SUCCESS == encap_mapper_sai_status);
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
            sdk_encap_cos_data->cos_ecn_params.ecn_encap.ecn_encap_map[uecn_idx].valid      = true;
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
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_idx][uecn_idx].valid      = true;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_idx][uecn_idx].egress_ecn =
                        uecn_idx;
                    sdk_decap_cos_data->cos_ecn_params.ecn_decap.ecn_decap_map[oecn_idx][uecn_idx].trap_enable = false;
                }
            }
            break;

        case SAI_TUNNEL_DECAP_ECN_MODE_USER_DEFINED:
            assert(SAI_STATUS_SUCCESS == decap_mapper_sai_status);
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
                                                    _In_ sai_tunnel_type_t                  sai_tunnel_type,
                                                    _Out_ sx_tunnel_ipinip_p2p_attribute_t *sdk_ipinip_p2p_attrib,
                                                    _Out_ sx_tunnel_ttl_data_t             *sdk_encap_ttl_data_attrib,
                                                    _Out_ sx_tunnel_ttl_data_t             *sdk_decap_ttl_data_attrib,
                                                    _Out_ sx_tunnel_cos_data_t             *sdk_encap_cos_data,
                                                    _Out_ sx_tunnel_cos_data_t             *sdk_decap_cos_data,
                                                    _Out_ bool                             *has_encap_attr,
                                                    _Out_ bool                             *has_decap_attr,
                                                    _Out_ sai_object_id_t                  *underlay_rif,
                                                    _Out_ tunnel_db_entry_t                *mlnx_tunnel_db_entry)
{
    sai_status_t                 sai_status = SAI_STATUS_FAILURE;
    uint32_t                     data;
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    sx_router_id_t               sdk_vrid;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, &attr, &attr_idx))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_object_to_type(attr->oid, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }
        sdk_ipinip_p2p_attrib->overlay_rif = (sx_router_interface_t)data;
    } else {
        SX_LOG_ERR("overlay interface should be specified on creating ip in ip type tunnel\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, &attr, &attr_idx))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_object_to_type(attr->oid, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }
        sdk_ipinip_p2p_attrib->underlay_rif = (sx_router_interface_t)data;

        *underlay_rif = attr->oid;

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_get_sx_vrid_from_sx_rif((sx_router_interface_t)data, &sdk_vrid))) {
            SX_LOG_ERR("mlnx_sai_get_sx_vrid_from_sx_rif failed\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        sdk_ipinip_p2p_attrib->encap.underlay_vrid = sdk_vrid;
    } else {
        SX_LOG_ERR("underlay interface should be specified on creating ip in ip type tunnel\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }

    sdk_ipinip_p2p_attrib->underlay_domain_type = SX_TUNNEL_UNDERLAY_DOMAIN_TYPE_VRID;

    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_SRC_IP, &attr, &attr_idx))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_translate_sai_ip_address_to_sdk(&attr->ipaddr,
                                                               &sdk_ipinip_p2p_attrib->encap.underlay_sip))) {
            SX_LOG_ERR("Error setting src ip on creating tunnel table\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        *has_encap_attr = true;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sdk_fill_tunnel_ttl_data(attr_count,
                                                    attr_list,
                                                    sai_tunnel_type,
                                                    sdk_encap_ttl_data_attrib,
                                                    sdk_decap_ttl_data_attrib,
                                                    has_encap_attr,
                                                    has_decap_attr))) {
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
                                                    has_encap_attr,
                                                    has_decap_attr))) {
        SX_LOG_ERR("Error fill sdk tunnel cos data\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    assert((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
           (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type));

    if (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) {
        sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, &attr, &attr_idx);
        if (SAI_STATUS_SUCCESS == sai_status) {
            SX_LOG_ERR("encap gre key valid are only supported for ip in ip gre on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
        }

        sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, &attr, &attr_idx);
        if (SAI_STATUS_SUCCESS == sai_status) {
            SX_LOG_ERR("encap gre key are only supported for ip in ip gre on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_SUPPORTED;
        }
    } else if (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type) {
        sdk_ipinip_p2p_attrib->decap.gre_check_key = false;

        if (SAI_STATUS_SUCCESS ==
            (sai_status =
                 find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, &attr, &attr_idx))) {
            if (attr->booldata) {
                sdk_ipinip_p2p_attrib->encap.gre_mode = SX_TUNNEL_IPINIP_GRE_MODE_ENABLED_WITH_KEY;

                if (SAI_STATUS_SUCCESS ==
                    (sai_status =
                         find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, &attr,
                                             &attr_idx))) {
                    sdk_ipinip_p2p_attrib->encap.gre_key = attr->u32;
                } else {
                    SX_LOG_ERR("gre key is missing when encap gre key valid is set to true\n");
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            } else {
                sdk_ipinip_p2p_attrib->encap.gre_mode = SX_TUNNEL_IPINIP_GRE_MODE_ENABLED;
                sdk_ipinip_p2p_attrib->encap.gre_key  = 0;
            }
            *has_encap_attr = true;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_fill_sx_ipinip_p2p_tunnel_data(_In_ sai_tunnel_type_t       sai_tunnel_type,
                                                            _In_ uint32_t                attr_count,
                                                            _In_ const sai_attribute_t  *attr_list,
                                                            _Out_ sx_tunnel_attribute_t *sx_tunnel_attribute,
                                                            _Out_ sx_tunnel_ttl_data_t  *sdk_encap_ttl_data_attrib,
                                                            _Out_ sx_tunnel_ttl_data_t  *sdk_decap_ttl_data_attrib,
                                                            _Out_ sx_tunnel_cos_data_t  *sdk_encap_cos_data,
                                                            _Out_ sx_tunnel_cos_data_t  *sdk_decap_cos_data,
                                                            _Out_ sai_object_id_t       *underlay_rif,
                                                            _Out_ tunnel_db_entry_t     *mlnx_tunnel_db_entry)
{
    sai_status_t                      sai_status;
    sx_tunnel_type_e                  sx_type;
    bool                              has_encap_attr = false;
    bool                              has_decap_attr = false;
    sx_tunnel_ipinip_p2p_attribute_t *sdk_ipinip_p2p_attrib;

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

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_convert_sai_tunnel_type_to_sx(sai_tunnel_type, &sx_type))) {
        SX_LOG_ERR("Error converting sai tunnel type to sdk tunnel type\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    if ((SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4 != sx_type) &&
        (SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE != sx_type)) {
        SX_LOG_ERR("Create sai tunnel using none ip in ip sx type: %d\n", sx_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sx_tunnel_attribute->type = sx_type;

    if (SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) {
        sdk_ipinip_p2p_attrib = &sx_tunnel_attribute->attributes.ipinip_p2p;
    } else if (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type) {
        sdk_ipinip_p2p_attrib = &sx_tunnel_attribute->attributes.ipinip_p2p_gre;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sdk_fill_ipinip_p2p_attrib(attr_count,
                                                      attr_list,
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
static sai_status_t mlnx_bridge_vport_set(_In_ sai_object_id_t  sai_tunnel_obj_id,
                                          _In_ sx_bridge_id_t   sx_bridge_id,
                                          _In_ sx_port_log_id_t sx_bridge_port_id,
                                          _In_ sai_vlan_id_t    vlan_id)
{
    sx_status_t      sdk_status    = SX_STATUS_ERROR;
    sai_status_t     sai_status    = SAI_STATUS_FAILURE;
    uint32_t         tunnel_db_idx = 0;
    sx_port_log_id_t sx_log_vport  = 0;

    SX_LOG_ENTER();

    /* TODO: change the logic here after SAI bridge port being officially introduced */
    if (SX_STATUS_SUCCESS !=
        (sdk_status =
             sx_api_port_vport_set(gh_sdk, SX_ACCESS_CMD_ADD, sx_bridge_port_id,
                                   vlan_id, &sx_log_vport))) {
        SX_LOG_ERR("Error setting vport of port, SX STATUS: %s\n", SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sdk_status);
    }

    if (SX_STATUS_SUCCESS !=
        (sdk_status = sx_api_port_state_set(gh_sdk, sx_log_vport, SX_PORT_ADMIN_STATUS_UP))) {
        SX_LOG_ERR("Error setting vport admin state, SX STATUS: %s\n", SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sdk_status);
    }

    if (SX_STATUS_SUCCESS !=
        (sdk_status = sx_api_bridge_vport_set(gh_sdk, SX_ACCESS_CMD_ADD, sx_bridge_id, sx_log_vport))) {
        SX_LOG_ERR("Error setting sx bridge vport, SX STATUS: %s\n", SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sdk_status);
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_db_idx))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    g_sai_db_ptr->tunnel_db[tunnel_db_idx].dot1q_vport_set = true;
    g_sai_db_ptr->tunnel_db[tunnel_db_idx].dot1q_vport_id = sx_log_vport;

    SX_LOG_DBG("Set bridge port for bridge id %x\n", sx_bridge_id);
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_tunnel_1Qbridge_get(_Out_ sx_bridge_id_t *sx_bridge_id)
{
    SX_LOG_ENTER();

    if (NULL == sx_bridge_id) {
        SX_LOG_ERR("sx_bridge_id is NULL pointer\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_db_read_lock();

    *sx_bridge_id = g_sai_db_ptr->sx_bridge_id;

    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_tunnel_1Dbridge_get(_In_ sai_object_id_t    sai_bridge_id,
                                                 _Out_ sx_bridge_id_t   *sx_bridge_id)
{
    mlnx_object_id_t mlnx_bridge_id = {0};
    sai_status_t     sai_status    = SAI_STATUS_FAILURE;
    SX_LOG_ENTER();

    if (NULL == sx_bridge_id) {
        SX_LOG_ERR("sx_bridge_id is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    sai_status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, sai_bridge_id, &mlnx_bridge_id);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error getting mlnx object id from bridge id %"PRIx64"\n", sai_bridge_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    *sx_bridge_id = mlnx_bridge_id.id.bridge_id;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_tunnel_map_entry_vlan_vni_bridge_set(_In_ sai_object_id_t       sai_mapper_obj_id,
                                                                  _In_ tunnel_direction_type sai_tunnel_map_direction,
                                                                  _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                                  _In_ sx_tunnel_id_t        sx_tunnel_id,
                                                                  _In_ sx_port_log_id_t      sx_bridge_port_id,
                                                                  _In_ sx_access_cmd_t       cmd)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_status_t           sdk_status = SX_STATUS_ERROR;
    sx_tunnel_map_entry_t sx_tunnel_map_entry;
    const uint32_t        sx_tunnel_map_entry_cnt = 1;
    sx_bridge_id_t        sx_bridge_id            = 0;
    sai_vlan_id_t         vlan_id                 = 1;
    uint32_t              vni_id                  = 0;
    uint32_t              ii                      = 0;
    uint32_t              tunnel_map_idx          = 0;

    SX_LOG_ENTER();

    assert((SX_ACCESS_CMD_ADD == cmd) || (SX_ACCESS_CMD_DELETE == cmd));

    /* use .1Q bridge as default bridge */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_tunnel_1Qbridge_get(&sx_bridge_id))) {
        SX_LOG_ERR("fail to get sx bridge id\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(sai_mapper_obj_id, &tunnel_map_idx))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    for (ii = g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_head_idx;
         ii != MLNX_TUNNEL_MAP_ENTRY_INVALID;
         ii = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].next_tunnel_map_entry_idx) {
        if (sai_mapper_obj_id == g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_id) {
            if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
                switch (g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type) {
                case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
                case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
                    break;

                case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
                    continue;
                    break;

                default:
                    sai_db_unlock();
                    SX_LOG_ERR("sai tunnel map type for encap should be %d or %d but getting %d\n",
                               SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI,
                               SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI,
                               g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type);
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
                switch (g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type) {
                case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
                case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
                    break;

                case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
                    continue;
                    break;

                default:
                    sai_db_unlock();
                    SX_LOG_ERR("sai tunnel map type for decap should be %d or %d but getting %d\n",
                               SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID,
                               SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF,
                               g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type);
                    SX_LOG_EXIT();
                    return SAI_STATUS_FAILURE;
                }
            }

            switch (g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type) {
            case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
                vlan_id = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].vlan_id_key;
                vni_id  = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].vni_id_value;
                break;

            case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
                vni_id  = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].vni_id_key;
                vlan_id = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].vlan_id_value;
                break;

            case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
                if (SAI_STATUS_SUCCESS !=
                    (sai_status =
                         mlnx_sai_tunnel_1Dbridge_get(g_sai_db_ptr->mlnx_tunnel_map_entry[ii].bridge_id_key,
                                                      &sx_bridge_id))) {
                    sai_db_unlock();
                    SX_LOG_ERR("missing bridge port\n");
                    SX_LOG_EXIT();
                    return sai_status;
                }
                vni_id = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].vni_id_value;
                break;

            case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
                if (SAI_STATUS_SUCCESS !=
                    (sai_status =
                         mlnx_sai_tunnel_1Dbridge_get(g_sai_db_ptr->mlnx_tunnel_map_entry[ii].bridge_id_value,
                                                      &sx_bridge_id))) {
                    sai_db_unlock();
                    SX_LOG_ERR("missing bridge port\n");
                    SX_LOG_EXIT();
                    return sai_status;
                }
                vni_id = g_sai_db_ptr->mlnx_tunnel_map_entry[ii].vni_id_key;
                break;

            default:
                sai_db_unlock();
                SX_LOG_ERR("Unsupported SAI tunnel map type %d\n",
                           g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type);
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
                break;
            }

            if ((SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI == g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type) ||
                (SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID == g_sai_db_ptr->mlnx_tunnel_map_entry[ii].tunnel_map_type)) {
                if (SAI_STATUS_SUCCESS !=
                    (sai_status = mlnx_bridge_vport_set(sai_tunnel_obj_id,
                                                        sx_bridge_id,
                                                        sx_bridge_port_id,
                                                        vlan_id))) {
                    sai_db_unlock();
                    SX_LOG_ERR("Error setting bridge vport\n");
                    SX_LOG_EXIT();
                    return sai_status;
                }
            }

            sx_tunnel_map_entry.type                 = SX_TUNNEL_TYPE_NVE_VXLAN;
            sx_tunnel_map_entry.params.nve.bridge_id = sx_bridge_id;
            sx_tunnel_map_entry.params.nve.vni       = vni_id;
            sx_tunnel_map_entry.params.nve.direction = SX_TUNNEL_MAP_DIR_BIDIR;

            if (SX_STATUS_SUCCESS !=
                (sdk_status = sx_api_tunnel_map_set(gh_sdk,
                                                    cmd,
                                                    sx_tunnel_id,
                                                    &sx_tunnel_map_entry,
                                                    sx_tunnel_map_entry_cnt))) {
                sai_db_unlock();
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error adding tunnel map associated with sx tunnel id %d, sx status %s\n",
                           sx_tunnel_id, SX_STATUS_MSG(sdk_status));
                SX_LOG_EXIT();
                return sai_status;
            }
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_tunnel_map_vlan_vni_bridge_set(_In_ sai_object_id_t       sai_mapper_obj_id,
                                                            _In_ tunnel_direction_type sai_tunnel_map_direction,
                                                            _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                            _In_ sx_tunnel_id_t        sx_tunnel_id,
                                                            _In_ sx_port_log_id_t      sx_bridge_port_id,
                                                            _In_ sx_access_cmd_t       cmd)
{
    sai_status_t          sai_status            = SAI_STATUS_FAILURE;
    sx_status_t           sdk_status            = SX_STATUS_ERROR;
    uint32_t              sai_tunnel_mapper_idx = 0;
    mlnx_tunnel_map_t     mlnx_tunnel_map;
    sai_vlan_id_t         vlan_id = 1;
    uint32_t              vni_id  = 0;
    sx_tunnel_map_entry_t sx_tunnel_map_entry;
    const uint32_t        sx_tunnel_map_entry_cnt = 1;
    sx_bridge_id_t        sx_bridge_id            = 0;
    uint32_t              ii                      = 0;

    SX_LOG_ENTER();

    assert((SX_ACCESS_CMD_ADD == cmd) || (SX_ACCESS_CMD_DELETE == cmd));

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_get_sai_tunnel_map_db_idx(sai_mapper_obj_id, &sai_tunnel_mapper_idx))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting tunnel mapper db idx from tunnel mapper obj id %" PRIx64 "\n",
                   sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_ACCESS_CMD_ADD == cmd) {
        g_sai_db_ptr->mlnx_tunnel_map[sai_tunnel_mapper_idx].tunnel_cnt++;
    } else if (SX_ACCESS_CMD_DELETE == cmd) {
        assert(0 < g_sai_db_ptr->mlnx_tunnel_map[sai_tunnel_mapper_idx].tunnel_cnt);
        g_sai_db_ptr->mlnx_tunnel_map[sai_tunnel_mapper_idx].tunnel_cnt--;
    }

    sai_db_unlock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_db_param_get_from_db(sai_mapper_obj_id, &mlnx_tunnel_map))) {
        SX_LOG_ERR("fail to get mlnx tunnel map for tunnel map obj id %" PRIx64 "\n", sai_mapper_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (TUNNEL_ENCAP == sai_tunnel_map_direction) {
        switch (mlnx_tunnel_map.tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
        case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
            break;

        case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
            SX_LOG_DBG("Tunnel map type is OECN to UECN for encap\n");
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
            break;

        default:
            SX_LOG_ERR("sai tunnel map type for encap should be %d or %d but getting %d\n",
                       SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI,
                       SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI,
                       mlnx_tunnel_map.tunnel_map_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    } else if (TUNNEL_DECAP == sai_tunnel_map_direction) {
        switch (mlnx_tunnel_map.tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
            break;

        case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
            SX_LOG_DBG("Tunnel map type is UECN OECN to OECN for decap\n");
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
            break;

        default:
            SX_LOG_ERR("sai tunnel map type for decap should be %d or %d but getting %d\n",
                       SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID,
                       SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF,
                       mlnx_tunnel_map.tunnel_map_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    if (0 == mlnx_tunnel_map.tunnel_map_list_count) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_tunnel_map_entry_vlan_vni_bridge_set(sai_mapper_obj_id,
                                                                        sai_tunnel_map_direction,
                                                                        sai_tunnel_obj_id,
                                                                        sx_tunnel_id,
                                                                        sx_bridge_port_id,
                                                                        cmd))) {
            SX_LOG_ERR("Error getting vlan vni id from sai tunnel map obj %" PRIx64 "\n ", sai_mapper_obj_id);
            SX_LOG_EXIT();
            return sai_status;
        }
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_tunnel_1Qbridge_get(&sx_bridge_id))) {
        SX_LOG_ERR("fail to get sx bridge id\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    for (ii = 0; ii < mlnx_tunnel_map.tunnel_map_list_count; ii++) {
        switch (mlnx_tunnel_map.tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
            vlan_id = mlnx_tunnel_map.tunnel_map_list[ii].key.vlan_id;
            vni_id  = mlnx_tunnel_map.tunnel_map_list[ii].value.vni_id;
            break;

        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
            vni_id  = mlnx_tunnel_map.tunnel_map_list[ii].key.vni_id;
            vlan_id = mlnx_tunnel_map.tunnel_map_list[ii].value.vlan_id;
            break;

        default:
            SX_LOG_ERR("Unsupported SAI tunnel map type %d\n", mlnx_tunnel_map.tunnel_map_type);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
            break;
        }

        SX_LOG_DBG("ii: %d\n", ii);

        sai_db_write_lock();
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_bridge_vport_set(sai_tunnel_obj_id,
                                                sx_bridge_id,
                                                sx_bridge_port_id,
                                                vlan_id))) {
            sai_db_unlock();
            SX_LOG_ERR("Error setting bridge vport\n");
            SX_LOG_EXIT();
            return sai_status;
        }
        sai_db_unlock();

        sx_tunnel_map_entry.type                 = SX_TUNNEL_TYPE_NVE_VXLAN;
        sx_tunnel_map_entry.params.nve.bridge_id = sx_bridge_id;
        sx_tunnel_map_entry.params.nve.vni       = vni_id;
        sx_tunnel_map_entry.params.nve.direction = SX_TUNNEL_MAP_DIR_BIDIR;

        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_map_set(gh_sdk,
                                                cmd,
                                                sx_tunnel_id,
                                                &sx_tunnel_map_entry,
                                                sx_tunnel_map_entry_cnt))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error adding tunnel map associated with sx tunnel id %d, sx status %s\n",
                       sx_tunnel_id, SX_STATUS_MSG(sdk_status));
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_create_vxlan_tunnel_map_list(_In_ sai_object_id_t      *sai_tunnel_mapper_list,
                                                          _In_ uint32_t              sai_tunnel_mapper_cnt,
                                                          _In_ tunnel_direction_type sai_tunnel_map_direction,
                                                          _In_ sai_object_id_t       sai_tunnel_obj_id,
                                                          _In_ sx_access_cmd_t       cmd)
{
    sai_object_id_t       sai_mapper_obj_id      = SAI_NULL_OBJECT_ID;
    sai_status_t          sai_status             = SAI_STATUS_FAILURE;
    sai_object_id_t       overlay_bridge_port_id = SAI_NULL_OBJECT_ID;
    sx_port_log_id_t      sx_bridge_port_id      = 0;
    uint32_t              tunnel_db_idx          = 0;
    uint32_t              ii                     = 0;
    sx_tunnel_map_entry_t sx_tunnel_map_entry;
    sx_tunnel_id_t        sx_tunnel_id = 0;
    sai_object_type_t     sai_obj_type = SAI_OBJECT_TYPE_NULL;

    SX_LOG_ENTER();

    memset(&sx_tunnel_map_entry, 0, sizeof(sx_tunnel_map_entry_t));

    if (0 == sai_tunnel_mapper_cnt) {
        SX_LOG_ERR("tunnel mapper cnt is zero\n");
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_db_idx))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    overlay_bridge_port_id = g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_vxlan_overlay_rif;

    sx_tunnel_id = g_sai_db_ptr->tunnel_db[tunnel_db_idx].sx_tunnel_id;

    sai_db_unlock();

    if (SAI_NULL_OBJECT_ID == overlay_bridge_port_id) {
        sx_bridge_port_id = 0;
    } else if (SAI_STATUS_SUCCESS !=
               (sai_status = mlnx_object_to_type(overlay_bridge_port_id, SAI_OBJECT_TYPE_PORT, &sx_bridge_port_id, NULL))) {
        SX_LOG_ERR("Fail to get bridge port for overlay interface\n");
        sx_bridge_port_id = 0;
    }

    for (ii = 0; ii < sai_tunnel_mapper_cnt; ii++) {
        sai_mapper_obj_id = sai_tunnel_mapper_list[ii];

        sai_obj_type = sai_object_type_query(sai_mapper_obj_id);

        if (SAI_OBJECT_TYPE_TUNNEL_MAP == sai_obj_type) {
            if (SAI_STATUS_SUCCESS !=
                (sai_status = mlnx_sai_tunnel_map_vlan_vni_bridge_set(sai_mapper_obj_id,
                                                                      sai_tunnel_map_direction,
                                                                      sai_tunnel_obj_id,
                                                                      sx_tunnel_id,
                                                                      sx_bridge_port_id,
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
                                                       _Out_ tunnel_db_entry_t     *mlnx_tunnel_db_entry)
{
    sai_status_t                 sai_status;
    sx_tunnel_type_e             sx_type;
    uint32_t                     data;
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    bool                         has_encap_attr = false;
    bool                         has_decap_attr = false;
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
    memset(mlnx_tunnel_db_entry, 0, sizeof(tunnel_db_entry_t));

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_convert_sai_tunnel_type_to_sx(sai_tunnel_type, &sx_type))) {
        SX_LOG_ERR("Error converting sai tunnel type to sdk tunnel type\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SX_TUNNEL_TYPE_NVE_VXLAN != sx_type) {
        SX_LOG_ERR("Create sai tunnel using none vxlan sx type: %d\n", sx_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sx_tunnel_attribute->type = sx_type;

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, &attr, &attr_idx))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_object_to_type(attr->oid, SAI_OBJECT_TYPE_PORT, &data, NULL))) {
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }
        mlnx_tunnel_db_entry->sai_vxlan_overlay_rif = attr->oid;
    } else {
        mlnx_tunnel_db_entry->sai_vxlan_overlay_rif = SAI_NULL_OBJECT_ID;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, &attr, &attr_idx))) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_object_to_type(attr->oid, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
            SX_LOG_ERR("underlay interface %"PRIx64" is not rif type\n", attr->oid);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        mlnx_tunnel_db_entry->sai_underlay_rif = attr->oid;

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_get_sx_vrid_from_sx_rif((sx_router_interface_t)data, &sdk_vrid))) {
            SX_LOG_ERR("mlnx_sai_get_sx_vrid_from_sx_rif failed\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        sx_tunnel_attribute->attributes.vxlan.encap.underlay_vrid = sdk_vrid;
    } else {
        SX_LOG_ERR("underlay interface should be specified on creating vxlan type tunnel\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
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

    sx_tunnel_attribute->attributes.vxlan.underlay_domain_type = SX_TUNNEL_UNDERLAY_DOMAIN_TYPE_VRID;

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
static sai_status_t mlnx_fill_tunnel_db(_In_ sai_object_id_t    sai_tunnel_obj_id,
                                        _In_ tunnel_db_entry_t *mlnx_tunnel_db_entry)
{
    sai_status_t sai_status    = SAI_STATUS_FAILURE;
    uint32_t     tunnel_db_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(sai_tunnel_obj_id, &tunnel_db_idx))) {
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", sai_tunnel_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_vxlan_overlay_rif = mlnx_tunnel_db_entry->sai_vxlan_overlay_rif;
    g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_underlay_rif      = mlnx_tunnel_db_entry->sai_underlay_rif;
    memcpy(g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_encap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_encap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt * sizeof(sai_object_id_t));
    g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_encap_cnt = mlnx_tunnel_db_entry->sai_tunnel_map_encap_cnt;
    g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_decap_cnt = mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt;
    memcpy(g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_decap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_decap_id_array,
           mlnx_tunnel_db_entry->sai_tunnel_map_decap_cnt * sizeof(sai_object_id_t));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_tunnel(_Out_ sai_object_id_t     * sai_tunnel_obj_id,
                                       _In_ sai_object_id_t        switch_id,
                                       _In_ uint32_t               attr_count,
                                       _In_ const sai_attribute_t* attr_list)
{
    SX_LOG_ENTER();
    sai_status_t                 sai_status;
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = { 0 };
    sx_status_t                  sdk_status;
    sx_tunnel_attribute_t        sx_tunnel_attr;
    sx_tunnel_id_t               sx_tunnel_id;
    sai_tunnel_type_t            sai_tunnel_type;
    sx_router_interface_state_t  rif_state;
    bool                         sdk_tunnel_map_created = false;
    bool                         sdk_tunnel_created     = false;
    bool                         sai_db_created         = false;
    tunnel_db_entry_t            mlnx_tunnel_db_entry;
    uint32_t                     tunnel_db_idx = 0;
    tunnel_db_entry_t            sai_tunnel_db_entry;
    sx_tunnel_map_entry_t        sx_tunnel_map_entry[MLNX_TUNNEL_MAP_MAX];
    sx_tunnel_ttl_data_t         sdk_encap_ttl_data_attrib;
    sx_tunnel_ttl_data_t         sdk_decap_ttl_data_attrib;
    sx_tunnel_cos_data_t         sdk_encap_cos_data;
    sx_tunnel_cos_data_t         sdk_decap_cos_data;
    sai_object_id_t              underlay_rif = SAI_NULL_OBJECT_ID;

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
    switch (sai_tunnel_type) {
    case SAI_TUNNEL_TYPE_IPINIP:
    case SAI_TUNNEL_TYPE_IPINIP_GRE:
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       mlnx_sai_fill_sx_ipinip_p2p_tunnel_data(
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
            SX_LOG_EXIT();
            return sai_status;
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
            SX_LOG_EXIT();
            return sai_status;
        }
        break;

    case SAI_TUNNEL_TYPE_MPLS:
        SX_LOG_ERR("Tunnel MPLS type is not supported yet\n");
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;

    default:
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_SUPPORTED;
    }

    if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_set(
                                  gh_sdk,
                                  SX_ACCESS_CMD_CREATE,
                                  &sx_tunnel_attr,
                                  &sx_tunnel_id))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error creating sdk tunnel, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }
    sdk_tunnel_created = true;

    sai_db_write_lock();
    sai_status = mlnx_sai_tunnel_create_tunnel_object_id(sx_tunnel_id, sai_tunnel_obj_id);

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error create tunnel object id from sx tunnel id %d\n", sx_tunnel_id);
        sai_db_unlock();
        goto cleanup;
    }
    sai_db_created = true;

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_db_idx(*sai_tunnel_obj_id, &tunnel_db_idx))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting sai tunnel db idx from sai tunnel id %" PRIx64 "\n", *sai_tunnel_obj_id);
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_tunnel_db_entry(*sai_tunnel_obj_id, &sai_tunnel_db_entry))) {
        sai_db_unlock();
        SX_LOG_ERR("Error getting sai tunnel db entry for sai tunnel obj id %" PRIx64 "\n", *sai_tunnel_obj_id);
        goto cleanup;
    }

    g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_type = sai_tunnel_type;

    sai_db_unlock();

    if ((SX_TUNNEL_DIRECTION_ENCAP == sx_tunnel_attr.direction) ||
        (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_attr.direction)) {
        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                     sx_tunnel_id,
                                                                     &sdk_encap_cos_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting sdk tunnel encap cos, sx status: %s\n", SX_STATUS_MSG(sdk_status));
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    if ((SX_TUNNEL_DIRECTION_DECAP == sx_tunnel_attr.direction) ||
        (SX_TUNNEL_DIRECTION_SYMMETRIC == sx_tunnel_attr.direction)) {
        if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_cos_set(gh_sdk,
                                                                     sx_tunnel_id,
                                                                     &sdk_decap_cos_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting sdk tunnel decap cos, sx status: %s\n", SX_STATUS_MSG(sdk_status));
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_fill_tunnel_db(*sai_tunnel_obj_id, &mlnx_tunnel_db_entry))) {
        sai_db_unlock();
        SX_LOG_ERR("Failed to fill in tunnel db for sai tunnel obj id %" PRIx64 "\n", *sai_tunnel_obj_id);
        goto cleanup;
    }

    if ((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
        (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type)) {
        g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_underlay_rif = underlay_rif;
    }

    sai_db_unlock();

    sdk_tunnel_map_created = true;

    if (SAI_TUNNEL_TYPE_VXLAN == sai_tunnel_type) {
        sai_status = mlnx_sai_create_vxlan_tunnel_map_list(mlnx_tunnel_db_entry.sai_tunnel_map_encap_id_array,
                                                           mlnx_tunnel_db_entry.sai_tunnel_map_encap_cnt,
                                                           TUNNEL_ENCAP,
                                                           *sai_tunnel_obj_id,
                                                           SX_ACCESS_CMD_ADD);
        if (SAI_STATUS_SUCCESS != sai_status) {
            SX_LOG_ERR("Failed to create sai vxlan encap tunnel map list\n");
            goto cleanup;
        }

        sai_status = mlnx_sai_create_vxlan_tunnel_map_list(mlnx_tunnel_db_entry.sai_tunnel_map_decap_id_array,
                                                           mlnx_tunnel_db_entry.sai_tunnel_map_decap_cnt,
                                                           TUNNEL_DECAP,
                                                           *sai_tunnel_obj_id,
                                                           SX_ACCESS_CMD_ADD);
        if (SAI_STATUS_SUCCESS != sai_status) {
            SX_LOG_ERR("Failed to create sai vxlan decap tunnel map list\n");
            goto cleanup;
        }
    }

    SX_LOG_NTC("created tunnel:0x%" PRIx64 "\n", *sai_tunnel_obj_id);

    memset(&rif_state, 0, sizeof(sx_router_interface_state_t));

    rif_state.ipv4_enable = true;
    rif_state.ipv6_enable = true;

    if ((SAI_TUNNEL_TYPE_IPINIP == sai_tunnel_type) ||
        (SAI_TUNNEL_TYPE_IPINIP_GRE == sai_tunnel_type)) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status =
                 sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif,
                                                   &rif_state))) {
            SX_LOG_ERR("Failed to set overlay router interface state - %s.\n", SX_STATUS_MSG(sai_status));
            sai_status = sdk_to_sai(sdk_status);
            goto cleanup;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;

cleanup:
    if (sai_db_created) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_object_to_type(*sai_tunnel_obj_id, SAI_OBJECT_TYPE_TUNNEL, &tunnel_db_idx,
                                              NULL))) {
            SX_LOG_ERR("Invalid sai tunnel obj id: 0x%" PRIx64 "\n", *sai_tunnel_obj_id);
        } else {
            if (tunnel_db_idx >= MAX_TUNNEL_DB_SIZE) {
                SX_LOG_ERR("tunnel db index: %d out of bounds:%d\n", tunnel_db_idx, MAX_TUNNEL_DB_SIZE);
                sai_status = SAI_STATUS_FAILURE;
            } else {
                memset(&g_sai_db_ptr->tunnel_db[tunnel_db_idx], 0, sizeof(tunnel_db_entry_t));
            }
        }
    }

    if (sdk_tunnel_map_created) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status =
                 sx_api_tunnel_map_set(gh_sdk,
                                       SX_ACCESS_CMD_DELETE_ALL,
                                       sx_tunnel_id,
                                       sx_tunnel_map_entry,
                                       0))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error deleting all tunnel map associated with sx tunnel id %d, sx status %s\n",
                       sx_tunnel_id, SX_STATUS_MSG(sdk_status));
        }
    }

    if (sdk_tunnel_created) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_set(gh_sdk,
                                            SX_ACCESS_CMD_DESTROY,
                                            &sx_tunnel_attr,
                                            &sx_tunnel_id))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n", sx_tunnel_id, SX_STATUS_MSG(sdk_status));
        }
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_remove_tunnel(_In_ const sai_object_id_t sai_tunnel_obj_id)
{
    sai_status_t                sai_status    = SAI_STATUS_FAILURE;
    sx_status_t                 sdk_status    = SX_STATUS_ERROR;
    uint32_t                    tunnel_db_idx = 0;
    sx_tunnel_id_t              sx_tunnel_id  = 0;
    sx_tunnel_attribute_t       sx_tunnel_attr;
    sx_router_interface_state_t rif_state;
    sx_tunnel_map_entry_t       sx_tunnel_map_entry;
    sai_object_id_t             sai_tunnel_map_id  = 0;
    uint32_t                    ii                 = 0;
    uint32_t                    sai_tunnel_map_idx = 0;
    sx_port_log_id_t            log_port           = 0;
    sx_port_log_id_t            log_vport          = 0;
    sx_vlan_id_t                vlan_id            = 0;

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

    if (!g_sai_db_ptr->tunnel_db[tunnel_db_idx].is_used) {
        SX_LOG_ERR("Tunnel db ind %d cannot be removed because it is not used\n", tunnel_db_idx);
        sai_status = SAI_STATUS_FAILURE;
        goto cleanup;
    }

    sx_tunnel_id = g_sai_db_ptr->tunnel_db[tunnel_db_idx].sx_tunnel_id;

    memset(&sx_tunnel_attr, 0, sizeof(sx_tunnel_attribute_t));

    if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_get(
                                  gh_sdk,
                                  sx_tunnel_id,
                                  &sx_tunnel_attr))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error getting sx tunnel attr from sx tunnel id %d, sx status: %s\n", sx_tunnel_id,
                   SX_STATUS_MSG(sdk_status));
        goto cleanup;
    }

    memset(&rif_state, 0, sizeof(sx_router_interface_state_t));

    if ((SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE == sx_tunnel_attr.type) ||
        (SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4 == sx_tunnel_attr.type)) {
        rif_state.ipv4_enable = false;
        rif_state.ipv6_enable = false;

        if (SX_STATUS_SUCCESS !=
            (sdk_status =
                 sx_api_router_interface_state_set(gh_sdk, sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif,
                                                   &rif_state))) {
            SX_LOG_ERR("Failed to set overlay router interface state to down - %s.\n", SX_STATUS_MSG(sdk_status));
            sai_status = sdk_to_sai(sdk_status);
            goto cleanup;
        }
    }

    if ((0 != g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_encap_cnt) ||
        (0 != g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_decap_cnt)) {
        if (SX_TUNNEL_TYPE_NVE_VXLAN == sx_tunnel_attr.type) {
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
        }

        for (ii = 0; ii < g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_encap_cnt; ii++) {
            sai_tunnel_map_id = g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_encap_id_array[ii];
            if (SAI_STATUS_SUCCESS !=
                (sai_status =
                     mlnx_get_sai_tunnel_map_db_idx(sai_tunnel_map_id, &sai_tunnel_map_idx))) {
                SX_LOG_ERR("Error getting tunnel mapper db idx from tunnel mapper obj id %" PRIx64 "\n",
                           sai_tunnel_map_id);
                goto cleanup;
            }

            assert(0 < g_sai_db_ptr->mlnx_tunnel_map[sai_tunnel_map_idx].tunnel_cnt);
            g_sai_db_ptr->mlnx_tunnel_map[sai_tunnel_map_idx].tunnel_cnt--;
        }

        for (ii = 0; ii < g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_decap_cnt; ii++) {
            sai_tunnel_map_id = g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_decap_id_array[ii];
            if (SAI_STATUS_SUCCESS !=
                (sai_status =
                     mlnx_get_sai_tunnel_map_db_idx(sai_tunnel_map_id, &sai_tunnel_map_idx))) {
                SX_LOG_ERR("Error getting tunnel mapper db idx from tunnel mapper obj id %" PRIx64 "\n",
                           sai_tunnel_map_id);
                goto cleanup;
            }

            assert(0 < g_sai_db_ptr->mlnx_tunnel_map[sai_tunnel_map_idx].tunnel_cnt);
            g_sai_db_ptr->mlnx_tunnel_map[sai_tunnel_map_idx].tunnel_cnt--;
        }

        memset(g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_encap_id_array, 0,
               sizeof(MLNX_TUNNEL_MAP_MAX));
        g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_encap_cnt = 0;
        memset(g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_decap_id_array, 0,
               sizeof(MLNX_TUNNEL_MAP_MAX));
        g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_tunnel_map_decap_cnt = 0;
    }

    if (SX_STATUS_SUCCESS != (sdk_status = sx_api_tunnel_set(
                                  gh_sdk,
                                  SX_ACCESS_CMD_DESTROY,
                                  &sx_tunnel_attr,
                                  &sx_tunnel_id))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error destroying sx tunnel id %d, sx status: %s\n", sx_tunnel_id, SX_STATUS_MSG(sdk_status));
        goto cleanup;
    }

    /* Remove the following bridge logic after SAI bridge being officially introduced */
    if (SX_TUNNEL_TYPE_NVE_VXLAN == sx_tunnel_attr.type) {
        if (g_sai_db_ptr->tunnel_db[tunnel_db_idx].dot1q_vport_set) {
            log_vport = g_sai_db_ptr->tunnel_db[tunnel_db_idx].dot1q_vport_id;
            if (SX_STATUS_SUCCESS !=
                (sdk_status = sx_api_port_state_set(gh_sdk, log_vport, SX_PORT_ADMIN_STATUS_DOWN))) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error setting vport admin state, SX STATUS: %s\n", SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }

            if (SX_STATUS_SUCCESS != (sdk_status = sx_api_bridge_vport_set(
                                          gh_sdk,
                                          SX_ACCESS_CMD_DELETE_ALL,
                                          g_sai_db_ptr->sx_bridge_id,
                                          log_vport))) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error deleting all vport for sx bridge id %d, sx status: %s\n",
                           g_sai_db_ptr->sx_bridge_id, SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }

            if (SAI_STATUS_SUCCESS !=
                (sai_status = mlnx_object_to_type(g_sai_db_ptr->tunnel_db[tunnel_db_idx].sai_vxlan_overlay_rif,
                                                  SAI_OBJECT_TYPE_PORT,
                                                  &log_port, NULL))) {
            }
            if (SX_STATUS_SUCCESS != (sdk_status = sx_api_port_vport_set(
                                          gh_sdk,
                                          SX_ACCESS_CMD_DELETE_ALL,
                                          log_port,
                                          vlan_id,
                                          &log_vport))) {
                sai_status = sdk_to_sai(sdk_status);
                SX_LOG_ERR("Error deleting all vport for sx bridge id %d, sx status: %s\n",
                           g_sai_db_ptr->sx_bridge_id, SX_STATUS_MSG(sdk_status));
                goto cleanup;
            }
        }
    }

    memset(&g_sai_db_ptr->tunnel_db[tunnel_db_idx], 0, sizeof(tunnel_db_entry_t));

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

/* caller of this function should use read lock to guard the callsite */
static sai_status_t mlnx_create_empty_tunneltable(_Out_ uint32_t *internal_tunneltable_idx)
{
    uint32_t idx = 0;

    SX_LOG_ENTER();

    assert(NULL != g_sai_db_ptr);

    for (idx = 0; idx < MLNX_TUNNELTABLE_SIZE; idx++) {
        if (!g_sai_db_ptr->mlnx_tunneltable[idx].in_use) {
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
    uint32_t     idx        = 0;
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
    uint32_t     sdk_vr_id  = 0;

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
             mlnx_convert_sai_tunnel_type_to_sx(tunneltable_tunnel_type->s32, &sdk_tunnel_decap_key->tunnel_type))) {
        SX_LOG_ERR("Error converting sai tunnel type %d to sdk tunnel type\n", tunneltable_tunnel_type->s32);
        SX_LOG_EXIT();
        return sai_status;
    }

    assert(NULL != tunneltable_tunnel_id);

    sai_db_read_lock();

    sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(tunneltable_tunnel_id->oid, &sdk_tunnel_decap_data->tunnel_id);

    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error coverting sai tunnel id %" PRIx64 " to sx tunnel id\n", tunneltable_tunnel_id->oid);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sdk_tunnel_decap_data->action     = SX_ROUTER_ACTION_FORWARD;
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
    const sai_attribute_value_t *tunneltable_vr_id        = NULL, *tunneltable_type = NULL, *tunneltable_dst_ip = NULL,
    *tunneltable_src_ip                                   = NULL;
    const sai_attribute_value_t *tunneltable_tunnel_type  = NULL, *tunneltable_tunnel_id = NULL;
    uint32_t                     internal_tunneltable_idx = 0;
    sx_tunnel_decap_entry_key_t  sdk_tunnel_decap_key;
    sx_tunnel_decap_entry_data_t sdk_tunnel_decap_data;

    memset(&sdk_tunnel_decap_key, 0, sizeof(sx_tunnel_decap_entry_key_t));
    memset(&sdk_tunnel_decap_data, 0, sizeof(sx_tunnel_decap_entry_data_t));
    sai_status_t sai_status  = SAI_STATUS_FAILURE;
    sx_status_t  sdk_status  = SX_STATUS_ERROR;
    bool         cleanup_sdk = false;
    bool         cleanup_db  = false;

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

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_set_tunnel_table_param(tunneltable_vr_id, tunneltable_type, tunneltable_dst_ip, tunneltable_src_ip,
                                         tunneltable_tunnel_type, tunneltable_tunnel_id,
                                         &sdk_tunnel_decap_key, &sdk_tunnel_decap_data))) {
        SX_LOG_ERR("Failed to set tunnel table param for internal tunnel table idx %d\n", internal_tunneltable_idx);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_STATUS_SUCCESS !=
        (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_CREATE,
                                                    &sdk_tunnel_decap_key,
                                                    &sdk_tunnel_decap_data))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error setting tunnel table entry on create, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_empty_tunneltable(&internal_tunneltable_idx))) {
        SX_LOG_ERR("Failed to create empty tunnel table entry\n");
        cleanup_sdk = true;
        goto cleanup;
    }

    SX_LOG_DBG("Created internal tunnel table entry idx: %d\n", internal_tunneltable_idx);

    memset(&g_sai_db_ptr->mlnx_tunneltable[internal_tunneltable_idx], 0, sizeof(mlnx_tunneltable_t));

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, internal_tunneltable_idx, NULL,
                                sai_tunnel_term_table_entry_obj_id))) {
        SX_LOG_ERR("Error creating sai tunnel table entry id from internal tunnel table entry id %d\n",
                   internal_tunneltable_idx);
        cleanup_db  = true;
        cleanup_sdk = true;
        goto cleanup;
    }

    g_sai_db_ptr->mlnx_tunneltable[internal_tunneltable_idx].in_use = true;
    memcpy(&g_sai_db_ptr->mlnx_tunneltable[internal_tunneltable_idx].sdk_tunnel_decap_key,
           &sdk_tunnel_decap_key,
           sizeof(sx_tunnel_decap_entry_key_t));

    SX_LOG_NTC("Created SAI tunnel table entry obj id: %" PRIx64 "\n", *sai_tunnel_term_table_entry_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    if (cleanup_db) {
        memset(&g_sai_db_ptr->mlnx_tunneltable[internal_tunneltable_idx], 0,
               sizeof(mlnx_tunneltable_t));
    }

    if (cleanup_sdk) {
        if (SX_STATUS_SUCCESS !=
            (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_DESTROY,
                                                        &sdk_tunnel_decap_key,
                                                        &sdk_tunnel_decap_data))) {
            sai_status = sdk_to_sai(sdk_status);
            SX_LOG_ERR("Error setting tunnel table entry on create, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_remove_tunnel_term_table_entry(_In_ const sai_object_id_t sai_tunnel_term_table_entry_obj_id)
{
    sai_status_t                 sai_status               = SAI_STATUS_FAILURE;
    sx_status_t                  sdk_status               = SX_STATUS_ERROR;
    uint32_t                     internal_tunneltable_idx = 0;
    sx_tunnel_decap_entry_key_t  sdk_tunnel_decap_key;
    sx_tunnel_decap_entry_data_t sdk_tunnel_decap_data;

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

    sai_db_read_lock();

    sai_status = mlnx_tunnel_term_table_entry_sdk_param_get(sai_tunnel_term_table_entry_obj_id, &sdk_tunnel_decap_key);

    sai_db_unlock();

    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Fail to get sdk param for tunnel term table entry id %" PRIx64 "\n",
                   sai_tunnel_term_table_entry_obj_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_STATUS_SUCCESS !=
        (sdk_status = sx_api_tunnel_decap_rules_set(gh_sdk, SX_ACCESS_CMD_DESTROY,
                                                    &sdk_tunnel_decap_key,
                                                    &sdk_tunnel_decap_data))) {
        sai_status = sdk_to_sai(sdk_status);
        SX_LOG_ERR("Error setting tunnel table entry on removal, sx status: %s\n", SX_STATUS_MSG(sdk_status));
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    memset(&g_sai_db_ptr->mlnx_tunneltable[internal_tunneltable_idx], 0,
           sizeof(mlnx_tunneltable_t));

    sai_db_unlock();

    SX_LOG_NTC("Removed SAI tunnel table entry obj id %" PRIx64 "\n", sai_tunnel_term_table_entry_obj_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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

/* caller of this function should use read lock to guard the callsite */
static sai_status_t mlnx_create_empty_tunnel_map_entry(_Out_ uint32_t *tunnel_map_entry_idx)
{
    uint32_t     idx        = 0;
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    for (idx = MLNX_TUNNEL_MAP_ENTRY_MIN; idx < MLNX_TUNNEL_MAP_ENTRY_MAX; idx++) {
        if (!g_sai_db_ptr->mlnx_tunnel_map_entry[idx].in_use) {
            *tunnel_map_entry_idx = idx;
            sai_status            = SAI_STATUS_SUCCESS;
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

static sai_status_t mlnx_validate_tunnel_map_condition(_In_ sai_status_t sai_status, _In_ bool condition)
{
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS == sai_status) {
        if (!condition) {
            SX_LOG_ERR("this attribute should not be set for the tunnel map type\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    } else if (condition) {
        SX_LOG_ERR("this attribute is missing for the tunnel map type\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_init_tunnel_map_entry_param(_In_ uint32_t                  attr_count,
                                                     _In_ const sai_attribute_t    *attr_list,
                                                     _Out_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry)
{
    const sai_attribute_value_t *tunnel_map_type = NULL, *tunnel_map = NULL;
    const sai_attribute_value_t *oecn_key        = NULL, *oecn_value = NULL;
    const sai_attribute_value_t *uecn_key        = NULL, *uecn_value = NULL;
    const sai_attribute_value_t *vlan_id_key     = NULL, *vlan_id_value = NULL;
    const sai_attribute_value_t *vni_id_key      = NULL, *vni_id_value = NULL;
    const sai_attribute_value_t *bridge_id_key   = NULL, *bridge_id_value = NULL;
    uint32_t                     attr_idx        = 0;
    uint32_t                     tunnel_map_idx  = 0;
    sai_status_t                 sai_status      = SAI_STATUS_FAILURE;
    bool                         condition       = false;

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

    condition = ((SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN == tunnel_map_type->s32) ||
                 SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate oecn key condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->oecn_key = oecn_key->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE,
                                     &oecn_value, &attr_idx);

    condition = (SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate oecn value condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->oecn_value = oecn_value->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY,
                                     &uecn_key, &attr_idx);

    condition = (SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate uecn key condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->uecn_key = uecn_key->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE,
                                     &uecn_value, &attr_idx);

    condition = (SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate uecn value condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->uecn_value = uecn_value->u8;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY,
                                     &vlan_id_key, &attr_idx);

    condition = (SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate vlan id key condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vlan_id_key = vlan_id_key->u16;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE,
                                     &vlan_id_value, &attr_idx);

    condition = (SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate vlan id value condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vlan_id_value = vlan_id_value->u16;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY,
                                     &vni_id_key, &attr_idx);

    condition = ((SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID == tunnel_map_type->s32) ||
                 (SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF == tunnel_map_type->s32));

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate vni id key condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vni_id_key = vni_id_key->u32;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE,
                                     &vni_id_value, &attr_idx);

    condition = ((SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI == tunnel_map_type->s32) ||
                 (SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI == tunnel_map_type->s32));

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate vni id value condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->vni_id_value = vni_id_value->u32;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY,
                                     &bridge_id_key, &attr_idx);

    condition = (SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate bridge id key condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->bridge_id_key = bridge_id_key->oid;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE,
                                     &bridge_id_value, &attr_idx);

    condition = (SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF == tunnel_map_type->s32);

    if (SAI_STATUS_SUCCESS != mlnx_validate_tunnel_map_condition(sai_status, condition)) {
        SX_LOG_ERR("Fail to validate bridge id value condition\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    if (SAI_STATUS_SUCCESS == sai_status) {
        mlnx_tunnel_map_entry->bridge_id_value = bridge_id_value->oid;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP,
                                     &tunnel_map,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS ==
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(tunnel_map->oid, &tunnel_map_idx))) {
        if ((sai_tunnel_map_type_t)(tunnel_map_type->s32) !=
            g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_type) {
            sai_db_unlock();
            SX_LOG_ERR("Tunnel map oid %" PRIx64 " Claimed tunnel map type is %d but actual tunnel map type is %d\n",
                       tunnel_map->oid,
                       tunnel_map_type->s32,
                       g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_type);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        if (0 != g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_list_count) {
            sai_db_unlock();
            SX_LOG_ERR("Tunnel map oid %" PRIx64 " has %d tunnel map list elements which is greater than 0\n",
                       tunnel_map->oid,
                       g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_list_count);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        if (0 != g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_cnt) {
            sai_db_unlock();
            SX_LOG_ERR("Tunnel map oid %" PRIx64 " has been attached to %d tunnel(s)\n",
                       tunnel_map->oid,
                       g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_cnt);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        }

        g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_cnt++;

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
static sai_status_t mlnx_tunnel_map_entry_list_add(_In_ mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry,
                                                   _In_ uint32_t                tunnel_map_entry_idx)
{
    uint32_t     tunnel_map_idx            = 0;
    sai_status_t sai_status                = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_entry_tail_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_tunnel_map_db_idx(mlnx_tunnel_map_entry.tunnel_map_id, &tunnel_map_idx))) {
        SX_LOG_ERR("Error getting tunnel map idx from tunnel map oid %" PRIx64 "\n",
                   mlnx_tunnel_map_entry.tunnel_map_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    tunnel_map_entry_tail_idx = g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_tail_idx;

    if (MLNX_TUNNEL_MAP_ENTRY_INVALID == g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_head_idx) {
        assert(MLNX_TUNNEL_MAP_ENTRY_INVALID == tunnel_map_entry_tail_idx);
        g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_head_idx = tunnel_map_entry_idx;
    } else {
        g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_tail_idx].next_tunnel_map_entry_idx =
            tunnel_map_entry_idx;
    }

    g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].prev_tunnel_map_entry_idx = tunnel_map_entry_tail_idx;

    g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].next_tunnel_map_entry_idx =
        MLNX_TUNNEL_MAP_ENTRY_INVALID;

    g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_tail_idx = tunnel_map_entry_idx;

    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/* Caller needs to guard this function with lock */
static sai_status_t mlnx_tunnel_map_entry_list_delete(_In_ mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry,
                                                      _In_ uint32_t                tunnel_map_entry_idx)
{
    uint32_t     tunnel_map_idx            = 0;
    sai_status_t sai_status                = SAI_STATUS_FAILURE;
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

    prev_tunnel_map_entry_idx = g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].prev_tunnel_map_entry_idx;

    next_tunnel_map_entry_idx = g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].next_tunnel_map_entry_idx;

    if (MLNX_TUNNEL_MAP_ENTRY_INVALID ==
        g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].prev_tunnel_map_entry_idx) {
        assert(tunnel_map_entry_idx == g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_head_idx);

        g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_head_idx = next_tunnel_map_entry_idx;
    } else {
        assert(tunnel_map_entry_idx != g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_head_idx);
    }

    if (MLNX_TUNNEL_MAP_ENTRY_INVALID ==
        g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].next_tunnel_map_entry_idx) {
        assert(tunnel_map_entry_idx == g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_tail_idx);

        g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_tail_idx = prev_tunnel_map_entry_idx;
    } else {
        assert(tunnel_map_entry_idx != g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_tail_idx);
    }

    g_sai_db_ptr->mlnx_tunnel_map_entry[prev_tunnel_map_entry_idx].next_tunnel_map_entry_idx =
        next_tunnel_map_entry_idx;

    g_sai_db_ptr->mlnx_tunnel_map_entry[next_tunnel_map_entry_idx].prev_tunnel_map_entry_idx =
        prev_tunnel_map_entry_idx;

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
    sai_status_t            sai_status           = SAI_STATUS_SUCCESS;
    uint32_t                tunnel_map_entry_idx = 0;
    mlnx_tunnel_map_entry_t mlnx_tunnel_map_entry;

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
    SX_LOG_NTC("SAI Tunnel map entry attributes: %s\n", list_str);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_init_tunnel_map_entry_param(attr_count, attr_list, &mlnx_tunnel_map_entry))) {
        SX_LOG_ERR("Fail to set tunnel map entry param on create\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_empty_tunnel_map_entry(&tunnel_map_entry_idx))) {
        SX_LOG_ERR("Failed to create empty tunnel map entry\n");
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, tunnel_map_entry_idx, NULL,
                                sai_tunnel_map_entry_obj_id))) {
        memset(&g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx], 0,
               sizeof(mlnx_tunnel_map_entry_t));
        SX_LOG_ERR("Error creating sai tunnel map entry obj id from tunnel map entry idx %d\n",
                   tunnel_map_entry_idx);
        goto cleanup;
    }

    memcpy(&g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx], &mlnx_tunnel_map_entry,
           sizeof(mlnx_tunnel_map_entry_t));

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_tunnel_map_entry_list_add(mlnx_tunnel_map_entry,
                                            tunnel_map_entry_idx))) {
        SX_LOG_ERR("Error adding idx %d to tunnel map entry list\n", tunnel_map_entry_idx);
        goto cleanup;
    }

    SX_LOG_NTC("Created SAI tunnel map entry obj id: %" PRIx64 "\n", *sai_tunnel_map_entry_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
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
    sai_status_t sai_status           = SAI_STATUS_FAILURE;
    uint32_t     tunnel_map_idx       = 0;
    uint32_t     tunnel_map_entry_idx = 0;

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

    if (!(g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].in_use)) {
        SX_LOG_ERR("Invalid sai tunnel map entry obj id: %" PRIx64 "\n", sai_tunnel_map_entry_obj_id);
        sai_status = SAI_STATUS_INVALID_OBJECT_ID;
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             mlnx_get_sai_tunnel_map_db_idx(g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].tunnel_map_id,
                                            &tunnel_map_idx))) {
        if (0 < g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_cnt) {
            SX_LOG_ERR("This tunnel map entry is still used by %d other tunnel(s)\n",
                       g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_cnt);
            sai_status = SAI_STATUS_OBJECT_IN_USE;
            goto cleanup;
        }

        assert(0 < g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_cnt);
        g_sai_db_ptr->mlnx_tunnel_map[tunnel_map_idx].tunnel_map_entry_cnt--;
    } else {
        SX_LOG_ERR("Error getting tunnel map idx from SAI tunnel map oid %" PRIx64 "\n",
                   g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx].tunnel_map_id);
        sai_status = SAI_STATUS_FAILURE;
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_tunnel_map_entry_list_delete(g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx],
                                                        tunnel_map_entry_idx))) {
        SX_LOG_ERR("Error deleting idx %d from tunnel map entry list\n", tunnel_map_entry_idx);
        goto cleanup;
    }

    memset(&g_sai_db_ptr->mlnx_tunnel_map_entry[tunnel_map_entry_idx], 0, sizeof(mlnx_tunnel_map_entry_t));

    SX_LOG_NTC("Removed SAI tunnel map entry obj id %" PRIx64 "\n", sai_tunnel_map_entry_obj_id);

    sai_status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
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

const sai_tunnel_api_t mlnx_tunnel_api = {
    mlnx_create_tunnel_map,
    mlnx_remove_tunnel_map,
    mlnx_set_tunnel_map_attribute,
    mlnx_get_tunnel_map_attribute,
    mlnx_create_tunnel,
    mlnx_remove_tunnel,
    mlnx_set_tunnel_attribute,
    mlnx_get_tunnel_attribute,
    mlnx_create_tunnel_term_table_entry,
    mlnx_remove_tunnel_term_table_entry,
    mlnx_set_tunnel_term_table_entry_attribute,
    mlnx_get_tunnel_term_table_entry_attribute,
    mlnx_create_tunnel_map_entry,
    mlnx_remove_tunnel_map_entry,
    mlnx_set_tunnel_map_entry_attribute,
    mlnx_get_tunnel_map_entry_attribute,
};
