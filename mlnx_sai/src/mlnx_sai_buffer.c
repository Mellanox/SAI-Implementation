/*
 *  Copyright (C) 2017-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License") you may
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
#include <limits.h>
#include <math.h>

#undef  __MODULE__
#define __MODULE__ SAI_BUFFER

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static mlnx_sai_buffer_resource_limits_t buffer_limits;
#define SAI_SDK_DEFAULT_MC_BUFFER_RESERVED_SIZE 213

typedef enum _sai_buffer_alpha_bounds_t {
    SAI_BUFFER_ALPHA_0 = -8, /* Values <= SAI_BUFFER_ALPHA_0 are interpreted as 0 */

    SAI_BUFFER_ALPHA_1_128 = -7,
    SAI_BUFFER_ALPHA_1_64  = -6,
    SAI_BUFFER_ALPHA_1_32  = -5,
    SAI_BUFFER_ALPHA_1_16  = -4,
    SAI_BUFFER_ALPHA_1_8   = -3,
    SAI_BUFFER_ALPHA_1_4   = -2,
    SAI_BUFFER_ALPHA_1_2   = -1,

    SAI_BUFFER_ALPHA_1  = 0,
    SAI_BUFFER_ALPHA_2  = 1,
    SAI_BUFFER_ALPHA_4  = 2,
    SAI_BUFFER_ALPHA_8  = 3,
    SAI_BUFFER_ALPHA_16 = 4,
    SAI_BUFFER_ALPHA_32 = 5,
    SAI_BUFFER_ALPHA_64 = 6,

    SAI_BUFFER_ALPHA_INFINITY = 7 /* Values >= SAI_BUFFER_ALPHA_INFINITY are interpreted as 'infinity'*/
} sai_buffer_alpha_bounds_t;
typedef struct _mlnx_affect_port_buff_items {
    uint32_t affected_count;
    bool   * pgs;
    bool   * tcs;
    bool   * i_port_buffers;
    bool   * e_port_buffers;
} mlnx_affect_port_buff_items_t;

static void log_buffer_profile_refs(_In_ mlnx_affect_port_buff_items_t const* refs);
sai_status_t mlnx_create_sai_pool_id(_In_ uint32_t sx_pool_id, _Out_ sai_object_id_t*  sai_pool);
sai_status_t mlnx_sai_port_hw_lanes_get(_In_ const sx_port_log_id_t *port_id, _Inout_ sai_attribute_value_t *value);
static sai_status_t mlnx_sai_is_buffer_in_use(_In_ sai_object_id_t buffer_profile_id);
static sai_status_t mlnx_sai_collect_buffer_refs(_In_ sai_object_id_t                 sai_buffer_id,
                                                 _In_ uint32_t                        db_port_ind,
                                                 _Out_ mlnx_affect_port_buff_items_t* affected_items);
static sai_status_t mlnx_sai_buffer_configure_reserved_buffers(_In_ sx_port_log_id_t            logical_port,
                                                               _Out_ sx_cos_port_buffer_attr_t* sx_port_reserved_buff_attr_arr,
                                                               _In_ uint32_t                    count);
static sai_status_t mlnx_sai_buffer_configure_shared_buffers(_In_ sx_port_log_id_t                   logical_port,
                                                             _Out_ sx_cos_port_shared_buffer_attr_t* sx_port_shared_buff_attr_arr,
                                                             _In_ uint32_t                           count);
static sai_status_t mlnx_sai_buffer_apply_buffer_change_to_references(_In_ sai_object_id_t sai_buffer_id);
static sai_status_t mlnx_sai_buffer_apply_buffer_to_queue(_In_ uint32_t                           qos_db_port_ind,
                                                          _In_ uint32_t                           qos_ind,
                                                          _In_ mlnx_sai_db_buffer_profile_entry_t buff_db_entry);
static sai_status_t mlnx_sai_buffer_apply_buffer_to_pg(_In_ uint32_t                           port_ind,
                                                       _In_ uint32_t                           pg_ind,
                                                       _In_ mlnx_sai_db_buffer_profile_entry_t buff_db_entry);
static sai_status_t mlnx_get_sai_buffer_profile_data(_In_ sai_object_id_t               sai_buffer,
                                                     _Out_ uint32_t                   * out_db_buffer_profile_index,
                                                     _Out_ mlnx_sai_buffer_pool_attr_t* sai_pool_attr);
static sai_status_t mlnx_sai_set_ingress_priority_group_buffer_profile_attr(_In_ const sai_object_key_t      * key,
                                                                            _In_ const sai_attribute_value_t * value,
                                                                            void                             * arg);
static sai_status_t mlnx_sai_get_ingress_priority_group_buffer_profile_attr(_In_ const sai_object_key_t   * key,
                                                                            _Inout_ sai_attribute_value_t * value,
                                                                            _In_ uint32_t                   attr_index,
                                                                            _Inout_ vendor_cache_t        * cache,
                                                                            void                          * arg);
static sai_status_t mlnx_sai_get_ingress_priority_group_attrib(_In_ const sai_object_key_t   * key,
                                                               _Inout_ sai_attribute_value_t * value,
                                                               _In_ uint32_t                   attr_index,
                                                               _Inout_ vendor_cache_t        * cache,
                                                               void                          * arg);
static sai_status_t mlnx_sai_create_buffer_pool(_Out_ sai_object_id_t     * pool_id,
                                                _In_ sai_object_id_t        switch_id,
                                                _In_ uint32_t               attr_count,
                                                _In_ const sai_attribute_t *attr_list);
static sai_status_t mlnx_sai_remove_buffer_pool(_In_ sai_object_id_t pool_id);
static sai_status_t mlnx_sai_set_buffer_pool_attr(_In_ sai_object_id_t pool_id, _In_ const sai_attribute_t *    attr);
static sai_status_t mlnx_sai_get_buffer_pool_attr(_In_ sai_object_id_t      pool_id,
                                                  _In_ uint32_t             attr_count,
                                                  _Inout_ sai_attribute_t * attr_list);
static sai_status_t mlnx_sai_create_buffer_profile(_Out_ sai_object_id_t     * buffer_profile_id,
                                                   _In_ sai_object_id_t        switch_id,
                                                   _In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list);
static sai_status_t mlnx_sai_remove_buffer_profile(_In_ sai_object_id_t buffer_profile_id);
static sai_status_t mlnx_sai_set_buffer_profile_attr(_In_ sai_object_id_t        buffer_profile_id,
                                                     _In_ const sai_attribute_t *attr);
static sai_status_t mlnx_sai_get_buffer_profile_attr(_In_ sai_object_id_t     buffer_profile_id,
                                                     _In_ uint32_t            attr_count,
                                                     _Inout_ sai_attribute_t *attr_list);
static sai_status_t mlnx_sai_get_pool_shared_size_attr(_In_ const sai_object_key_t   * key,
                                                       _Inout_ sai_attribute_value_t * value,
                                                       _In_ uint32_t                   attr_index,
                                                       _Inout_ vendor_cache_t        * cache,
                                                       void                          * arg);
static sai_status_t mlnx_sai_get_pool_type_attr(_In_ const sai_object_key_t   * key,
                                                _Inout_ sai_attribute_value_t * value,
                                                _In_ uint32_t                   attr_index,
                                                _Inout_ vendor_cache_t        * cache,
                                                void                          * arg);
static sai_status_t mlnx_sai_get_pool_size_attr(_In_ const sai_object_key_t   * key,
                                                _Inout_ sai_attribute_value_t * value,
                                                _In_ uint32_t                   attr_index,
                                                _Inout_ vendor_cache_t        * cache,
                                                void                          * arg);
static sai_status_t mlnx_sai_set_pool_size_attr(_In_ const sai_object_key_t      * key,
                                                _In_ const sai_attribute_value_t * value,
                                                void                             * arg);
static sai_status_t mlnx_sai_get_pool_th_mode_attr(_In_ const sai_object_key_t   * key,
                                                   _Inout_ sai_attribute_value_t * value,
                                                   _In_ uint32_t                   attr_index,
                                                   _Inout_ vendor_cache_t        * cache,
                                                   void                          * arg);
static sai_status_t mlnx_sai_get_buffer_profile_pool_id_attr(_In_ const sai_object_key_t   * key,
                                                             _Inout_ sai_attribute_value_t * value,
                                                             _In_ uint32_t                   attr_index,
                                                             _Inout_ vendor_cache_t        * cache,
                                                             void                          * arg);
static sai_status_t mlnx_sai_get_buffer_profile_size_attr(_In_ const sai_object_key_t   * key,
                                                          _Inout_ sai_attribute_value_t * value,
                                                          _In_ uint32_t                   attr_index,
                                                          _Inout_ vendor_cache_t        * cache,
                                                          void                          * arg);
static sai_status_t mlnx_sai_set_buffer_profile_size_attr(_In_ const sai_object_key_t      * key,
                                                          _In_ const sai_attribute_value_t * value,
                                                          void                             * arg);
static sai_status_t mlnx_sai_get_buffer_profile_dynamic_th_attr(_In_ const sai_object_key_t   * key,
                                                                _Inout_ sai_attribute_value_t * value,
                                                                _In_ uint32_t                   attr_index,
                                                                _Inout_ vendor_cache_t        * cache,
                                                                void                          * arg);
static sai_status_t mlnx_sai_set_buffer_profile_dynamic_th_attr(_In_ const sai_object_key_t      * key,
                                                                _In_ const sai_attribute_value_t * value,
                                                                void                             * arg);
static sai_status_t mlnx_sai_get_buffer_profile_static_th_attr(_In_ const sai_object_key_t   * key,
                                                               _Inout_ sai_attribute_value_t * value,
                                                               _In_ uint32_t                   attr_index,
                                                               _Inout_ vendor_cache_t        * cache,
                                                               void                          * arg);
static sai_status_t mlnx_sai_set_buffer_profile_static_th_attr(_In_ const sai_object_key_t      * key,
                                                               _In_ const sai_attribute_value_t * value,
                                                               void                             * arg);
static sai_status_t mlnx_sai_get_buffer_profile_xoff_attr(_In_ const sai_object_key_t   * key,
                                                          _Inout_ sai_attribute_value_t * value,
                                                          _In_ uint32_t                   attr_index,
                                                          _Inout_ vendor_cache_t        * cache,
                                                          void                          * arg);
static sai_status_t mlnx_sai_set_buffer_profile_xoff_attr(_In_ const sai_object_key_t      * key,
                                                          _In_ const sai_attribute_value_t * value,
                                                          void                             * arg);
static sai_status_t mlnx_sai_get_buffer_profile_xon_attr(_In_ const sai_object_key_t   * key,
                                                         _Inout_ sai_attribute_value_t * value,
                                                         _In_ uint32_t                   attr_index,
                                                         _Inout_ vendor_cache_t        * cache,
                                                         void                          * arg);
static sai_status_t mlnx_sai_set_buffer_profile_xon_attr(_In_ const sai_object_key_t      * key,
                                                         _In_ const sai_attribute_value_t * value,
                                                         void                             * arg);
static sai_status_t mlnx_sai_get_buffer_profile_th_mode(_In_ const sai_object_key_t   * key,
                                                        _Inout_ sai_attribute_value_t * value,
                                                        _In_ uint32_t                   attr_index,
                                                        _Inout_ vendor_cache_t        * cache,
                                                        void                          * arg);
sai_status_t mlnx_buffer_convert_alpha_sai_to_sx(_In_ sai_int8_t sai_alpha, _Out_ sx_cos_port_buff_alpha_e* sx_alpha);
static sai_status_t mlnx_sai_buffer_construct_shp_sx_attr_internal(_Out_ sx_cos_pool_attr_t *sx_pool_attr,
                                                                   _In_ uint64_t             pool_size);
static sai_status_t mlnx_sai_buffer_port_psb_cells_coefficient_get(_In_ const sx_port_log_id_t *sx_port_logical,
                                                                   _Inout_ uint32_t            *coefficient);
static sai_status_t mlnx_sai_buffer_construct_psb_sx_attr_internal(
    _Out_ sx_cos_port_shared_headroom_attr_t *sx_psb_attr,
    _In_ sx_cos_pool_id_t                     sx_shp_pool_id,
    _In_ uint32_t                             max_pool_loan,
    _In_ const sx_port_log_id_t              *sx_port_logical_id);
static void mlnx_sai_buffer_update_sai_db_shp_ipool_map(_In_ bool            is_shp_created,
                                                        _In_ sai_object_id_t sai_pool_id,
                                                        _In_ sai_object_id_t shp_pool_id);
static sai_status_t mlnx_sai_buffer_update_pg_and_psb_buffers_hw(_In_ sai_object_id_t  sai_ipool_id,
                                                                 _In_ sx_cos_pool_id_t sx_shp_pool_id,
                                                                 _In_ bool             is_create);
static sai_status_t mlnx_sai_buffer_create_pool_hw(_In_ sx_cos_pool_attr_t *sx_pool_attr,
                                                   _Out_ sx_cos_pool_id_t  *sx_shp_pool_id,
                                                   _Out_ sai_object_id_t   *sai_pool_id);
static sai_status_t mlnx_sai_buffer_remove_pool_hw(_In_ sx_cos_pool_attr_t *sx_pool_attr, _In_ uint32_t *sx_pool_id);
static sai_status_t mlnx_sai_buffer_disable_shared_headroom_internal(_In_ sai_object_id_t sai_parent_pool_id,
                                                                     _In_ sai_object_id_t sai_shp_pool_id,
                                                                     _In_ bool            is_update_pg_psb);
static sai_status_t mlnx_sai_buffer_enable_shared_headroom_internal(_In_ sai_object_id_t   sai_ipool_id,
                                                                    _Out_ sai_object_id_t *sai_shp_pool_id,
                                                                    _In_ uint64_t          shp_pool_size,
                                                                    _In_ bool              is_update_pg_psb);
static sai_status_t mlnx_sai_buffer_calculate_psb_max_pool_loan(
    _In_ mlnx_affect_port_buff_items_t const      *affected_items,
    _In_ mlnx_sai_db_buffer_profile_entry_t const *buff_db_entry,
    _In_ uint32_t                                  cells_coeff,
    _In_ uint32_t                                  db_port_ind,
    _Out_ uint32_t                                *pool_loan);
static sai_status_t mlnx_sai_buffer_prepare_affected_buffers(_In_ const mlnx_sai_buffer_pool_attr_t     *sai_pool_attr,
                                                             _In_ mlnx_affect_port_buff_items_t const   *affected_items,
                                                             _Out_opt_ sx_cos_port_shared_buffer_attr_t *sx_port_shared_buff_attr_arr,
                                                             _Out_opt_ sx_cos_port_buffer_attr_t        *sx_port_reserved_buff_attr_arr);
static void mlnx_sai_buffer_apply_profile_to_reserved_structs(
    _Inout_ sx_cos_port_buffer_attr_t            * sx_port_reserved_buff_attr_arr,
    _In_ uint32_t                                  count,
    _In_ const mlnx_sai_db_buffer_profile_entry_t *buff_db_entry,
    _In_ const mlnx_sai_buffer_pool_attr_t        *sai_pool_attr,
    _In_ mlnx_affect_port_buff_items_t const      *affected_items);
static void mlnx_sai_buffer_calculate_max_pool_loan_and_update_affected_items(
    _In_ sai_object_id_t                 sai_ipool_id,
    _In_ const uint32_t                 *sai_port_pg_profile_refs,
    _In_ uint32_t                        cells_coeff,
    _Out_ uint32_t                      *pool_loan,
    _Out_ mlnx_affect_port_buff_items_t *mlnx_sai_affected_items);
static sai_status_t mlnx_sai_buffer_configure_buffers(_In_ const mlnx_port_config_t         *port,
                                                      _In_ sx_cos_port_buffer_attr_t        *buff_reserved_attr_arr,
                                                      _In_ uint32_t                          buff_reserved_attr_count,
                                                      _In_ sx_cos_port_shared_buffer_attr_t *buff_shared_attr_arr,
                                                      _In_ uint32_t                          buff_shared_attr_count);
static sai_status_t mlnx_sai_buffer_pg0_update_is_required(_In_ const mlnx_port_config_t *port,
                                                           _Inout_ bool                  *is_update);
static sai_status_t mlnx_sai_buffer_construct_pg_buffer_attr(_In_ const mlnx_port_config_t            *port,
                                                             _In_ uint32_t                             pg_index,
                                                             _Inout_ sx_cos_port_buffer_attr_t        *pgs_buff_reserved_attr_arr,
                                                             _Inout_ uint32_t                         *buff_reserved_attr_count,
                                                             _Inout_ sx_cos_port_shared_buffer_attr_t *pgs_buff_shared_attr_arr,
                                                             _Inout_ uint32_t                         *buff_shared_attr_count);
static sai_status_t mlnx_sai_buffer_construct_pg9_buffers_attrs(_In_ const mlnx_port_config_t     *port,
                                                                _Inout_ sx_cos_port_buffer_attr_t *pgs_buff_reserved_attr_arr,
                                                                _Inout_ uint32_t                  *buff_attr_count);
sai_status_t mlnx_sai_bulk_ingress_priority_group_stats_clear(_In_ sai_object_id_t         switch_id,
                                                              _In_ uint32_t                object_count,
                                                              _In_ const sai_object_key_t *object_key,
                                                              _In_ uint32_t                number_of_counters,
                                                              _In_ const sai_stat_id_t    *counter_ids,
                                                              _In_ sx_access_cmd_t         cmd,
                                                              _Inout_ sai_status_t        *object_statuses);
static const sai_vendor_attribute_entry_t pg_vendor_attribs[] = {
    {
        SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_ingress_priority_group_buffer_profile_attr, NULL,
        mlnx_sai_set_ingress_priority_group_buffer_profile_attr, NULL
    },
    {
        SAI_INGRESS_PRIORITY_GROUP_ATTR_PORT,
        { true, false, false, true },
        { true, false, false, true },
        mlnx_sai_get_ingress_priority_group_attrib, (void*)SAI_INGRESS_PRIORITY_GROUP_ATTR_PORT,
        NULL, NULL
    },
    {
        SAI_INGRESS_PRIORITY_GROUP_ATTR_INDEX,
        { true, false, false, true },
        { true, false, false, true },
        mlnx_sai_get_ingress_priority_group_attrib, (void*)SAI_INGRESS_PRIORITY_GROUP_ATTR_INDEX,
        NULL, NULL
    },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL}
};
static const sai_stat_capability_t        pg_stats_capabilies[] = {
    { SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES,
      SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR | SAI_STATS_MODE_BULK_READ |
      SAI_STATS_MODE_BULK_READ_AND_CLEAR | SAI_STATS_MODE_BULK_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES,
      SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR | SAI_STATS_MODE_BULK_READ |
      SAI_STATS_MODE_BULK_READ_AND_CLEAR | SAI_STATS_MODE_BULK_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES,
      SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR | SAI_STATS_MODE_BULK_READ |
      SAI_STATS_MODE_BULK_READ_AND_CLEAR | SAI_STATS_MODE_BULK_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES,
      SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR | SAI_STATS_MODE_BULK_READ |
      SAI_STATS_MODE_BULK_READ_AND_CLEAR | SAI_STATS_MODE_BULK_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES,
      SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR | SAI_STATS_MODE_BULK_READ |
      SAI_STATS_MODE_BULK_READ_AND_CLEAR | SAI_STATS_MODE_BULK_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES,
      SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR | SAI_STATS_MODE_BULK_READ |
      SAI_STATS_MODE_BULK_READ_AND_CLEAR | SAI_STATS_MODE_BULK_CLEAR },
    { SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
};
const mlnx_obj_type_attrs_info_t          mlnx_ingress_pg_obj_type_info =
{ pg_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO(pg_stats_capabilies)};
static const sai_vendor_attribute_entry_t pool_vendor_attribs[] = {
    {
        SAI_BUFFER_POOL_ATTR_SHARED_SIZE,
        { false, false, false, true },
        { false, false, false, true },
        mlnx_sai_get_pool_shared_size_attr, NULL,
        NULL, NULL
    },
    {
        SAI_BUFFER_POOL_ATTR_TYPE,
        { true, false, false, true },
        { true, false, false, true },
        mlnx_sai_get_pool_type_attr, NULL,
        NULL, NULL
    },
    {
        SAI_BUFFER_POOL_ATTR_SIZE,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_pool_size_attr, (void*)SAI_BUFFER_POOL_ATTR_SIZE,
        mlnx_sai_set_pool_size_attr, (void*)SAI_BUFFER_POOL_ATTR_SIZE
    },
    {
        SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE,
        { true, false, false, true },
        { true, false, false, true },
        mlnx_sai_get_pool_th_mode_attr, NULL,
        NULL, NULL
    },
    {
        SAI_BUFFER_POOL_ATTR_XOFF_SIZE,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_pool_size_attr, (void*)SAI_BUFFER_POOL_ATTR_XOFF_SIZE,
        mlnx_sai_set_pool_size_attr, (void*)SAI_BUFFER_POOL_ATTR_XOFF_SIZE
    },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL}
};
static const mlnx_attr_enum_info_t        buffer_pool_enum_info[] = {
    [SAI_BUFFER_POOL_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_BUFFER_POOL_TYPE_INGRESS,
        SAI_BUFFER_POOL_TYPE_EGRESS),
    [SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE] = ATTR_ENUM_VALUES_ALL(),
};
static const sai_stat_capability_t        buffer_pool_stats_capabilities[] = {
    { SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_BUFFER_POOL_STAT_WATERMARK_BYTES, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_BUFFER_POOL_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
};
const mlnx_obj_type_attrs_info_t          mlnx_buffer_pool_obj_type_info =
{ pool_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(buffer_pool_enum_info), OBJ_STAT_CAP_INFO(buffer_pool_stats_capabilities)};
static const sai_vendor_attribute_entry_t buffer_profile_vendor_attribs[] = {
    {
        SAI_BUFFER_PROFILE_ATTR_POOL_ID,
        { true, false, false, true },
        { true, false, false, true },
        mlnx_sai_get_buffer_profile_pool_id_attr, NULL,
        NULL, NULL
    },
    {
        SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_buffer_profile_size_attr, NULL,
        mlnx_sai_set_buffer_profile_size_attr, NULL
    },
    {
        SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_buffer_profile_dynamic_th_attr, NULL,
        mlnx_sai_set_buffer_profile_dynamic_th_attr, NULL
    },
    {
        SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_buffer_profile_static_th_attr, NULL,
        mlnx_sai_set_buffer_profile_static_th_attr, NULL
    },
    {
        SAI_BUFFER_PROFILE_ATTR_XOFF_TH,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_buffer_profile_xoff_attr, NULL,
        mlnx_sai_set_buffer_profile_xoff_attr, NULL
    },
    {
        SAI_BUFFER_PROFILE_ATTR_XON_TH,
        { true, false, true, true },
        { true, false, true, true },
        mlnx_sai_get_buffer_profile_xon_attr, NULL,
        mlnx_sai_set_buffer_profile_xon_attr, NULL
    },
    {
        SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE,
        { true, false, false, true },
        { true, false, false, true },
        mlnx_sai_get_buffer_profile_th_mode, NULL,
        NULL, NULL
    },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL}
};
static const mlnx_attr_enum_info_t        buffer_profile_enum_info[] = {
    [SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_buffer_profile_obj_type_info =
{ buffer_profile_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(buffer_profile_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};
void init_buffer_resource_limits()
{
    /* number of user allocatable pools */
    buffer_limits.num_ingress_pools = 8;         /* g_resource_limits.shared_buff_num_ingress_pools; */
    buffer_limits.num_egress_pools = 8;          /* g_resource_limits.shared_buff_num_egress_pools; */
    buffer_limits.num_shared_headroom_pools = g_resource_limits.shared_buff_num_headroom_pools;
    /* total data pools, for validation of data pool id */
    buffer_limits.num_total_pools = g_resource_limits.shared_buff_total_num_pools;
    buffer_limits.num_port_queue_buff = g_resource_limits.shared_buff_num_port_egress_buff - 1;           /* we need 1 less without CTRL TC */
    buffer_limits.num_port_pg_buff = g_resource_limits.shared_buff_num_port_ingress_buff - 1;              /* g_resource_limits is including CTRL PG#9. We Need 1 less, without CTRL PG */
    buffer_limits.num_port_shared_headroom_buff = g_resource_limits.headroom_num_port_buff;   /* amount of port shared headroom buffers per port*/
    buffer_limits.unit_size = g_resource_limits.shared_buff_buffer_unit_size;
    /* data and descriptors usage per PG and TC + port usage per every pool either data or descriptors */

    /* does not include amount of shared headroom buffers per port */
    buffer_limits.max_buffers_per_port = g_resource_limits.shared_buff_num_port_egress_buff * 2 +
                                         g_resource_limits.shared_buff_num_port_ingress_buff * 2 +
                                         g_resource_limits.shared_buff_total_num_pools;


    printf("%s[\n", __FUNCTION__);
    printf("num_ingress_pools:%d\n", buffer_limits.num_ingress_pools);
    printf("num_egress_pools:%d\n", buffer_limits.num_egress_pools);
    printf("num_shared_headroom_pools:%d\n", buffer_limits.num_shared_headroom_pools);
    printf("num_total_pools:%d\n", buffer_limits.num_total_pools);
    printf("num_port_queue_buff:%d\n", buffer_limits.num_port_queue_buff);
    printf("num_port_pg_buff:%d\n", buffer_limits.num_port_pg_buff);
    printf("num_headroom_port_buff:%d\n", buffer_limits.num_port_shared_headroom_buff);
    printf("unit_size:%d\n", buffer_limits.unit_size);
    printf("max_buffers_per_port:%d\n", buffer_limits.max_buffers_per_port);
    printf("%s]\n", __FUNCTION__);
}

const mlnx_sai_buffer_resource_limits_t* mlnx_sai_get_buffer_resource_limits()
{
    return &buffer_limits;
}

uint32_t mlnx_sai_get_buffer_profile_number()
{
    return (1 + (MAX_PORTS * buffer_limits.max_buffers_per_port));
}

sai_status_t mlnx_init_buffer_pool_ids()
{
#define INITIAL_POOLS 20
    sx_cos_pool_id_t   pools[INITIAL_POOLS];
    uint32_t           ii, pool_num = INITIAL_POOLS;
    sx_status_t        sx_status;
    sx_cos_pool_attr_t pool_attr;
    uint32_t           found = 0;

    if (SX_STATUS_SUCCESS != (sx_status = sx_api_cos_pools_list_get(gh_sdk, &pool_num, pools))) {
        SX_LOG_ERR("Failed to get sx pool list, %s.\n", SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }
    for (ii = 0; ii < pool_num; ii++) {
        if (SX_STATUS_SUCCESS != (sx_status = sx_api_cos_shared_buff_pool_get(gh_sdk, pools[ii], &pool_attr))) {
            SX_LOG_ERR("Failed to get pool %u attr, %s.\n", pools[ii], SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }
        switch (pool_attr.pool_info) {
        case SX_COS_POOL_INFO_DEFAULT_DATA_INGRESS_E:
            g_sai_buffer_db_ptr->buffer_pool_ids.default_ingress_pool_id = pools[ii];
            found++;
            break;

        case SX_COS_POOL_INFO_DEFAULT_DATA_EGRESS_E:
            g_sai_buffer_db_ptr->buffer_pool_ids.default_egress_pool_id = pools[ii];
            found++;
            break;

        case SX_COS_POOL_INFO_DEFAULT_INGRESS_MANAGMENT_E:
            g_sai_buffer_db_ptr->buffer_pool_ids.management_ingress_pool_id = pools[ii];
            found++;
            break;

        case SX_COS_POOL_INFO_DEFAULT_EGRESS_MANAGMENT_E:
            g_sai_buffer_db_ptr->buffer_pool_ids.management_egress_pool_id = pools[ii];
            found++;
            break;

        case SX_COS_POOL_INFO_DEFAULT_MULTICAST_E:
            g_sai_buffer_db_ptr->buffer_pool_ids.default_multicast_pool_id = pools[ii];
            found++;
            break;

        case SX_COS_POOL_INFO_DEFAULT_DESCRIPTOR_INGRESS_E:
            g_sai_buffer_db_ptr->buffer_pool_ids.default_descriptor_ingress_pool_id = pools[ii];
            found++;
            break;

        case SX_COS_POOL_INFO_DEFAULT_DESCRIPTOR_EGRESS_E:
            g_sai_buffer_db_ptr->buffer_pool_ids.default_descriptor_egress_pool_id = pools[ii];
            found++;
            break;

        default:
            break;
        }
    }
    if (7 != found) {
        SX_LOG_ERR("Failed to find 7 base pools %u\n", found);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    g_sai_buffer_db_ptr->buffer_pool_ids.user_pool_step =
        g_sai_buffer_db_ptr->buffer_pool_ids.management_ingress_pool_id -
        g_sai_buffer_db_ptr->buffer_pool_ids.default_ingress_pool_id;
    g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id =
        g_sai_buffer_db_ptr->buffer_pool_ids.management_ingress_pool_id +
        g_sai_buffer_db_ptr->buffer_pool_ids.
        user_pool_step;
    g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id =
        g_sai_buffer_db_ptr->buffer_pool_ids.management_egress_pool_id +
        g_sai_buffer_db_ptr->buffer_pool_ids.
        user_pool_step;

    printf("%s[\n", __FUNCTION__);
    printf("default_ingress_pool_id:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.default_ingress_pool_id);
    printf("management_ingress_pool_id:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.management_ingress_pool_id);
    printf("base_ingress_user_sx_pool_id:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id);
    printf("default_egress_pool_id:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.default_egress_pool_id);
    printf("management_egress_pool_id:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.management_egress_pool_id);
    printf("base_egress_user_sx_pool_id:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id);
    printf("default_multicast_pool_id:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.default_multicast_pool_id);
    printf("user_pool_step:%u\n", g_sai_buffer_db_ptr->buffer_pool_ids.user_pool_step);
    printf("default_descriptor_ingress_pool_id:%u\n",
           g_sai_buffer_db_ptr->buffer_pool_ids.default_descriptor_ingress_pool_id);
    printf("default_descriptor_egress_pool_id:%u\n",
           g_sai_buffer_db_ptr->buffer_pool_ids.default_descriptor_egress_pool_id);
    printf("%s]\n", __FUNCTION__);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_get_port_buffer_index_array(uint32_t                       db_port_ind,
                                                  port_buffer_index_array_type_t buff_type,
                                                  uint32_t                    ** index_arr)
{
    SX_LOG_ENTER();
    uint32_t array_location_offset = 0;

    if (NULL == index_arr) {
        SX_LOG_ERR("NULL index_arr\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (db_port_ind >= MAX_PORTS) {
        SX_LOG_ERR("db_port_ind out of bounds\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    switch (buff_type) {
    case PORT_BUFF_TYPE_INGRESS:
        array_location_offset = db_port_ind * buffer_limits.num_ingress_pools;
        break;

    case PORT_BUFF_TYPE_EGRESS:
        array_location_offset =
            buffer_limits.num_ingress_pools * MAX_PORTS +
            db_port_ind * buffer_limits.num_egress_pools;
        break;

    case PORT_BUFF_TYPE_PG:
        array_location_offset =
            buffer_limits.num_ingress_pools * MAX_PORTS +
            buffer_limits.num_egress_pools * MAX_PORTS +
            db_port_ind * buffer_limits.num_port_pg_buff;
        break;

    default:
        SX_LOG_ERR("Invalid buffer type:%d\n", buff_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *index_arr = g_sai_buffer_db_ptr->port_buffer_data + array_location_offset;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static bool mlnx_sai_buffer_get_pool_create_triggered_flag()
{
    return g_sai_buffer_db_ptr->pool_allocation[0];
}

static sai_status_t mlnx_sai_buffer_set_pool_create_triggered_flag(bool is_pool_creation_triggered)
{
    if (g_sai_buffer_db_ptr->pool_allocation[0] == is_pool_creation_triggered) {
        SX_LOG_ERR("Double setting the initial pool creation flag\n");
        return SAI_STATUS_FAILURE;
    }
    g_sai_buffer_db_ptr->pool_allocation[0] = is_pool_creation_triggered;
    return SAI_STATUS_SUCCESS;
}

#define max_value(x, y) ((x > y) ? x : y)

uint32_t mlnx_cells_to_bytes(uint32_t cells)
{
    return (cells * g_resource_limits.shared_buff_buffer_unit_size);
}

buffer_units_t bytes_to_mlnx_cells(uint32_t bytes)
{
    return ((buffer_units_t)ceil(((double)bytes) / (double)g_resource_limits.shared_buff_buffer_unit_size));
}

static bool alloc_affected_items(_Out_ mlnx_affect_port_buff_items_t* affected_items)
{
    bool ret = false;

    memset(affected_items, 0, sizeof(mlnx_affect_port_buff_items_t));
    if (NULL == (affected_items->pgs = calloc(buffer_limits.num_port_pg_buff, sizeof(bool)))) {
        goto exit;
    }
    if (NULL == (affected_items->tcs = calloc(buffer_limits.num_port_queue_buff, sizeof(bool)))) {
        goto exit;
    }
    if (NULL == (affected_items->i_port_buffers = calloc(buffer_limits.num_ingress_pools, sizeof(bool)))) {
        goto exit;
    }
    if (NULL == (affected_items->e_port_buffers = calloc(buffer_limits.num_egress_pools, sizeof(bool)))) {
        goto exit;
    }
    ret = true;
exit:
    if (!ret) {
        if (affected_items->pgs) {
            free(affected_items->pgs);
        }
        if (affected_items->tcs) {
            free(affected_items->tcs);
        }
        if (affected_items->i_port_buffers) {
            free(affected_items->i_port_buffers);
        }
        if (affected_items->e_port_buffers) {
            free(affected_items->e_port_buffers);
        }
    }
    return ret;
}

static void reset_affected_items(_Out_ mlnx_affect_port_buff_items_t* affected_items)
{
    affected_items->affected_count = 0;
    memset(affected_items->pgs, 0, buffer_limits.num_port_pg_buff * sizeof(bool));
    memset(affected_items->tcs, 0, buffer_limits.num_port_queue_buff * sizeof(bool));
    memset(affected_items->i_port_buffers, 0, buffer_limits.num_ingress_pools * sizeof(bool));
    memset(affected_items->e_port_buffers, 0, buffer_limits.num_egress_pools * sizeof(bool));
}

static void free_affected_items(_Out_ mlnx_affect_port_buff_items_t* affected_items)
{
    safe_free(affected_items->pgs);
    safe_free(affected_items->tcs);
    safe_free(affected_items->i_port_buffers);
    safe_free(affected_items->e_port_buffers);
}

sai_status_t mlnx_sai_buffer_log_set(_In_ sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;
    if (gh_sdk) {
        return sdk_to_sai(sx_api_cos_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

static void pool_key_to_str(_In_ sai_object_id_t sai_pool, _Out_ char              *key_str)
{
    uint32_t sx_pool_id = 0;

    if (NULL == key_str) {
        SX_LOG_ERR("NULL key_str\n");
        return;
    }

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(sai_pool, SAI_OBJECT_TYPE_BUFFER_POOL, &sx_pool_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid sai pool key");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "pool id:%u", sx_pool_id);
    }
}

static void pg_key_to_str(_In_ sai_object_id_t sai_port_pg, _Out_ char              *key_str)
{
    uint32_t port_db_index = 0;
    uint8_t  extended_data[EXTENDED_DATA_SIZE];

    memset(extended_data, 0, sizeof(extended_data));

    if (NULL == key_str) {
        SX_LOG_ERR("NULL key_str\n");
        return;
    }

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_port_pg, SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, &port_db_index, extended_data)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid port PG key");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "port:%u, PG index:%u", port_db_index, extended_data[0]);
    }
}

static void buffer_profile_key_to_str(_In_ sai_object_id_t sai_buffer_profile, _Out_ char              *key_str)
{
    uint32_t buffer_db_index = 0;

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_buffer_profile, SAI_OBJECT_TYPE_BUFFER_PROFILE, &buffer_db_index, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid buffer profile");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "profile index:0x%x", buffer_db_index);
    }
}

static void log_buffer_profile_refs(_In_ mlnx_affect_port_buff_items_t const* refs)
{
    uint32_t ind;

    SX_LOG_ENTER();

    for (ind = 0; ind < buffer_limits.num_port_pg_buff; ind++) {
        if (refs->pgs[ind]) {
            SX_LOG_DBG("pg[%d]\n", ind);
        }
    }
    for (ind = 0; ind < buffer_limits.num_port_queue_buff; ind++) {
        if (refs->tcs[ind]) {
            SX_LOG_DBG("tc[%d]\n", ind);
        }
    }
    for (ind = 0; ind < buffer_limits.num_ingress_pools; ind++) {
        if (refs->i_port_buffers[ind]) {
            SX_LOG_DBG("i_port_buffers[%d]\n", ind);
        }
    }
    for (ind = 0; ind < buffer_limits.num_egress_pools; ind++) {
        if (refs->e_port_buffers[ind]) {
            SX_LOG_DBG("e_port_buffers[%d]\n", ind);
        }
    }
    SX_LOG_EXIT();
}

static void log_sx_pool_mode(_In_ sx_cos_buffer_max_mode_e mode)
{
    if (SX_COS_BUFFER_MAX_MODE_STATIC_E == mode) {
        SX_LOG_DBG("SX_COS_BUFFER_MAX_MODE_STATIC_E\n");
    }
    if (SX_COS_BUFFER_MAX_MODE_DYNAMIC_E == mode) {
        SX_LOG_DBG("SX_COS_BUFFER_MAX_MODE_DYNAMIC_E\n");
    }
}

static void log_sx_shared_max_size(sx_cos_buffer_max_t max)
{
    SX_LOG_ENTER();

    log_sx_pool_mode(max.mode);

    if ((SX_COS_BUFFER_MAX_MODE_STATIC_E == max.mode) || (SX_COS_BUFFER_MAX_MODE_BUFFER_UNITS_E == max.mode)) {
        SX_LOG_DBG("size:%d\n", max.max.size);
    } else if (SX_COS_BUFFER_MAX_MODE_DYNAMIC_E == max.mode) {
        SX_LOG_DBG("alpha:%d\n", max.max.alpha);
    } else {
        SX_LOG_WRN("Unknown max.mode:%d\n", max.mode);
    }

    SX_LOG_EXIT();
}

static sai_status_t log_sai_shared_max_size(mlnx_sai_shared_max_size_t shared_max_size)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    switch (shared_max_size.mode) {
    case SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC:
        SX_LOG_DBG("mode:SAI_BUFFER_THRESHOLD_MODE_STATIC static_th:%u\n", shared_max_size.max.static_th);
        break;

    case SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC:
        SX_LOG_DBG("mode:SAI_BUFFER_THRESHOLD_MODE_DYNAMIC alpha:%d\n", shared_max_size.max.alpha);
        break;

    default:
        SX_LOG_ERR("Invalid shared max size mode specified:%d", shared_max_size.mode);
        sai_status = SAI_STATUS_INVALID_PARAMETER;
    }

    SX_LOG_EXIT();
    return sai_status;
}

void log_sx_port_buffers(uint32_t                   port_ind,
                         uint32_t                   sx_port_buffer_attr_cnt,
                         sx_cos_port_buffer_attr_t* sx_port_buff_attr)
{
    uint32_t buff_ind;

    SX_LOG_ENTER();
    SX_LOG_DBG("port_db[%d].logical:%x, sx buffer count:%d.\n",
               port_ind, g_sai_db_ptr->ports_db[port_ind].logical, sx_port_buffer_attr_cnt);

    for (buff_ind = 0; buff_ind < sx_port_buffer_attr_cnt; buff_ind++) {
        SX_LOG_DBG("item %d[\n", buff_ind);
        switch (sx_port_buff_attr[buff_ind].type) {
        case SX_COS_INGRESS_PORT_ATTR_E:
            SX_LOG_DBG("type:SX_COS_INGRESS_PORT_ATTR_E size:%d pool_id:%d]\n",
                       sx_port_buff_attr[buff_ind].attr.ingress_port_buff_attr.size,
                       sx_port_buff_attr[buff_ind].attr.ingress_port_buff_attr.pool_id);
            break;

        case SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E:
            SX_LOG_DBG("type:SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E size:%d pg:%d\n",
                       sx_port_buff_attr[buff_ind].attr.ingress_port_pg_buff_attr.size,
                       sx_port_buff_attr[buff_ind].attr.ingress_port_pg_buff_attr.pg);
            SX_LOG_DBG("is_lossy:%d xon:%d xoff:%d pool_id:%d use_shared_headroom:%s]\n",
                       sx_port_buff_attr[buff_ind].attr.ingress_port_pg_buff_attr.is_lossy,
                       sx_port_buff_attr[buff_ind].attr.ingress_port_pg_buff_attr.xon,
                       sx_port_buff_attr[buff_ind].attr.ingress_port_pg_buff_attr.xoff,
                       sx_port_buff_attr[buff_ind].attr.ingress_port_pg_buff_attr.pool_id,
                       sx_port_buff_attr[buff_ind].attr.ingress_port_pg_buff_attr.use_shared_headroom ?
                       "true" : "false");
            break;

        case SX_COS_EGRESS_PORT_ATTR_E:
            SX_LOG_DBG("type:SX_COS_EGRESS_PORT_ATTR_E size:%d pool_id:%d]\n",
                       sx_port_buff_attr[buff_ind].attr.egress_port_buff_attr.size,
                       sx_port_buff_attr[buff_ind].attr.egress_port_buff_attr.pool_id);
            break;

        case SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E:
            SX_LOG_DBG("type:SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E pool_id:%d size:%d tc:%d]\n",
                       sx_port_buff_attr[buff_ind].attr.egress_port_tc_buff_attr.pool_id,
                       sx_port_buff_attr[buff_ind].attr.egress_port_tc_buff_attr.size,
                       sx_port_buff_attr[buff_ind].attr.egress_port_tc_buff_attr.tc);
            break;

        case SX_COS_MULTICAST_ATTR_E:
            SX_LOG_DBG("type:SX_COS_MULTICAST_ATTR_E pool_id:%d size:%d sp:%d]\n",
                       sx_port_buff_attr[buff_ind].attr.multicast_buff_attr.pool_id,
                       sx_port_buff_attr[buff_ind].attr.multicast_buff_attr.size,
                       sx_port_buff_attr[buff_ind].attr.multicast_buff_attr.sp);
            break;

        case SX_COS_MULTICAST_PORT_ATTR_E:
            SX_LOG_DBG("type:SX_COS_MULTICAST_PORT_ATTR_E size:%d]\n",
                       sx_port_buff_attr[buff_ind].attr.multicast_port_buff_attr.size);
            break;

        case SX_COS_PORT_SHARED_HEADROOM_E:
            SX_LOG_DBG("type:SX_COS_PORT_SHARED_HEADROOM_E size:%d\n",
                       sx_port_buff_attr[buff_ind].attr.port_shared_headroom_attr.size);
            SX_LOG_DBG("xon:%d xoff:%d shared_pool_id:%d max_pool_loan:%d]\n",
                       sx_port_buff_attr[buff_ind].attr.port_shared_headroom_attr.xon,
                       sx_port_buff_attr[buff_ind].attr.port_shared_headroom_attr.xoff,
                       sx_port_buff_attr[buff_ind].attr.port_shared_headroom_attr.shared_pool_id,
                       sx_port_buff_attr[buff_ind].attr.port_shared_headroom_attr.max_pool_loan);
            break;

        default:
            SX_LOG_DBG("Unknown buff type %d %d\n", sx_port_buff_attr[buff_ind].type, buff_ind);
        }
    }

    SX_LOG_EXIT();
}

void log_sx_port_shared_buffers(uint32_t                          port_ind,
                                uint32_t                          sx_port_shared_buffer_attr_cnt,
                                sx_cos_port_shared_buffer_attr_t* sx_port_shared_buff_attr)
{
    uint32_t buff_ind;

    SX_LOG_ENTER();
    SX_LOG_DBG("port_db[%d].logical:%x, sx buffer count:%d.\n",
               port_ind, g_sai_db_ptr->ports_db[port_ind].logical, sx_port_shared_buffer_attr_cnt);

    for (buff_ind = 0; buff_ind < sx_port_shared_buffer_attr_cnt; buff_ind++) {
        SX_LOG_DBG("item %d[\n", buff_ind);
        switch (sx_port_shared_buff_attr[buff_ind].type) {
        case SX_COS_INGRESS_PORT_ATTR_E:
            SX_LOG_DBG("type:SX_COS_INGRESS_PORT_ATTR_E\n");
            log_sx_shared_max_size(sx_port_shared_buff_attr[buff_ind].attr.ingress_port_shared_buff_attr.max);
            SX_LOG_DBG("pool_id:%d]\n", sx_port_shared_buff_attr[buff_ind].attr.ingress_port_shared_buff_attr.pool_id);
            break;

        case SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E:
            SX_LOG_DBG("type:SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E\n");
            log_sx_shared_max_size(sx_port_shared_buff_attr[buff_ind].attr.ingress_port_pg_shared_buff_attr.max);
            SX_LOG_DBG("pg:%d pool_id:%d]\n",
                       sx_port_shared_buff_attr[buff_ind].attr.ingress_port_pg_shared_buff_attr.pg,
                       sx_port_shared_buff_attr[buff_ind].attr.ingress_port_pg_shared_buff_attr.pool_id);
            break;

        case SX_COS_EGRESS_PORT_ATTR_E:
            SX_LOG_DBG("type:SX_COS_EGRESS_PORT_ATTR_E\n");
            log_sx_shared_max_size(sx_port_shared_buff_attr[buff_ind].attr.egress_port_shared_buff_attr.max);
            SX_LOG_DBG("pool_id:%d]\n", sx_port_shared_buff_attr[buff_ind].attr.egress_port_shared_buff_attr.pool_id);
            break;

        case SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E:
            SX_LOG_DBG("type:SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E\n");
            log_sx_shared_max_size(sx_port_shared_buff_attr[buff_ind].attr.egress_port_tc_shared_buff_attr.max);
            SX_LOG_DBG("tc:%d pool_id:%d]\n",
                       sx_port_shared_buff_attr[buff_ind].attr.egress_port_tc_shared_buff_attr.tc,
                       sx_port_shared_buff_attr[buff_ind].attr.egress_port_tc_shared_buff_attr.pool_id);
            break;

        case SX_COS_MULTICAST_ATTR_E:
            SX_LOG_DBG("type:SX_COS_MULTICAST_ATTR_E\n");
            log_sx_shared_max_size(sx_port_shared_buff_attr[buff_ind].attr.multicast_shared_buff_attr.max);
            SX_LOG_DBG("sp:%d pool_id:%d]\n", sx_port_shared_buff_attr[buff_ind].attr.multicast_shared_buff_attr.sp,
                       sx_port_shared_buff_attr[buff_ind].attr.multicast_shared_buff_attr.pool_id);
            break;

        case SX_COS_MULTICAST_PORT_ATTR_E:
            SX_LOG_DBG("type:SX_COS_MULTICAST_PORT_ATTR_E]\n");
            log_sx_shared_max_size(sx_port_shared_buff_attr[buff_ind].attr.multicast_port_shared_buff_attr.max);
            break;

        default:
            SX_LOG_DBG("Unknown buff type %d %d\n", sx_port_shared_buff_attr[buff_ind].type, buff_ind);
        }
    }

    SX_LOG_EXIT();
}

static void log_sai_pool_attribs(_In_ const mlnx_sai_buffer_pool_attr_t *sai_pool_attr)
{
    SX_LOG_ENTER();
    SX_LOG_DBG("sx_pool_id:%d %s %s pool_size:%d is_shp_mapped: %s\n", sai_pool_attr->sx_pool_id,
               (SAI_BUFFER_POOL_TYPE_INGRESS == sai_pool_attr->pool_type) ?
               "SAI_BUFFER_POOL_TYPE_INGRESS" : "SAI_BUFFER_POOL_TYPE_EGRESS",
               (SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC == sai_pool_attr->pool_mode) ?
               "SAI_BUFFER_THRESHOLD_MODE_STATIC" : "SAI_BUFFER_THRESHOLD_MODE_DYNAMIC",
               sai_pool_attr->pool_size,
               sai_pool_attr->is_shp_mapped ? "TRUE" : "FALSE");
    SX_LOG_EXIT();
}

sai_status_t log_sai_pool_data(_In_ sai_object_id_t sai_pool)
{
    sai_status_t                sai_status;
    char                        key_str[MAX_KEY_STR_LEN];
    mlnx_sai_buffer_pool_attr_t sai_pool_attr;

    SX_LOG_ENTER();
    pool_key_to_str(sai_pool, key_str);
    sai_status = mlnx_get_sai_pool_data(sai_pool, &sai_pool_attr);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_EXIT();
        return sai_status;
    }
    log_sai_pool_attribs(&sai_pool_attr);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t log_sai_buffer_profile_db_entry_fields(_In_ const mlnx_sai_db_buffer_profile_entry_t *db_buff)
{
    sai_status_t sai_status;
    char         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    pool_key_to_str(db_buff->sai_pool, key_str);
    SX_LOG_DBG("is_valid:%d SAI pool:0x%" PRIx64 " pool data:%s reserved_size:%d xon:%d xoff:%d\n", db_buff->is_valid,
               db_buff->sai_pool, key_str, db_buff->reserved_size, db_buff->xon, db_buff->xoff);
    sai_status = log_sai_shared_max_size(db_buff->shared_max);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t log_sai_buffer_profile_db_entry(_In_ uint32_t db_buffer_profile_index)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();
    if (db_buffer_profile_index >= mlnx_sai_get_buffer_profile_number()) {
        SX_LOG_ERR("Invalid db_buffer_profile_index:%d\n", db_buffer_profile_index);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    const mlnx_sai_db_buffer_profile_entry_t *db_buff = &g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index];

    SX_LOG_DBG("db_buffer_profile_index:0x%X\n", db_buffer_profile_index);
    sai_status = log_sai_buffer_profile_db_entry_fields(db_buff);

    SX_LOG_EXIT();
    return sai_status;
}

static bool is_valid_buffer_profile_db_entry(_In_ uint32_t db_buffer_profile_index)
{
    SX_LOG_ENTER();
    SX_LOG_DBG("db_buffer_profile_index:0x%X \n", db_buffer_profile_index);
    if (mlnx_sai_get_buffer_profile_number() <= db_buffer_profile_index) {
        SX_LOG_ERR("buffer profile index exceeds range:0x%X \n", mlnx_sai_get_buffer_profile_number());
        SX_LOG_EXIT();
        return false;
    }
    if (!g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].is_valid) {
        SX_LOG_ERR("buffer profile at index :0x%X is marked as unused\n", db_buffer_profile_index);
        SX_LOG_EXIT();
        return false;
    }
    SX_LOG_EXIT();
    return true;
}
static sai_status_t is_valid_buffer_profile(_In_ sai_object_id_t sai_buffer)
{
    uint32_t     db_buffer_profile_index;
    sai_status_t sai_status;

    SX_LOG_ENTER();
    SX_LOG_DBG("Input sai buffer:0x%" PRIx64 ", \n", sai_buffer);
    if (SAI_NULL_OBJECT_ID == sai_buffer) {
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_buffer, SAI_OBJECT_TYPE_BUFFER_PROFILE, &db_buffer_profile_index, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (!is_valid_buffer_profile_db_entry(db_buffer_profile_index)) {
        SX_LOG_ERR("Input sai buffer:0x%" PRIx64 ", db_buffer_profile_index:0x%X, refers to invalid entry\n",
                   sai_buffer, db_buffer_profile_index);
        sai_status = SAI_STATUS_FAILURE;
    }
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t get_buffer_profile_db_index(_In_ sai_object_id_t oid, _Out_ uint32_t* db_index)
{
    sai_status_t sai_status;
    uint32_t     input_db_buffer_profile_index;
    char         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();
    if (NULL == db_index) {
        SX_LOG_ERR("NULL db_index\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_NULL_OBJECT_ID == oid) {
        /* point to sentinel entry in buffer_db */
        SX_LOG_DBG("Input buffer profile is NULL\n");
        *db_index = SENTINEL_BUFFER_DB_ENTRY_INDEX;
        return SAI_STATUS_SUCCESS;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = is_valid_buffer_profile(oid))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    buffer_profile_key_to_str(oid, key_str);
    SX_LOG_DBG("SAI buffer profile id:%s\n", key_str);
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(oid, SAI_OBJECT_TYPE_BUFFER_PROFILE, &input_db_buffer_profile_index, NULL))) {
        SX_LOG_ERR("Failed to obtain input buffer profile's db index\n");
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SENTINEL_BUFFER_DB_ENTRY_INDEX == input_db_buffer_profile_index) {
        SX_LOG_ERR("Invalid Buffer profile db reference. Make sure buffer configuration was initialized.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_DBG("Input buffer profile:0x%" PRIx64 ", db index:%d\n", oid, input_db_buffer_profile_index);
    *db_index = input_db_buffer_profile_index;
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t log_sai_buffer_profile(_In_ sai_object_id_t sai_buffer_profile)
{
    sai_status_t sai_status;
    uint32_t     input_db_buffer_profile_index = 0;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(sai_buffer_profile, &input_db_buffer_profile_index))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    sai_status = log_sai_buffer_profile_db_entry(input_db_buffer_profile_index);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t get_pg_data(_In_ sai_object_id_t sai_pg,
                                _Out_ uint32_t     * db_port_index,
                                _Out_ uint32_t     * port_pg_index)
{
    sai_status_t sai_status;
    uint8_t      extended_data[EXTENDED_DATA_SIZE];

    SX_LOG_ENTER();

    if (NULL == db_port_index) {
        SX_LOG_ERR("NULL db_port_index\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (NULL == port_pg_index) {
        SX_LOG_ERR("NULL port_pg_index\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(sai_pg, SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, db_port_index, extended_data))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (extended_data[0] >= buffer_limits.num_port_pg_buff) {
        SX_LOG_ERR("Invalid pg index:%d, found for db_port_index:%d\n", extended_data[0], *db_port_index);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (*db_port_index >= MAX_PORTS) {
        SX_LOG_ERR("Invalid db_port_index:%d, for pg_index:%d\n", *db_port_index, extended_data[0]);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *port_pg_index = extended_data[0];
    SX_LOG_DBG("PG details: db_port_index:%d, pg_index:%d\n", *db_port_index, *port_pg_index);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
static sai_status_t mlnx_pg_set_null_profile(uint32_t db_port_index,
                                             uint32_t port_pg_index,
                                             uint32_t current_pg_profile_ind)
{
    sai_status_t                       status;
    mlnx_port_config_t                *port;
    sx_cos_port_buffer_attr_t          pgs_buff_reserved_attr[2] = {0};
    sx_cos_port_shared_buffer_attr_t   pgs_buff_shared_attr[2] = {0};
    uint32_t                           reserved_attr_count = 0, shared_attr_count = 0;
    mlnx_affect_port_buff_items_t      affected_items = {0};
    sai_object_id_t                    default_ingress_pool;
    mlnx_sai_db_buffer_profile_entry_t buff_db_entry = {0};
    uint32_t                           cells_coeff = 1;
    uint32_t                           max_pool_loan;
    mlnx_sai_buffer_pool_attr_t        sai_shp_pool_attr = {0};
    sai_object_id_t                    current_sai_pool;

    SX_LOG_ENTER();

    port = mlnx_port_by_idx(db_port_index);

    status = mlnx_sai_buffer_construct_pg_buffer_attr(port, port_pg_index, &pgs_buff_reserved_attr[0],
                                                      &reserved_attr_count, &pgs_buff_shared_attr[0],
                                                      &shared_attr_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to construct lossy PG%d buffers attributes \n", port_pg_index);
        return status;
    }

    current_sai_pool = g_sai_buffer_db_ptr->buffer_profiles[current_pg_profile_ind].sai_pool;
    if ((current_sai_pool != SAI_NULL_OBJECT_ID) &&
        (current_sai_pool == g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id)) {
        if (!alloc_affected_items(&affected_items)) {
            return SAI_STATUS_NO_MEMORY;
        }

        affected_items.pgs[port_pg_index] = true;
        affected_items.affected_count = 1;

        status = mlnx_create_sai_pool_id(g_sai_buffer_db_ptr->buffer_pool_ids.default_ingress_pool_id,
                                         &default_ingress_pool);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create default ingress sai pool id\n");
            goto out;
        }

        status = mlnx_sai_buffer_port_psb_cells_coefficient_get(&port->logical, &cells_coeff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get port %d shared buffer coefficient\n", port->logical);
            goto out;
        }

        buff_db_entry.is_valid = true;
        buff_db_entry.sai_pool = default_ingress_pool;

        status = mlnx_sai_buffer_calculate_psb_max_pool_loan(&affected_items,
                                                             &buff_db_entry,
                                                             cells_coeff,
                                                             db_port_index,
                                                             &max_pool_loan);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to calculate max port %d shared buffer pool loan\n", port->logical);
            goto out;
        }

        status = mlnx_get_sai_pool_data(g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id, &sai_shp_pool_attr);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get shared headroom pool data\n");
            goto out;
        }

        pgs_buff_reserved_attr[1].type = SX_COS_PORT_SHARED_HEADROOM_E;

        status = mlnx_sai_buffer_construct_psb_sx_attr_internal(
            &pgs_buff_reserved_attr[1].attr.port_shared_headroom_attr, sai_shp_pool_attr.sx_pool_id,
            max_pool_loan, &port->logical);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to construct port shared buffer attribute for port %d\n", port->logical);
            goto out;
        }

        reserved_attr_count++;
    }

    status = mlnx_sai_buffer_configure_buffers(port, pgs_buff_reserved_attr, reserved_attr_count, pgs_buff_shared_attr,
                                               shared_attr_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to configure empty buffer profile on port index %d pg index %d\n", db_port_index,
                   port_pg_index);
        goto out;
    }

out:
    free_affected_items(&affected_items);

    return status;
}

static sai_status_t pg_profile_set(uint32_t db_port_index, uint32_t port_pg_ind, sai_object_id_t profile)
{
    sai_status_t                       sai_status;
    uint32_t                           input_db_buffer_profile_index = 0;
    uint16_t                           pg_buffer_db_ind = 0;
    mlnx_sai_db_buffer_profile_entry_t buff_db_entry;
    mlnx_sai_buffer_pool_attr_t        sai_pool_attr;
    uint32_t                         * port_pg_profile_refs = NULL;

    SX_LOG_ENTER();

    sai_db_write_lock();

    sai_status = mlnx_sai_get_port_buffer_index_array(db_port_index, PORT_BUFF_TYPE_PG, &port_pg_profile_refs);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get port buffer index array for port db index %d\n", db_port_index);
        goto out;
    }

    if (SAI_NULL_OBJECT_ID == profile) {
        if (mlnx_sai_buffer_get_pool_create_triggered_flag()) {
            SX_LOG_DBG("Resetting buffer profile reference on port[%d].pg[%d]\n", db_port_index, port_pg_ind);

            sai_status = mlnx_pg_set_null_profile(db_port_index, port_pg_ind, port_pg_profile_refs[port_pg_ind]);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Failed to set pg null profile for port index %d pg index %d\n", db_port_index,
                           port_pg_ind);
                goto out;
            }

            port_pg_profile_refs[port_pg_ind] = SENTINEL_BUFFER_DB_ENTRY_INDEX;
        }
    } else {
        sai_status = mlnx_get_sai_buffer_profile_data(profile, &input_db_buffer_profile_index, &sai_pool_attr);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to get sai buffer profile data for buffer profile 0x%" PRIx64 "\n", profile);
            goto out;
        }

        buff_db_entry = g_sai_buffer_db_ptr->buffer_profiles[input_db_buffer_profile_index];

        /* buffer profile attached to PG must be INGRESS buffer*/
        if (SAI_BUFFER_POOL_TYPE_INGRESS != sai_pool_attr.pool_type) {
            SX_LOG_ERR(
                "Buffer profile:0x%" PRIx64 " refers to EGRESS pool:0x%" PRIx64 ", Cannot be set on PG:port:%u, PG index : %u\n",
                profile,
                g_sai_buffer_db_ptr->buffer_profiles[input_db_buffer_profile_index].sai_pool,
                db_port_index,
                port_pg_ind);
            sai_status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
        pg_buffer_db_ind = port_pg_profile_refs[port_pg_ind];
        SX_LOG_DBG("port_db[%d] pg index:%d, pg->buffer_profile db_ind:0x%X. input buffer profile index:%d\n",
                   db_port_index, port_pg_ind, pg_buffer_db_ind, input_db_buffer_profile_index);

        /* For diagnostic purposes  */
        if (SENTINEL_BUFFER_DB_ENTRY_INDEX == pg_buffer_db_ind) {
            SX_LOG_DBG("replace NULL pg_buffer index with index:0x%X\n", input_db_buffer_profile_index);
        } else {
            SX_LOG_DBG("previous buffer profile db_ind:%d, new buffer profile index:0x%X\n",
                       pg_buffer_db_ind, input_db_buffer_profile_index);
        }

        sai_status = mlnx_sai_buffer_apply_buffer_to_pg(db_port_index, port_pg_ind, buff_db_entry);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to apply buffer profile for port index %d pg index %d\n", db_port_index, port_pg_ind);
            return sai_status;
        }

        port_pg_profile_refs[port_pg_ind] = input_db_buffer_profile_index;
        SX_LOG_DBG("Logging newly set buffer profile\n");
        log_sai_buffer_profile_db_entry(input_db_buffer_profile_index);
    }

out:
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return sai_status;
}

/** buffer profile pointer [sai_object_id_t] */
static sai_status_t mlnx_sai_set_ingress_priority_group_buffer_profile_attr(_In_ const sai_object_key_t      * key,
                                                                            _In_ const sai_attribute_value_t * value,
                                                                            void                             * arg)
{
    sai_status_t sai_status;
    uint32_t     db_port_index = 0;
    uint32_t     port_pg_ind = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (sai_status = get_pg_data(key->key.object_id, &db_port_index, &port_pg_ind))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    return pg_profile_set(db_port_index, port_pg_ind, value->oid);
}

/** port [sai_object_id_t]
 *  PG index [sai_uint8_t] */
static sai_status_t mlnx_sai_get_ingress_priority_group_attrib(_In_ const sai_object_key_t   * key,
                                                               _Inout_ sai_attribute_value_t * value,
                                                               _In_ uint32_t                   attr_index,
                                                               _Inout_ vendor_cache_t        * cache,
                                                               void                          * arg)
{
    uint32_t            db_port_index = 0;
    uint32_t            port_pg_ind = 0;
    sai_status_t        status;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    assert((SAI_INGRESS_PRIORITY_GROUP_ATTR_INDEX == (long)arg) ||
           (SAI_INGRESS_PRIORITY_GROUP_ATTR_PORT == (long)arg));

    if (SAI_STATUS_SUCCESS != (status = get_pg_data(key->key.object_id, &db_port_index, &port_pg_ind))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_INGRESS_PRIORITY_GROUP_ATTR_INDEX == (long)arg) {
        value->u8 = port_pg_ind;
    } else {
        sai_db_read_lock();
        port = mlnx_port_by_idx(db_port_index);
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, port->logical, NULL, &value->oid))) {
            sai_db_unlock();
            SX_LOG_EXIT();
            return status;
        }
        sai_db_unlock();
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** buffer profile pointer [sai_object_id_t] */
static sai_status_t mlnx_sai_get_ingress_priority_group_buffer_profile_attr(_In_ const sai_object_key_t   * key,
                                                                            _Inout_ sai_attribute_value_t * value,
                                                                            _In_ uint32_t                   attr_index,
                                                                            _Inout_ vendor_cache_t        * cache,
                                                                            void                          * arg)
{
    sai_status_t sai_status;
    uint32_t     db_port_index = 0;
    uint32_t     port_pg_ind = 0;
    uint16_t     pg_buffer_db_ind = 0;
    uint32_t   * port_pg_profile_refs = NULL;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS != (sai_status = get_pg_data(key->key.object_id, &db_port_index, &port_pg_ind))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_get_port_buffer_index_array(db_port_index, PORT_BUFF_TYPE_PG, &port_pg_profile_refs))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    pg_buffer_db_ind = port_pg_profile_refs[port_pg_ind];
    if (SENTINEL_BUFFER_DB_ENTRY_INDEX == pg_buffer_db_ind) {
        value->oid = SAI_NULL_OBJECT_ID;
    } else {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_BUFFER_PROFILE, pg_buffer_db_ind, NULL, &value->oid))) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            SX_LOG_EXIT();
            return sai_status;
        }
    }
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Create ingress priority group
 *
 * @param[out] ingress_pg_id Ingress priority group
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_ingress_priority_group(_Out_ sai_object_id_t     * ingress_pg_id,
                                                       _In_ sai_object_id_t        switch_id,
                                                       _In_ uint32_t               attr_count,
                                                       _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *buff_profile_attr = NULL;
    const sai_attribute_value_t *index_attr = NULL;
    const sai_attribute_value_t *port_attr = NULL;
    uint32_t                     buff_profile_idx;
    uint32_t                     index_idx;
    uint32_t                     port_idx;
    sx_port_log_id_t             port_id;
    sai_status_t                 status;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    uint32_t                     db_port_index;
    uint8_t                      extended_data[EXTENDED_DATA_SIZE];

    SX_LOG_ENTER();

    if (ingress_pg_id == NULL) {
        SX_LOG_ERR("Invalid NULL ingress pg id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, pg_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_attr_list_to_str(attr_count,
                         attr_list,
                         SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP,
                         MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create PG, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_INGRESS_PRIORITY_GROUP_ATTR_PORT, &port_attr, &port_idx);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_object_to_type(port_attr->oid, SAI_OBJECT_TYPE_PORT, &port_id, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    status =
        find_attrib_in_list(attr_count, attr_list, SAI_INGRESS_PRIORITY_GROUP_ATTR_INDEX, &index_attr, &index_idx);
    assert(SAI_STATUS_SUCCESS == status);

    if (index_attr->u8 >= buffer_limits.num_port_pg_buff) {
        SX_LOG_ERR("Invalid pg index:%d\n", index_attr->u8);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + index_idx;
    }

    sai_db_read_lock();

    status = mlnx_port_idx_by_log_id(port_id, &db_port_index);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        goto out;
    }

    sai_db_unlock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE,
                                 &buff_profile_attr, &buff_profile_idx);

    if (!SAI_ERR(status)) {
        status = pg_profile_set(db_port_index, index_attr->u8, buff_profile_attr->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set profile for PG\n");
            goto out;
        }
    }

    extended_data[0] = index_attr->u8;
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, db_port_index, extended_data,
                                     ingress_pg_id))) {
        SX_LOG_EXIT();
        return status;
    }
    pg_key_to_str(*ingress_pg_id, key_str);
    SX_LOG_NTC("Created %s\n", key_str);

out:
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove ingress priority group
 *
 * @param[in] ingress_pg_id Ingress priority group
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_ingress_priority_group(_In_ sai_object_id_t ingress_pg_id)
{
    char         key_str[MAX_KEY_STR_LEN];
    sai_status_t status;
    uint32_t     db_port_index = 0;
    uint32_t     port_pg_ind = 0;

    SX_LOG_ENTER();

    pg_key_to_str(ingress_pg_id, key_str);

    SX_LOG_NTC("Remove %s\n", key_str);

    if (SAI_STATUS_SUCCESS != (status = get_pg_data(ingress_pg_id, &db_port_index, &port_pg_ind))) {
        SX_LOG_EXIT();
        return status;
    }

    status = pg_profile_set(db_port_index, port_pg_ind, SAI_NULL_OBJECT_ID);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to reset profile for PG\n");
        return status;
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_sai_get_ingress_priority_group_attr(_In_ sai_object_id_t      ingress_pg_id,
                                                             _In_ uint32_t             attr_count,
                                                             _Inout_ sai_attribute_t * attr_list)
{
    const sai_object_key_t key = { .key.object_id = ingress_pg_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();
    pg_key_to_str(ingress_pg_id, key_str);
    sai_status = sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP,
                                    pg_vendor_attribs, attr_count, attr_list);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_set_ingress_priority_group_attr(_In_ sai_object_id_t        ingress_pg_id,
                                                             _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = ingress_pg_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();
    pg_key_to_str(ingress_pg_id, key_str);
    sai_status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, pg_vendor_attribs, attr);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t convert_sai_pool_type_to_sx_pool_direction(_In_ sai_buffer_pool_type_t              sai_pool_type,
                                                               _Out_ sx_cos_port_buff_pool_direction_e* sx_pool_direction)
{
    SX_LOG_DBG("Input pool type:%d\n", sai_pool_type);
    switch (sai_pool_type) {
    case SAI_BUFFER_POOL_TYPE_INGRESS:
        *sx_pool_direction = SX_COS_PORT_BUFF_POOL_DIRECTION_INGRESS_E;
        break;

    case SAI_BUFFER_POOL_TYPE_EGRESS:
        *sx_pool_direction = SX_COS_PORT_BUFF_POOL_DIRECTION_EGRESS_E;
        break;

    default:
        SX_LOG_ERR("Invalid value for sai pool direction specified:%d\n", sai_pool_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t convert_sai_pool_mode_to_sx_pool_mode(_In_ sai_buffer_pool_threshold_mode_t sai_pool_mode,
                                                          _Out_ sx_cos_buffer_max_mode_e      * sx_pool_mode)
{
    if (NULL == sx_pool_mode) {
        SX_LOG_ERR("NULL sx_pool_mode\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    switch (sai_pool_mode) {
    case SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC:
        *sx_pool_mode = SX_COS_BUFFER_MAX_MODE_STATIC_E;
        break;

    case SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC:
        *sx_pool_mode = SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
        break;

    default:
        SX_LOG_ERR("Invalid sai pool mode specified:%d\n", sai_pool_mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t convert_sx_pool_mode_to_sai_pool_mode(_In_ sx_cos_buffer_max_mode_e           sx_pool_mode,
                                                          _Out_ sai_buffer_pool_threshold_mode_t* sai_pool_mode)
{
    if (NULL == sai_pool_mode) {
        SX_LOG_ERR("NULL sai_pool_mode\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    switch (sx_pool_mode) {
    case SX_COS_BUFFER_MAX_MODE_STATIC_E:
        *sai_pool_mode = SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC;
        break;

    case SX_COS_BUFFER_MAX_MODE_DYNAMIC_E:
        *sai_pool_mode = SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC;
        break;

    case SX_COS_BUFFER_MAX_MODE_BUFFER_UNITS_E:
        /* stub until SAI API change */
        *sai_pool_mode = SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC;
        break;

    default:
        SX_LOG_ERR("Invalid sx pool mode specified:%d\n", sx_pool_mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    SX_LOG_DBG("sai_pool_mode:%d\n", *sai_pool_mode);
    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t convert_sx_pool_dir_to_sai_pool_type(_In_ sx_cos_port_buff_pool_direction_e sx_pool_direction,
                                                         _Out_ sai_buffer_pool_type_t         * sai_pool_type)
{
    if (NULL == sai_pool_type) {
        SX_LOG_ERR("NULL sai_pool_type\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SX_COS_PORT_BUFF_POOL_DIRECTION_INGRESS_E == sx_pool_direction) {
        *sai_pool_type = SAI_BUFFER_POOL_TYPE_INGRESS;
    } else if (SX_COS_PORT_BUFF_POOL_DIRECTION_EGRESS_E == sx_pool_direction) {
        *sai_pool_type = SAI_BUFFER_POOL_TYPE_EGRESS;
    } else {
        SX_LOG_ERR("Invalid sx_pool direction specified:%d\n", sx_pool_direction);
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_DBG("sai_pool_type:%d\n", *sai_pool_type);
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_sai_pool_id(_In_ uint32_t sx_pool_id, _Out_ sai_object_id_t*    sai_pool)
{
    sai_status_t sai_status;

    SX_LOG_ENTER();
    if (NULL == sai_pool) {
        SX_LOG_ERR("NULL sai_pool\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (buffer_limits.num_total_pools <= sx_pool_id) {
        SX_LOG_ERR("Invalid sx_pool_id:%d\n", sx_pool_id);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    sai_status = mlnx_create_object(SAI_OBJECT_TYPE_BUFFER_POOL, sx_pool_id, NULL, sai_pool);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_get_sai_buffer_profile_data(_In_ sai_object_id_t               sai_buffer,
                                                     _Out_ uint32_t                   * out_db_buffer_profile_index,
                                                     _Out_ mlnx_sai_buffer_pool_attr_t* sai_pool_attr)
{
    sai_status_t                sai_status;
    uint32_t                    input_db_buffer_profile_index;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr_local;

    SX_LOG_ENTER();

    sai_status = get_buffer_profile_db_index(sai_buffer, &input_db_buffer_profile_index);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get buffer profile db index for sai buffer 0x%" PRIx64 "\n", sai_buffer);
        goto out;
    }

    sai_status = mlnx_get_sai_pool_data(g_sai_buffer_db_ptr->buffer_profiles[input_db_buffer_profile_index].sai_pool,
                                        &sai_pool_attr_local);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get pool data for sai pool 0x%" PRIx64 "\n",
                   g_sai_buffer_db_ptr->buffer_profiles[input_db_buffer_profile_index].sai_pool);
        goto out;
    }

    if (sai_pool_attr) {
        *sai_pool_attr = sai_pool_attr_local;
    }
    if (out_db_buffer_profile_index) {
        *out_db_buffer_profile_index = input_db_buffer_profile_index;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

/* DB read lock is needed */
sai_status_t mlnx_get_sai_pool_data(_In_ sai_object_id_t sai_pool, _Out_ mlnx_sai_buffer_pool_attr_t *sai_pool_attr)
{
    sx_status_t        sx_status = SX_STATUS_SUCCESS;
    sai_status_t       sai_status = SAI_STATUS_SUCCESS;
    char               key_str[MAX_KEY_STR_LEN] = "";
    uint32_t           sx_pool_id_local = 0;
    sx_cos_pool_attr_t sx_pool_attr = {0};

    SX_LOG_ENTER();
    memset(&sx_pool_attr, 0, sizeof(sx_cos_pool_attr_t));
    pool_key_to_str(sai_pool, key_str);
    SX_LOG_DBG("sai pool:%s\n", key_str);
    if (NULL == sai_pool_attr) {
        SX_LOG_ERR("NULL sai_pool_attr\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_pool, SAI_OBJECT_TYPE_BUFFER_POOL, &sx_pool_id_local, NULL))) {
        goto bail;
    }
    if (SX_STATUS_SUCCESS != (sx_status = sx_api_cos_shared_buff_pool_get(gh_sdk, sx_pool_id_local,  &sx_pool_attr))) {
        SX_LOG_ERR("Failed to get sx pool settings, sx_status:%d, message %s.\n", sx_status, SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto bail;
    }
    SX_LOG_DBG("sx pool_size:%d\n", sx_pool_attr.pool_size);

    sai_pool_attr->sx_pool_id = sx_pool_id_local;
    sai_pool_attr->pool_size = mlnx_cells_to_bytes(sx_pool_attr.pool_size);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = convert_sx_pool_mode_to_sai_pool_mode(sx_pool_attr.mode, &sai_pool_attr->pool_mode))) {
        goto bail;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = convert_sx_pool_dir_to_sai_pool_type(sx_pool_attr.pool_dir, &sai_pool_attr->pool_type))) {
        goto bail;
    }
    sai_pool_attr->is_shp_mapped = false;
    if ((SAI_BUFFER_POOL_TYPE_INGRESS == sai_pool_attr->pool_type) &&
        (g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created) &&
        (g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id == sai_pool)) {
        sai_pool_attr->is_shp_mapped = true;
    }

bail:
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t reset_port_buffer_db_data()
{
    uint32_t                 queue_ind;
    uint32_t                 port_ind;
    sai_status_t             sai_status;
    mlnx_qos_queue_config_t *queue_cfg = NULL;
    mlnx_port_config_t      *port;

    SX_LOG_ENTER();
    memset(g_sai_buffer_db_ptr->buffer_profiles, 0, g_sai_buffer_db_size);

    mlnx_port_phy_foreach(port, port_ind) {
        for (queue_ind = 0; queue_ind < buffer_limits.num_port_queue_buff; queue_ind++) {
            if (SAI_STATUS_SUCCESS != (sai_status = mlnx_queue_cfg_lookup(port->logical, queue_ind, &queue_cfg))) {
                SX_LOG_EXIT();
                return sai_status;
            }
            queue_cfg->buffer_id = SAI_NULL_OBJECT_ID;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_cleanup_buffer_config()
{
    sai_status_t sai_status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (sai_status = reset_port_buffer_db_data())) {
        SX_LOG_ERR("Failed resetting buffer db data\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_construct_shp_sx_attr_internal(_Out_ sx_cos_pool_attr_t *sx_pool_attr,
                                                                   _In_ uint64_t             pool_size)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();


    if (NULL == sx_pool_attr) {
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }

    sx_pool_attr->pool_dir = SX_COS_PORT_BUFF_POOL_DIRECTION_INGRESS_E;
    sx_pool_attr->pool_size = bytes_to_mlnx_cells((uint32_t)pool_size);
    sx_pool_attr->mode = SX_COS_BUFFER_MAX_MODE_BUFFER_UNITS_E;
    sx_pool_attr->buffer_type = SX_COS_SHARED_HEADROOM_BUFFER_E;
    sx_pool_attr->infinite_size = false;
    sx_pool_attr->pool_info = SX_COS_POOL_INFO_USER_SHARED_HEADROOM_POOL_E;

    SX_LOG_DBG("SHP size in bytes:%" PRIu64 ", cells:%d\n", pool_size, sx_pool_attr->pool_size);

bail:
    SX_LOG_EXIT();
    return sai_status;
}

/** 8x ports use 2 buffer units, so headroom configurations
 * should be 2x the configurations of a regular port.
 * PSB.size, PSB.Xon, PSB.Xoff should be 2x the values used in normal ports */
static sai_status_t mlnx_sai_buffer_port_psb_cells_coefficient_get(_In_ const sx_port_log_id_t *sx_port_logical,
                                                                   _Inout_ uint32_t            *coefficient)
{
    sai_status_t          sai_status = SAI_STATUS_SUCCESS;
    sai_attribute_value_t value = {0};
    uint32_t              split_lanes[8] = {0};

    SX_LOG_ENTER();

    value.u32list.list = &split_lanes[0];
    value.u32list.count = 8;

    if (!coefficient) {
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_sai_port_hw_lanes_get(sx_port_logical, &value))) {
        goto bail;
    }

    *coefficient = (8 == value.u8) ? 2 : 1;

bail:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_construct_psb_sx_attr_internal(
    _Out_ sx_cos_port_shared_headroom_attr_t *sx_psb_attr,
    _In_ sx_cos_pool_id_t                     sx_shp_pool_id,
    _In_ uint32_t                             max_pool_loan,
    _In_ const sx_port_log_id_t              *sx_port_logical_id)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     size = SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_MIN_SIZE;
    uint32_t     cells_coeff = 1;

    SX_LOG_ENTER();

    if (!sx_psb_attr) {
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }

    memset(sx_psb_attr, 0, sizeof(*sx_psb_attr));

    if (max_pool_loan) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_buffer_port_psb_cells_coefficient_get(sx_port_logical_id, &cells_coeff))) {
            goto bail;
        }
        sx_psb_attr->shared_pool_id = sx_shp_pool_id;
        sx_psb_attr->size = bytes_to_mlnx_cells(size * cells_coeff);
        sx_psb_attr->xon = SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_XON_INFINITE;
        sx_psb_attr->xoff = SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_XOFF_INFINITE;
        sx_psb_attr->max_pool_loan = bytes_to_mlnx_cells(max_pool_loan);
    }

    SX_LOG_DBG("PSB size(bytes):%d, (cells):%d, xon:%x, xoff:%x\n",
               size, sx_psb_attr->size, sx_psb_attr->xon, sx_psb_attr->xoff);
    SX_LOG_DBG("PSB pool_loan(bytes):%d, (cells):%d, shared_pool_id:%d \n",
               max_pool_loan, sx_psb_attr->max_pool_loan, sx_psb_attr->shared_pool_id);

bail:
    SX_LOG_EXIT();
    return sai_status;
}

/* requires sai_db write lock */
static sai_status_t mlnx_save_port_default_buffers_config()
{
    sx_status_t                      sx_status;
    mlnx_port_config_t              *port;
    uint32_t                         buffer_count = 2, ii;
    sx_cos_port_buffer_attr_t        sx_reserved_attr[2] = {0};
    sx_cos_port_shared_buffer_attr_t sx_shared_attr[2] = {0};

    SX_LOG_ENTER();

    if (g_sai_db_ptr->port_queue_defaults.is_valid && g_sai_db_ptr->port_pg0_defaults.is_valid) {
        return SAI_STATUS_SUCCESS;
    }

    sx_reserved_attr[0].type = SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E;
    sx_reserved_attr[0].attr.egress_port_tc_buff_attr.tc = 0;
    sx_shared_attr[0].type = SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E;
    sx_shared_attr[0].attr.egress_port_tc_shared_buff_attr.tc = 0;

    sx_reserved_attr[1].type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
    sx_reserved_attr[1].attr.ingress_port_pg_buff_attr.pg = 0;
    sx_shared_attr[1].type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
    sx_shared_attr[1].attr.ingress_port_pg_shared_buff_attr.pg = 0;

    /* get default queue config from first valid port*/
    mlnx_port_foreach(port, ii) {
        sx_status = sx_api_cos_port_buff_type_get(gh_sdk, port->logical, sx_reserved_attr, &buffer_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get queue default reserved configuration for port index %d queue index 0,"
                       " sx status - %s\n", ii, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_cos_port_shared_buff_type_get(gh_sdk, port->logical, sx_shared_attr, &buffer_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get queue default shared configuration for port index %d queue index 0,"
                       " sx status - %s\n", ii, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        memcpy(&g_sai_db_ptr->port_queue_defaults.sx_reserved_attr, &sx_reserved_attr[0], sizeof(sx_reserved_attr[0]));
        memcpy(&g_sai_db_ptr->port_pg0_defaults.sx_reserved_attr, &sx_reserved_attr[1], sizeof(sx_reserved_attr[1]));

        memcpy(&g_sai_db_ptr->port_queue_defaults.sx_shared_attr, &sx_shared_attr[0], sizeof(sx_shared_attr[0]));
        memcpy(&g_sai_db_ptr->port_pg0_defaults.sx_shared_attr, &sx_shared_attr[1], sizeof(sx_shared_attr[1]));

        g_sai_db_ptr->port_queue_defaults.is_valid = true;
        g_sai_db_ptr->port_pg0_defaults.is_valid = true;

        break;
    }

    if ((!g_sai_db_ptr->port_queue_defaults.is_valid) || (!g_sai_db_ptr->port_pg0_defaults.is_valid)) {
        SX_LOG_ERR("No valid ports\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/* requires sai_db read lock */
static sai_status_t mlnx_restore_default_pg_and_queue_buffer_configuration()
{
    sai_status_t                      status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t               *port;
    uint32_t                          buffer_count, ii;
    sx_cos_port_buffer_attr_t        *sx_reserved_attr_arr;
    sx_cos_port_shared_buffer_attr_t *sx_shared_attr_arr;

    if (!g_sai_db_ptr->port_queue_defaults.is_valid) {
        SX_LOG_ERR("No default buffers configuration for queue provided\n");
        return SAI_STATUS_FAILURE;
    }

    if (!g_sai_db_ptr->port_pg0_defaults.is_valid) {
        SX_LOG_ERR("No default buffers configuration for pg0 provided\n");
        return SAI_STATUS_FAILURE;
    }

    buffer_count = mlnx_sai_get_buffer_resource_limits()->num_port_queue_buff + 1; /* 1 for port PG0 */
    sx_reserved_attr_arr = calloc(buffer_count, sizeof(*sx_reserved_attr_arr));
    sx_shared_attr_arr = calloc(buffer_count, sizeof(*sx_shared_attr_arr));

    if ((!sx_reserved_attr_arr) || (!sx_shared_attr_arr)) {
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (ii = 0; ii < mlnx_sai_get_buffer_resource_limits()->num_port_queue_buff; ii++) {
        memcpy(&sx_reserved_attr_arr[ii], &g_sai_db_ptr->port_queue_defaults.sx_reserved_attr,
               sizeof(g_sai_db_ptr->port_queue_defaults.sx_reserved_attr));
        sx_reserved_attr_arr[ii].attr.egress_port_tc_buff_attr.tc = ii;

        memcpy(&sx_shared_attr_arr[ii], &g_sai_db_ptr->port_queue_defaults.sx_shared_attr,
               sizeof(g_sai_db_ptr->port_queue_defaults.sx_shared_attr));
        sx_shared_attr_arr[ii].attr.egress_port_tc_shared_buff_attr.tc = ii;
    }


    memcpy(&sx_reserved_attr_arr[buffer_count - 1], &g_sai_db_ptr->port_pg0_defaults.sx_reserved_attr,
           sizeof(g_sai_db_ptr->port_pg0_defaults.sx_reserved_attr));
    memcpy(&sx_shared_attr_arr[buffer_count - 1], &g_sai_db_ptr->port_pg0_defaults.sx_shared_attr,
           sizeof(g_sai_db_ptr->port_pg0_defaults.sx_shared_attr));


    mlnx_port_phy_foreach(port, ii) {
        status = mlnx_sai_buffer_configure_buffers(port, sx_reserved_attr_arr, buffer_count, sx_shared_attr_arr,
                                                   buffer_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply default pg and queue configuration for port 0x%" PRIx64 "\n", port->logical);
            goto out;
        }
    }

out:
    safe_free(sx_reserved_attr_arr);
    safe_free(sx_shared_attr_arr);

    return status;
}

/*
 *  Creates buffer pool by requesting new pool from SDK.
 *  Also creates shared headroom pool if required
 */
static sai_status_t mlnx_sai_create_buffer_pool(_Out_ sai_object_id_t     * pool_id,
                                                _In_ sai_object_id_t        switch_id,
                                                _In_ uint32_t               attr_count,
                                                _In_ const sai_attribute_t *attr_list)
{
    sx_cos_pool_id_t                 sx_pool_id = 0;
    sx_cos_pool_attr_t               sx_pool_attr = {0};
    bool                             pool_creation_triggered = false;
    sai_status_t                     sai_status = SAI_STATUS_SUCCESS;
    const sai_attribute_value_t    * attr = NULL;
    uint32_t                         attr_ind = 0;
    char                             list_str[MAX_LIST_VALUE_STR_LEN] = { 0 };
    sai_buffer_pool_type_t           pool_type = SAI_BUFFER_POOL_TYPE_INGRESS;
    sai_buffer_pool_threshold_mode_t pool_mode = SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC;
    sai_object_id_t                  sai_pool = 0;
    uint32_t                         pool_size = 0;
    sai_object_id_t                  shp_pool = 0;
    bool                             is_create_shp = false;
    bool                             is_db_locked = false;
    uint64_t                         sai_shp_pool_size = 0;
    bool                             is_warmboot_init_stage = false;
    mlnx_port_config_t              *port;
    uint32_t                         ii = 0;

    SX_LOG_ENTER();

    if (NULL == pool_id) {
        SX_LOG_ERR("NULL pool passed in\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }
    memset(&sx_pool_attr, 0, sizeof(sx_cos_pool_attr_t));
    if (SAI_STATUS_SUCCESS != (sai_status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_BUFFER_POOL,
                                                                   pool_vendor_attribs, SAI_COMMON_API_CREATE))) {
        goto bail;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_BUFFER_POOL, MAX_LIST_VALUE_STR_LEN,
                                           list_str))) {
        goto bail;
    }
    SX_LOG_NTC("Create buffer pool, %s\n", list_str);
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_POOL_ATTR_TYPE, &attr, &attr_ind);
    assert(SAI_STATUS_SUCCESS == sai_status);
    pool_type = attr->s32;
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_POOL_ATTR_SIZE, &attr, &attr_ind);
    assert(SAI_STATUS_SUCCESS == sai_status);
    pool_size = (uint32_t)attr->u64;
    if (SAI_STATUS_SUCCESS ==
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, &attr, &attr_ind))) {
        pool_mode = attr->s32;
    } else {
        pool_mode = SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC; /* default */
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = convert_sai_pool_mode_to_sx_pool_mode(pool_mode, &sx_pool_attr.mode))) {
        goto bail;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = convert_sai_pool_type_to_sx_pool_direction(pool_type, &sx_pool_attr.pool_dir))) {
        goto bail;
    }
    sx_pool_attr.pool_size = bytes_to_mlnx_cells(pool_size);
    SX_LOG_DBG("Input bytes:%d, cells:%d\n", pool_size, sx_pool_attr.pool_size);

    if ((SAI_STATUS_SUCCESS ==
         (sai_status =
              find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_POOL_ATTR_XOFF_SIZE, &attr, &attr_ind))) &&
        attr->u64) {
        if (SAI_BUFFER_POOL_TYPE_INGRESS != pool_type) {
            SX_LOG_ERR("Shared headroom pool can be created only with ingress pool");
            sai_status = SAI_STATUS_ATTR_NOT_SUPPORTED_0 + attr_ind;
            goto bail;
        }

        sai_shp_pool_size = attr->u64;

        is_create_shp = true;
    }

    sai_db_write_lock();
    is_db_locked = true;

    is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                             (!g_sai_db_ptr->issu_end_called);

    if (is_create_shp && g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created) {
        SX_LOG_ERR("No unallocated shared headroom pools left in the system");
        sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto bail;
    }

    pool_creation_triggered = mlnx_sai_buffer_get_pool_create_triggered_flag();
    if (!pool_creation_triggered) {
        SX_LOG_NTC(
            "First call to create pool. Will delete all existing pools and buffers before creating new pool now\n");

        sai_status = mlnx_sai_cleanup_buffer_config();
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to cleanup buffer config\n");
            goto bail;
        }

        sai_status = mlnx_sai_buffer_set_pool_create_triggered_flag(true);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to set pool creation flag\n");
            goto bail;
        }
    }

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_buffer_create_pool_hw(&sx_pool_attr, &sx_pool_id, &sai_pool))) {
        goto bail;
    }

    if (is_create_shp && (SAI_STATUS_SUCCESS !=
                          (sai_status =
                               mlnx_sai_buffer_enable_shared_headroom_internal(sai_pool, &shp_pool, sai_shp_pool_size,
                                                                               false)))) {
        goto bail;
    }

    if (!pool_creation_triggered && !is_warmboot_init_stage) {
        sai_status = mlnx_save_port_default_buffers_config();
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to save default port buffer attrs\n");
            goto bail;
        }

        mlnx_port_phy_foreach(port, ii) {
            sai_status = mlnx_sai_buffer_update_pg0_buffer_sdk_if_required(port);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Failed to update lossy PG pipeline latency size on user pool creation.\n");
                goto bail;
            }
        }
    }

    if (SAI_BUFFER_POOL_TYPE_INGRESS == pool_type) {
        /* Keep track if a pool is allocated (to avoid sdk get calls on it that will log error).
         *  First element is boolean if pools were ever allocated. Then 8 user ingress pools starting at base ingress pool id.
         *  Then 8 egress user pools starting at base egress pool id. */
        g_sai_buffer_db_ptr->pool_allocation[1 + sx_pool_id -
                                             g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id] = true;
    } else {
        g_sai_buffer_db_ptr->pool_allocation[1 + mlnx_sai_get_buffer_resource_limits()->num_ingress_pools +
                                             sx_pool_id -
                                             g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id] = true;
    }
    *pool_id = sai_pool;

    if (is_create_shp) {
        mlnx_sai_buffer_update_sai_db_shp_ipool_map(true, sai_pool, shp_pool);
    }

    sai_db_sync();

bail:
    if (is_db_locked) {
        sai_db_unlock();
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_remove_buffer_pool(_In_ sai_object_id_t pool_id)
{
    sx_cos_pool_attr_t          sx_pool_attr = {0};
    sai_status_t                sai_status = SAI_STATUS_SUCCESS;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr = {0};
    bool                        is_shp_related = false;
    bool                        is_any_pool_created = false;
    uint32_t                    ii;
    const uint32_t              num_ingress_pools = mlnx_sai_get_buffer_resource_limits()->num_ingress_pools;
    const uint32_t              num_egress_pools = mlnx_sai_get_buffer_resource_limits()->num_egress_pools;

    SX_LOG_ENTER();

    /* dummy sx struct to destroy pool in SDK */
    memset(&sx_pool_attr, 0, sizeof(sx_cos_pool_attr_t));

    sai_db_write_lock();

    sai_status = mlnx_get_sai_pool_data(pool_id, &sai_pool_attr);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get sai pool data with pool id 0x%" PRIx64 "\n", pool_id);
        goto bail;
    }

    if ((SAI_BUFFER_POOL_TYPE_INGRESS == sai_pool_attr.pool_type) &&
        (g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created) &&
        (pool_id == g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id)) {
        sai_status = mlnx_sai_buffer_disable_shared_headroom_internal(g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id,
                                                                      g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id,
                                                                      false);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to disable shared headroom\n");
            goto bail;
        }
        is_shp_related = true;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_remove_pool_hw(&sx_pool_attr, &sai_pool_attr.sx_pool_id))) {
        goto bail;
    }

    if (SAI_BUFFER_POOL_TYPE_INGRESS == sai_pool_attr.pool_type) {
        g_sai_buffer_db_ptr->pool_allocation[1 + sai_pool_attr.sx_pool_id -
                                             g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id] =
            false;
    } else {
        g_sai_buffer_db_ptr->pool_allocation[1 + num_ingress_pools +
                                             sai_pool_attr.sx_pool_id -
                                             g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id] = false;
    }

    for (ii = 1; ii < num_ingress_pools + num_egress_pools + 1; ii++) {
        if (g_sai_buffer_db_ptr->pool_allocation[ii]) {
            is_any_pool_created = true;
            break;
        }
    }

    if (is_shp_related) {
        mlnx_sai_buffer_update_sai_db_shp_ipool_map(false, 0, 0);
    }

    if (!is_any_pool_created) {
        sai_status = mlnx_restore_default_pg_and_queue_buffer_configuration();
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to restore default pg0 and queues configuration\n");
            goto bail;
        }

        sai_status = mlnx_sai_buffer_set_pool_create_triggered_flag(false);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to set pool create triggered flag to false\n");
            goto bail;
        }
    }

    sai_db_sync();

bail:
    sai_db_unlock();
    SX_LOG_EXIT();

    return sai_status;
}

/* DB write lock is needed */
static void mlnx_sai_buffer_update_sai_db_shp_ipool_map(_In_ bool            is_shp_created,
                                                        _In_ sai_object_id_t sai_pool_id,
                                                        _In_ sai_object_id_t shp_pool_id)
{
    SX_LOG_ENTER();

    g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created = is_shp_created;
    g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id = sai_pool_id;
    g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id = shp_pool_id;

    SX_LOG_EXIT();
}

static sai_status_t mlnx_sai_buffer_update_pg_and_psb_buffers_hw(_In_ sai_object_id_t  sai_ipool_id,
                                                                 _In_ sx_cos_pool_id_t sx_shp_pool_id,
                                                                 _In_ bool             is_create)
{
    sx_cos_port_buffer_attr_t                *sx_port_reserved_buff_attr_arr = NULL;
    sai_status_t                              sai_status = SAI_STATUS_SUCCESS;
    uint32_t                                  db_port_index = 0;
    uint32_t                                  sai_pg_ind = 0;
    uint32_t                                  sai_buff_ind = 0;
    uint32_t                                  count_pg_buffers = 0;
    uint32_t                                  count_all_buffers = 0;
    uint32_t                                  max_pool_loan = 0;
    uint32_t                                  ii = 0;
    uint32_t                                 *sai_port_pg_profile_refs = NULL;       /* do not free */
    const mlnx_port_config_t                 *port = NULL;
    const mlnx_sai_db_buffer_profile_entry_t *mlnx_sai_buff_db_entry = NULL;
    mlnx_affect_port_buff_items_t             mlnx_sai_affected_items = {0};        /* need to free */
    mlnx_sai_buffer_pool_attr_t               sai_ipool_attr = {0};
    uint32_t                                  cells_coeff = 1;

    SX_LOG_ENTER();

    /* get parent pool info */
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(sai_ipool_id, &sai_ipool_attr))) {
        goto bail;
    }
    /* SAI DB was not updated yet. Need to set flag explicitly.
     * It is used to determine value of pg buffer use_shared_headroom flag */
    sai_ipool_attr.is_shp_mapped = is_create;

    /* Configure pg buffers and port shared buffers per port */
    if (!alloc_affected_items(&mlnx_sai_affected_items)) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto bail;
    }
    mlnx_port_phy_foreach(port, db_port_index) {
        sai_port_pg_profile_refs = NULL;
        max_pool_loan = 0;
        reset_affected_items(&mlnx_sai_affected_items);
        safe_free(sx_port_reserved_buff_attr_arr);

        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_sai_get_port_buffer_index_array(db_port_index, PORT_BUFF_TYPE_PG, &sai_port_pg_profile_refs))) {
            goto bail;
        }

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_buffer_port_psb_cells_coefficient_get(&port->logical, &cells_coeff))) {
            goto bail;
        }

        mlnx_sai_buffer_calculate_max_pool_loan_and_update_affected_items(sai_ipool_id,
                                                                          sai_port_pg_profile_refs,
                                                                          cells_coeff,
                                                                          &max_pool_loan,
                                                                          &mlnx_sai_affected_items);

        count_pg_buffers = mlnx_sai_affected_items.affected_count;
        /* Port does not have lossless pg buffers. No need to update SDK */
        if (!count_pg_buffers) {
            continue;
        }
        count_all_buffers = count_pg_buffers + 1;

        /* Allocate place only for affected buffers + port shared (headroom) buffer */
        sx_port_reserved_buff_attr_arr = calloc(count_all_buffers, sizeof(sx_cos_port_buffer_attr_t));
        if (!sx_port_reserved_buff_attr_arr) {
            sai_status = SAI_STATUS_NO_MEMORY;
            goto bail;
        }

        /* Add port shared (headroom) buffer to sx attribute array as last element */
        sx_port_reserved_buff_attr_arr[count_all_buffers - 1].type = SX_COS_PORT_SHARED_HEADROOM_E;
        /* Construct port shared (headroom) buffer sx struct only on creation
         * On removal need to provide dummy sx struct */
        if (is_create && (SAI_STATUS_SUCCESS !=
                          (sai_status = mlnx_sai_buffer_construct_psb_sx_attr_internal
                                            (&sx_port_reserved_buff_attr_arr[count_all_buffers -
                                                                             1].attr.port_shared_headroom_attr,
                                            sx_shp_pool_id,
                                            max_pool_loan,
                                            &(port->logical))))) {
            goto bail;
        }

        /* Create only those pg buffers which are affected */
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_sai_buffer_prepare_affected_buffers(&sai_ipool_attr,
                                                          &mlnx_sai_affected_items, NULL,
                                                          &sx_port_reserved_buff_attr_arr[0]))) {
            SX_LOG_ERR("Failed to prepare affected buffers, status:%d\n", sai_status);
            goto bail;
        }

        /* Construct sx attribute array for PG buffers */
        for (ii = 0; ii < count_pg_buffers; ++ii) {
            sai_pg_ind = sx_port_reserved_buff_attr_arr[ii].attr.ingress_port_pg_buff_attr.pg;

            sai_buff_ind = sai_port_pg_profile_refs[sai_pg_ind];

            mlnx_sai_buff_db_entry = &g_sai_buffer_db_ptr->buffer_profiles[sai_buff_ind];

            mlnx_sai_buffer_apply_profile_to_reserved_structs(&sx_port_reserved_buff_attr_arr[ii],
                                                              1,
                                                              mlnx_sai_buff_db_entry,
                                                              &sai_ipool_attr,
                                                              &mlnx_sai_affected_items);
        }

        /* Update port PG buffers and port shared (headroom) buffer configuration in SDK*/
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_buffer_configure_reserved_buffers
                              (port->logical, sx_port_reserved_buff_attr_arr, count_all_buffers))) {
            log_sx_port_buffers(db_port_index, count_all_buffers, sx_port_reserved_buff_attr_arr);
            goto bail;
        }
    }

bail:
    free_affected_items(&mlnx_sai_affected_items);
    safe_free(sx_port_reserved_buff_attr_arr);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_create_pool_hw(_In_ sx_cos_pool_attr_t *sx_pool_attr,
                                                   _Out_ sx_cos_pool_id_t  *sx_shp_pool_id,
                                                   _Out_ sai_object_id_t   *sai_pool_id)
{
    sx_status_t  sx_status = SX_STATUS_SUCCESS;
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    char         key_str[MAX_KEY_STR_LEN] = "";

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_cos_shared_buff_pool_set(gh_sdk, SX_ACCESS_CMD_CREATE,
                                                     sx_pool_attr, sx_shp_pool_id))) {
        SX_LOG_ERR("Pool creation failed. sx_status:%d, message %s.\n", sx_status, SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto bail;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_create_sai_pool_id(*sx_shp_pool_id, sai_pool_id))) {
        goto bail;
    }
    pool_key_to_str(*sai_pool_id, key_str);
    SX_LOG_NTC("Pool is created %s\n", key_str);
    log_sai_pool_data(*sai_pool_id);

bail:
    SX_LOG_EXIT();
    return sai_status;
}

/* DB write lock is needed */
static sai_status_t mlnx_sai_buffer_enable_shared_headroom_internal(_In_ sai_object_id_t   sai_ipool_id,
                                                                    _Out_ sai_object_id_t *sai_shp_pool_id,
                                                                    _In_ uint64_t          shp_pool_size,
                                                                    _In_ bool              is_update_pg_psb)
{
    sai_status_t       sai_status = SAI_STATUS_SUCCESS;
    sx_cos_pool_attr_t sx_shp_pool_attr = {0};
    sx_cos_pool_id_t   sx_shp_pool_id = 0;

    SX_LOG_ENTER();

    /* populate SDK shared headroom pool structure */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_construct_shp_sx_attr_internal(&sx_shp_pool_attr, shp_pool_size))) {
        goto bail;
    }

    /* Create shared headroom pool in SDK */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_create_pool_hw(&sx_shp_pool_attr, &sx_shp_pool_id, sai_shp_pool_id))) {
        SX_LOG_ERR("Shared headroom pool creation failed\n");
        goto bail;
    }

    /* Create port shared (headroom) buffers and reconfigure relevant pg buffers per port in SDK */
    if (is_update_pg_psb &&
        (SAI_STATUS_SUCCESS !=
         (sai_status = mlnx_sai_buffer_update_pg_and_psb_buffers_hw(sai_ipool_id, sx_shp_pool_id, true)))) {
        SX_LOG_ERR("PG buffers and PSB buffers creation failed\n");
        goto bail;
    }

bail:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_remove_pool_hw(_In_ sx_cos_pool_attr_t *sx_pool_attr,
                                                   _In_ uint32_t           *sx_pool_id)
{
    sx_status_t  sx_status = SX_STATUS_SUCCESS;
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_cos_shared_buff_pool_set(gh_sdk, SX_ACCESS_CMD_DESTROY, sx_pool_attr,
                                                     sx_pool_id))) {
        SX_LOG_ERR("Failed to destroy sx pool, sx_status:%d, message %s.\n", sx_status, SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto bail;
    }

bail:
    SX_LOG_EXIT();
    return sai_status;
}

/* DB write lock is needed */
static sai_status_t mlnx_sai_buffer_disable_shared_headroom_internal(_In_ sai_object_id_t sai_parent_pool_id,
                                                                     _In_ sai_object_id_t sai_shp_pool_id,
                                                                     _In_ bool            is_update_pg_psb)
{
    sai_status_t                sai_status = SAI_STATUS_SUCCESS;
    mlnx_sai_buffer_pool_attr_t sai_shp_pool_attr = {0};
    sx_cos_pool_attr_t          sx_pool_attr = {0};

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(sai_shp_pool_id, &sai_shp_pool_attr))) {
        goto bail;
    }
    /* Reconfigure relevant pg buffers and remove port shared (headroom) buffers and per port in SDK */
    if (is_update_pg_psb &&
        (SAI_STATUS_SUCCESS !=
         (sai_status = mlnx_sai_buffer_update_pg_and_psb_buffers_hw(sai_parent_pool_id,
                                                                    sai_shp_pool_attr.sx_pool_id,
                                                                    false)))) {
        SX_LOG_ERR("PG buffers and PSB buffers creation failed\n");
        goto bail;
    }

    /* Destroy shared headroom pool in SDK */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_remove_pool_hw(&sx_pool_attr, &sai_shp_pool_attr.sx_pool_id))) {
        goto bail;
    }

bail:
    SX_LOG_EXIT();
    return sai_status;
}

/** buffer pool size in bytes [sai_uint32_t] */
sai_status_t mlnx_sai_set_pool_size_attr(_In_ const sai_object_key_t      * key,
                                         _In_ const sai_attribute_value_t * value,
                                         void                             * arg)
{
    sx_status_t                 sx_status = SX_STATUS_SUCCESS;
    uint32_t                    sx_pool_id = 0;
    sx_cos_pool_attr_t          sx_pool_attr = {0};
    sai_status_t                sai_status = SAI_STATUS_SUCCESS;
    sai_object_id_t             sai_pool_object_id = 0;
    sai_object_id_t             sai_shp_pool_id = 0;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr = {0};
    bool                        is_sai_db_locked = false;
    const char                * err_msg = NULL;


    SX_LOG_ENTER();

    assert((SAI_BUFFER_POOL_ATTR_SIZE == (long)arg) ||
           (SAI_BUFFER_POOL_ATTR_XOFF_SIZE == (long)arg));

    /* parent pool id */
    sai_pool_object_id = key->key.object_id;

    if (SAI_BUFFER_POOL_ATTR_XOFF_SIZE == (long)arg) {
        sai_db_write_lock();
        is_sai_db_locked = true;

        /* get parent pool info */
        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(sai_pool_object_id, &sai_pool_attr))) {
            goto bail;
        }

        if (g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created) {
            if (sai_pool_object_id == g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id) {
                if (0 == value->u64) {
                    /*
                     * reconfigure relevant PG buffers
                     * destroy per port shared buffers
                     * destroy shared headroom pool
                     * update SAI DB
                     */
                    if (SAI_STATUS_SUCCESS !=
                        (sai_status = mlnx_sai_buffer_disable_shared_headroom_internal(
                             g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id,
                             g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id,
                             true))) {
                        err_msg = "Failed to disable shared headroom\n";
                    }

                    /* Update SAI DB */
                    mlnx_sai_buffer_update_sai_db_shp_ipool_map(false, 0, 0);
                    sai_db_sync();
                    goto bail;
                }
                /* else update shared headroom pool size instead of regular pool */
                /* shared headroom pool id */
                sai_pool_object_id = g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id;
                sai_db_unlock();
                is_sai_db_locked = false;
                /* pool id does not match pool associated with shared headroom pool*/
            } else {
                sai_status = SAI_STATUS_INVALID_PARAMETER;
                SX_LOG_ERR("No shared headroom pool is associated with provided pool id. sai_status:%d, .\n",
                           sai_status);
                goto bail;
            }
            /* shared headroom is disabled */
        } else {
            if (SAI_BUFFER_POOL_TYPE_INGRESS != sai_pool_attr.pool_type) {
                sai_status = SAI_STATUS_INVALID_PARAMETER;
                err_msg = "Shared headroom pool can be created only with ingress pool\n";
                /* value->u64 > 0 */
            } else if (value->u64) {
                err_msg = NULL;
                /*
                 * create shared headroom pool
                 * create per port shared buffers if needed
                 * reconfigure relevant PG buffers
                 * update SAI DB
                 */
                /* create shared headroom pool and update sai db */
                if (SAI_STATUS_SUCCESS !=
                    (sai_status = mlnx_sai_buffer_enable_shared_headroom_internal(sai_pool_object_id,
                                                                                  &sai_shp_pool_id,
                                                                                  value->u64,
                                                                                  true))) {
                    err_msg = "Failed to enable shared headroom\n";
                }
                /* Update SAI DB */
                mlnx_sai_buffer_update_sai_db_shp_ipool_map(true, sai_pool_object_id, sai_shp_pool_id);
                sai_db_sync();
            }
            goto bail;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_pool_object_id, SAI_OBJECT_TYPE_BUFFER_POOL, &sx_pool_id, NULL))) {
        goto bail;
    }
    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_cos_shared_buff_pool_get(gh_sdk, sx_pool_id,  &sx_pool_attr))) {
        SX_LOG_ERR("Failed to get sx pool settings, sx_status:%d, message %s.\n", sx_status, SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto bail;
    }

    sx_pool_attr.pool_size = bytes_to_mlnx_cells((uint32_t)value->u64);
    SX_LOG_DBG("Input bytes:%lu Size to set:%d\n", value->u64, sx_pool_attr.pool_size);
    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_cos_shared_buff_pool_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sx_pool_attr, &sx_pool_id))) {
        SX_LOG_ERR("Failed to change sx pool size, sx_status:%d, message %s.\n", sx_status, SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto bail;
    }

bail:
    if (is_sai_db_locked) {
        sai_db_unlock();
    }

    if (err_msg) {
        SX_LOG_ERR("%s", err_msg);
    }

    SX_LOG_EXIT();
    return sai_status;
}

/** buffer pool size in bytes [sai_uint32_t] */
static sai_status_t mlnx_sai_get_pool_size_attr(_In_ const sai_object_key_t   * key,
                                                _Inout_ sai_attribute_value_t * value,
                                                _In_ uint32_t                   attr_index,
                                                _Inout_ vendor_cache_t        * cache,
                                                void                          * arg)
{
    sai_status_t                sai_status = SAI_STATUS_SUCCESS;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr = {0};
    sai_object_id_t             pool_object_id = 0;
    bool                        is_db_locked = false;

    SX_LOG_ENTER();

    assert(NULL != key);
    assert(NULL != value);
    assert((SAI_BUFFER_POOL_ATTR_SIZE == (long)arg) ||
           (SAI_BUFFER_POOL_ATTR_XOFF_SIZE == (long)arg));

    pool_object_id = key->key.object_id;

    sai_db_read_lock();
    is_db_locked = true;
    if (SAI_BUFFER_POOL_ATTR_XOFF_SIZE == (long)arg) {
        /* currently only a single instance of shared headroom pool is available */
        if ((g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created) &&
            (g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id == pool_object_id)) {
            pool_object_id = g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id;
        } else {
            value->u64 = 0;
            goto bail;
        }
    }

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(pool_object_id, &sai_pool_attr))) {
        goto bail;
    }
    sai_db_unlock();
    is_db_locked = false;

    value->u64 = sai_pool_attr.pool_size;

bail:
    if (is_db_locked) {
        sai_db_unlock();
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_set_buffer_pool_attr(_In_ sai_object_id_t pool_id, _In_ const sai_attribute_t * attr)
{
    const sai_object_key_t key = { .key.object_id = pool_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();

    pool_key_to_str(pool_id, key_str);
    sai_status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_BUFFER_POOL, pool_vendor_attribs, attr);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_compute_shared_size(_In_ sai_object_id_t            sai_pool,
                                                        _In_ sx_cos_port_buffer_attr_t* sx_port_reserved_buff_attr_arr,
                                                        _In_ uint32_t                   arr_length,
                                                        _Out_ uint64_t                * total_shared_bytes)
{
    sai_status_t                sai_status = SAI_STATUS_SUCCESS;
    uint32_t                    port_ind = 0;
    uint32_t                    buff_ind = 0;
    sx_status_t                 sx_status = SX_STATUS_SUCCESS;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr = {0};
    sx_port_log_id_t            mc_port_logical = SX_MC_PORT_LOG_ID;
    uint32_t                    total_reserved_size = 0;
    uint32_t                    get_count = 0;
    mlnx_port_config_t         *port = NULL;

    SX_LOG_ENTER();
    if (NULL == sx_port_reserved_buff_attr_arr) {
        SX_LOG_ERR("NULL sx_port_reserved_buff_attr_arr\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (0 == arr_length) {
        SX_LOG_ERR("0 count\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (NULL == total_shared_bytes) {
        SX_LOG_ERR("NULL total_shared_bytes\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(sai_pool, &sai_pool_attr))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    mlnx_port_phy_foreach(port, port_ind) {
        memset(sx_port_reserved_buff_attr_arr, 0, arr_length * sizeof(sx_port_reserved_buff_attr_arr[0]));
        get_count = arr_length;
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_cos_port_buff_type_get(gh_sdk, port->logical, sx_port_reserved_buff_attr_arr,
                                                       &get_count))) {
            SX_LOG_ERR(
                "Failed to get bindings for reserved buffers. port[%d].logical:%x, number of items:%d sx_status:%d, message %s\n",
                port_ind,
                port->logical,
                get_count,
                sx_status,
                SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }
        assert(get_count <= arr_length);
        for (buff_ind = 0; buff_ind < get_count; buff_ind++) {
            switch (sx_port_reserved_buff_attr_arr[buff_ind].type) {
            case SX_COS_INGRESS_PORT_ATTR_E:
                if (sx_port_reserved_buff_attr_arr[buff_ind].attr.ingress_port_buff_attr.pool_id ==
                    sai_pool_attr.sx_pool_id) {
                    total_reserved_size += sx_port_reserved_buff_attr_arr[buff_ind].attr.ingress_port_buff_attr.size;
                    SX_LOG_DBG("port[%d].logical:%x, ingress port_buff[%d].size:%d\n",
                               port_ind, port->logical, buff_ind,
                               sx_port_reserved_buff_attr_arr[buff_ind].attr.ingress_port_buff_attr.size);
                }
                break;

            case SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E:
                if (sx_port_reserved_buff_attr_arr[buff_ind].attr.ingress_port_pg_buff_attr.pool_id ==
                    sai_pool_attr.sx_pool_id) {
                    total_reserved_size +=
                        sx_port_reserved_buff_attr_arr[buff_ind].attr.ingress_port_pg_buff_attr.size;
                    SX_LOG_DBG("port[%d].logical:%x, pg:%d port_buff[%d].size:%d\n",
                               port_ind,
                               port->logical,
                               sx_port_reserved_buff_attr_arr[buff_ind].attr.ingress_port_pg_buff_attr.pg,
                               buff_ind,
                               sx_port_reserved_buff_attr_arr[buff_ind].attr.ingress_port_pg_buff_attr.size);
                }
                break;

            case SX_COS_EGRESS_PORT_ATTR_E:
                if (sx_port_reserved_buff_attr_arr[buff_ind].attr.egress_port_buff_attr.pool_id ==
                    sai_pool_attr.sx_pool_id) {
                    total_reserved_size += sx_port_reserved_buff_attr_arr[buff_ind].attr.egress_port_buff_attr.size;
                    SX_LOG_DBG("port[%d].logical:%x, egress port_buff[%d].size:%d\n",
                               port_ind, port->logical, buff_ind,
                               sx_port_reserved_buff_attr_arr[buff_ind].attr.egress_port_buff_attr.size);
                }
                break;

            case SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E:
                if (sx_port_reserved_buff_attr_arr[buff_ind].attr.egress_port_tc_buff_attr.pool_id ==
                    sai_pool_attr.sx_pool_id) {
                    total_reserved_size += sx_port_reserved_buff_attr_arr[buff_ind].attr.egress_port_tc_buff_attr.size;
                    SX_LOG_DBG("port[%d].logical:%x, tc:%d port_buff[%d].size:%d\n",
                               port_ind,
                               port->logical,
                               sx_port_reserved_buff_attr_arr[buff_ind].attr.egress_port_tc_buff_attr.tc,
                               buff_ind,
                               sx_port_reserved_buff_attr_arr[buff_ind].attr.egress_port_tc_buff_attr.size);
                }
                break;

            case SX_COS_PORT_SHARED_HEADROOM_E:
                if (sai_pool_attr.is_shp_mapped) {
                    total_reserved_size +=
                        sx_port_reserved_buff_attr_arr[buff_ind].attr.port_shared_headroom_attr.size;
                    SX_LOG_DBG("port[%d].logical:%x, shared headroom port_buff[%d].size:%d\n",
                               port_ind,
                               port->logical,
                               buff_ind,
                               sx_port_reserved_buff_attr_arr[buff_ind].attr.port_shared_headroom_attr.size);
                }
                break;

            default:
                break;
            }
        }
    }

    memset(sx_port_reserved_buff_attr_arr, 0, arr_length * sizeof(sx_port_reserved_buff_attr_arr[0]));
    get_count = arr_length;
    if (SX_STATUS_SUCCESS != (sx_status = sx_api_cos_port_buff_type_get(gh_sdk, mc_port_logical,
                                                                        sx_port_reserved_buff_attr_arr, &get_count))) {
        SX_LOG_ERR(
            "Failed to get bindings for MC reserved buffers. MC logical:%x, number of items:%d sx_status:%d, message %s\n",
            mc_port_logical,
            get_count,
            sx_status,
            SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }
    assert(get_count <= arr_length);
    for (buff_ind = 0; buff_ind < get_count; buff_ind++) {
        if (sx_port_reserved_buff_attr_arr[buff_ind].attr.multicast_buff_attr.pool_id == sai_pool_attr.sx_pool_id) {
            total_reserved_size += sx_port_reserved_buff_attr_arr[buff_ind].attr.multicast_buff_attr.size;
        }
    }
    if (sai_pool_attr.pool_size < mlnx_cells_to_bytes(total_reserved_size)) {
        SX_LOG_ERR("Pool size:%d is less than total reserved sizes:%d\n",
                   sai_pool_attr.pool_size, total_reserved_size);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_DBG("pool_id:%d, pool size:%d, total reserved used from the pool:%d, total shared size:%d\n",
               sai_pool_attr.sx_pool_id,
               sai_pool_attr.pool_size,
               total_reserved_size,
               sai_pool_attr.pool_size - total_reserved_size);

    *total_shared_bytes = sai_pool_attr.pool_size - mlnx_cells_to_bytes(total_reserved_size);

    SX_LOG_EXIT();
    return sai_status;
}

/** pool shared size in bytes [sai_uint32_t].
 * This is derived from subtracting all reserved buffers of queue/pg/psb per port
 * from the total pool size. */
static sai_status_t mlnx_sai_get_pool_shared_size_attr(_In_ const sai_object_key_t   * key,
                                                       _Inout_ sai_attribute_value_t * value,
                                                       _In_ uint32_t                   attr_index,
                                                       _Inout_ vendor_cache_t        * cache,
                                                       void                          * arg)
{
    sx_cos_port_buffer_attr_t *sx_port_reserved_buff_attr_arr = NULL;
    uint32_t                   count = 0;
    sai_status_t               sai_status = SAI_STATUS_SUCCESS;
    bool                       is_db_locked = false;

    count = buffer_limits.max_buffers_per_port + buffer_limits.num_port_shared_headroom_buff;

    sx_port_reserved_buff_attr_arr = calloc(count, sizeof(sx_cos_port_buffer_attr_t));
    if (!sx_port_reserved_buff_attr_arr) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto bail;
    }

    sai_db_read_lock();
    is_db_locked = true;

    if (SAI_STATUS_SUCCESS != (sai_status =
                                   mlnx_sai_buffer_compute_shared_size(key->key.object_id,
                                                                       sx_port_reserved_buff_attr_arr, count,
                                                                       &(value->u64)))) {
        goto bail;
    }

bail:
    if (is_db_locked) {
        sai_db_unlock();
    }
    safe_free(sx_port_reserved_buff_attr_arr);
    SX_LOG_EXIT();
    return sai_status;
}

/** buffer pool type [sai_buffer_pool_type_t] */
static sai_status_t mlnx_sai_get_pool_type_attr(_In_ const sai_object_key_t   * key,
                                                _Inout_ sai_attribute_value_t * value,
                                                _In_ uint32_t                   attr_index,
                                                _Inout_ vendor_cache_t        * cache,
                                                void                          * arg)
{
    sai_status_t                sai_status;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr;

    SX_LOG_ENTER();
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(key->key.object_id, &sai_pool_attr))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->s32 = sai_pool_attr.pool_type;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** shared threshold mode for the buffer pool [sai_buffer_pool_threshold_mode_t]
 * (default to SAI_BUFFER_POOL_DYNAMIC_TH) */
static sai_status_t mlnx_sai_get_pool_th_mode_attr(_In_ const sai_object_key_t   * key,
                                                   _Inout_ sai_attribute_value_t * value,
                                                   _In_ uint32_t                   attr_index,
                                                   _Inout_ vendor_cache_t        * cache,
                                                   void                          * arg)
{
    sai_status_t                sai_status;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr;

    SX_LOG_ENTER();
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(key->key.object_id, &sai_pool_attr))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->s32 = sai_pool_attr.pool_mode;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_get_buffer_pool_attr(_In_ sai_object_id_t      pool_id,
                                                  _In_ uint32_t             attr_count,
                                                  _Inout_ sai_attribute_t * attr_list)
{
    const sai_object_key_t key = { .key.object_id = pool_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();
    pool_key_to_str(pool_id, key_str);

    sai_status = sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_BUFFER_POOL,
                                    pool_vendor_attribs, attr_count, attr_list);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t db_buffer_profile_reserve_entry(_Out_ uint32_t* buff_profile_db_ind_out)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     buff_profile_db_ind = 0;
    uint32_t     buff_profile_db_cnt = mlnx_sai_get_buffer_profile_number();

    SX_LOG_ENTER();
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    for (buff_profile_db_ind = SENTINEL_BUFFER_DB_ENTRY_INDEX + 1;
         buff_profile_db_ind < buff_profile_db_cnt;
         buff_profile_db_ind++) {
        if (!g_sai_buffer_db_ptr->buffer_profiles[buff_profile_db_ind].is_valid) {
            break;
        }
    }
    if (buff_profile_db_ind == buff_profile_db_cnt) {
        SX_LOG_ERR("Buffer profile db full\n");
        cl_plock_release(&g_sai_db_ptr->p_lock);
        return SAI_STATUS_TABLE_FULL;
    }
    g_sai_buffer_db_ptr->buffer_profiles[buff_profile_db_ind].is_valid = true;
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);

    *buff_profile_db_ind_out = buff_profile_db_ind;
    SX_LOG_DBG("Reserved buffer profile db item_ind:0x%X\n", buff_profile_db_ind);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_create_buffer_profile(_Out_ sai_object_id_t     * buffer_profile_id,
                                                   _In_ sai_object_id_t        switch_id,
                                                   _In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list)
{
    uint32_t                           buff_profile_db_ind = 0;
    mlnx_sai_db_buffer_profile_entry_t new_buffer_profile;
    char                               list_str[MAX_LIST_VALUE_STR_LEN];
    char                               key_str[MAX_KEY_STR_LEN];
    sai_status_t                       sai_status;
    const sai_attribute_value_t      * attr;
    uint32_t                           attr_ind;
    mlnx_sai_buffer_pool_attr_t        sai_pool_attr;
    bool                               mode_set = false;

    SX_LOG_ENTER();
    memset(&new_buffer_profile, 0, sizeof(new_buffer_profile));
    if (NULL == buffer_profile_id) {
        SX_LOG_ERR("NULL key passed in\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_BUFFER_PROFILE,
                                             buffer_profile_vendor_attribs,
                                             SAI_COMMON_API_CREATE))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_BUFFER_PROFILE,
                                           MAX_LIST_VALUE_STR_LEN, list_str))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_NTC("Create buffer profile, %s\n", list_str);
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_PROFILE_ATTR_POOL_ID, &attr, &attr_ind);
    assert(SAI_STATUS_SUCCESS == sai_status);

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(attr->oid, &sai_pool_attr))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    cl_plock_release(&g_sai_db_ptr->p_lock);

    new_buffer_profile.sai_pool = attr->oid;
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_PROFILE_ATTR_BUFFER_SIZE,
                                     &attr, &attr_ind);
    assert(SAI_STATUS_SUCCESS == sai_status);
    new_buffer_profile.reserved_size = attr->u32;

    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, &attr,
                                          &attr_ind))) {
        if (SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC != sai_pool_attr.pool_mode) {
            SX_LOG_ERR("Dynamic threshold size cannot be passed to buffer profile when Input pool is not dynamic.\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_ind;
        }
        new_buffer_profile.shared_max.mode = SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC;
        new_buffer_profile.shared_max.max.alpha = attr->u8;
        mode_set = true;
    }
    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH, &attr,
                                          &attr_ind))) {
        if (mode_set) {
            SX_LOG_ERR("Both static and dynamic thresholds cannot be specified.\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_ind;
        }

        if (SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC != sai_pool_attr.pool_mode) {
            SX_LOG_ERR("Static threshold size cannot be passed to buffer profile when Input pool is not static.\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_ind;
        }
        new_buffer_profile.shared_max.mode = SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC;
        new_buffer_profile.shared_max.max.static_th = (uint32_t)attr->u64;
        mode_set = true;
    }
    if (!mode_set) {
        SX_LOG_ERR("One of threshold modes must be specified.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_ind;
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, &attr,
                                          &attr_ind))) {
        if (new_buffer_profile.shared_max.mode != (sai_buffer_profile_threshold_mode_t)attr->s32) {
            SX_LOG_ERR("Threshold mode %d mixed with threshold value %d.\n",
                       attr->s32,
                       new_buffer_profile.shared_max.mode);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_ind;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_PROFILE_ATTR_XOFF_TH, &attr, &attr_ind))) {
        new_buffer_profile.xoff = (uint32_t)attr->u64;
    } else {
        new_buffer_profile.xoff = 0; /*default*/
    }

    if (SAI_STATUS_SUCCESS ==
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_BUFFER_PROFILE_ATTR_XON_TH, &attr, &attr_ind))) {
        new_buffer_profile.xon = (uint32_t)attr->u64;
    } else {
        new_buffer_profile.xon = 0; /*default*/
    }

    if (SAI_STATUS_SUCCESS != (sai_status = db_buffer_profile_reserve_entry(&buff_profile_db_ind))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    new_buffer_profile.is_valid = true;
    g_sai_buffer_db_ptr->buffer_profiles[buff_profile_db_ind] = new_buffer_profile;
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_BUFFER_PROFILE, buff_profile_db_ind, NULL, buffer_profile_id))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    buffer_profile_key_to_str(*buffer_profile_id, key_str);
    SX_LOG_NTC("Created %s\n", key_str);
    log_sai_buffer_profile_db_entry(buff_profile_db_ind);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_remove_buffer_profile(_In_ sai_object_id_t buffer_profile_id)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    if (SAI_NULL_OBJECT_ID == buffer_profile_id) {
        SX_LOG_DBG("NULL Buffer profile\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_buffer_profile_data(buffer_profile_id, &db_buffer_profile_index, NULL))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_is_buffer_in_use(buffer_profile_id))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }

    memset(&g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index],
           0,
           sizeof(mlnx_sai_db_buffer_profile_entry_t));
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** pointer to buffer pool object id [sai_object_id_t] */
static sai_status_t mlnx_sai_get_buffer_profile_pool_id_attr(_In_ const sai_object_key_t   * key,
                                                             _Inout_ sai_attribute_value_t * value,
                                                             _In_ uint32_t                   attr_index,
                                                             _Inout_ vendor_cache_t        * cache,
                                                             void                          * arg)
{
    sai_status_t                sai_status;
    uint32_t                    db_buffer_profile_index;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr;

    SX_LOG_ENTER();
    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_get_sai_buffer_profile_data(key->key.object_id, &db_buffer_profile_index, &sai_pool_attr))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->oid = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].sai_pool;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** reserved buffer size in bytes [sai_uint32_t] */
static sai_status_t mlnx_sai_get_buffer_profile_size_attr(_In_ const sai_object_key_t   * key,
                                                          _Inout_ sai_attribute_value_t * value,
                                                          _In_ uint32_t                   attr_index,
                                                          _Inout_ vendor_cache_t        * cache,
                                                          void                          * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_ind;

    SX_LOG_ENTER();
    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_buffer_profile_data(key->key.object_id, &db_buffer_profile_ind, NULL))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->u64 = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_ind].reserved_size;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *  Description
 *   Applies settings of buffer profile entry to SDK buffers which are identified by affected_items structure.
 *
 *   affected_items contains bool flags for each pg/tc/i_port_buffer/e_port_buffer.
 *   If an entry is true, it means given item should be applied with new buffer profile settings.
 */
static void mlnx_sai_buffer_apply_profile_to_reserved_structs(
    _Inout_ sx_cos_port_buffer_attr_t            * sx_port_reserved_buff_attr_arr,
    _In_ uint32_t                                  count,
    _In_ const mlnx_sai_db_buffer_profile_entry_t *buff_db_entry,
    _In_ const mlnx_sai_buffer_pool_attr_t        *sai_pool_attr,
    _In_ mlnx_affect_port_buff_items_t const      *affected_items)
{
    uint32_t ind = 0;
    bool     is_buffer_lossy = false;
    bool     is_use_shared_headroom = false;

    SX_LOG_ENTER();
    SX_LOG_DBG("count:%d\n", count);
    for (ind = 0; ind < count; ind++) {
        switch (sai_pool_attr->pool_type) {
        case SAI_BUFFER_POOL_TYPE_INGRESS:
            switch (sx_port_reserved_buff_attr_arr[ind].type) {
            case SX_COS_INGRESS_PORT_ATTR_E:
                assert(sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_buff_attr.pool_id <
                       buffer_limits.num_ingress_pools +
                       g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id);
                if (true ==
                    affected_items->i_port_buffers[sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_buff_attr.
                                                   pool_id -
                                                   g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id])
                {
                    SX_LOG_DBG("(i)port_buffers[%d], pool_id:%d\n",
                               ind, sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_buff_attr.pool_id);
                    assert(SAI_BUFFER_POOL_TYPE_INGRESS == sai_pool_attr->pool_type);
                    sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_buff_attr.size = bytes_to_mlnx_cells(
                        buff_db_entry->reserved_size);
                    log_sx_port_buffers(0, 1, &sx_port_reserved_buff_attr_arr[ind]);
                }
                break;

            case SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E:
                if (sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.pg >=
                    mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff) {
                    /* control traffic is not supported */
                    continue;
                }
                if (true ==
                    affected_items->pgs[sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.pg]) {
                    SX_LOG_DBG("item:%d, pg:%d\n",
                               ind,
                               sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.pg);
                    assert(SAI_BUFFER_POOL_TYPE_INGRESS == sai_pool_attr->pool_type);
                    log_sai_buffer_profile_db_entry_fields(buff_db_entry);

                    is_buffer_lossy = ((0 == buff_db_entry->xoff) && (0 == buff_db_entry->xon));
                    is_use_shared_headroom = (sai_pool_attr->is_shp_mapped && !is_buffer_lossy);

                    sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.size = bytes_to_mlnx_cells(
                        buff_db_entry->reserved_size);
                    sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.is_lossy =
                        is_buffer_lossy;
                    sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.xon = bytes_to_mlnx_cells(
                        buff_db_entry->xon);
                    sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.xoff = is_use_shared_headroom ?
                                                                                              sx_port_reserved_buff_attr_arr
                                                                                              [ind].attr.
                                                                                              ingress_port_pg_buff_attr
                                                                                              .xon :
                                                                                              bytes_to_mlnx_cells(
                        buff_db_entry->reserved_size - buff_db_entry->xoff);
                    sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.pool_id =
                        sai_pool_attr->sx_pool_id;
                    sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.use_shared_headroom =
                        is_use_shared_headroom;
#ifdef ACS_OS
                    bool is_shared_zero;

                    if (buff_db_entry->shared_max.mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC) {
                        is_shared_zero = (buff_db_entry->shared_max.max.static_th == 0);
                    } else { /* SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC */
                        is_shared_zero = (buff_db_entry->shared_max.max.alpha == SAI_BUFFER_ALPHA_0);
                    }

                    if ((0 == buff_db_entry->reserved_size) && is_shared_zero) {
                        sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.pipeline_latency.
                        override_default = true;
                        sx_port_reserved_buff_attr_arr[ind].attr.ingress_port_pg_buff_attr.pipeline_latency.size
                            = 0;
                    }
#endif /* ACS_OS */
                    log_sx_port_buffers(0, 1, &sx_port_reserved_buff_attr_arr[ind]);
                }
                break;

            default:
                break;
            }
            break;

        case SAI_BUFFER_POOL_TYPE_EGRESS:
            switch (sx_port_reserved_buff_attr_arr[ind].type) {
            case SX_COS_EGRESS_PORT_ATTR_E:
                SX_LOG_DBG("pool_id:%d\n", sx_port_reserved_buff_attr_arr[ind].attr.egress_port_buff_attr.pool_id);
                assert((sx_port_reserved_buff_attr_arr[ind].attr.egress_port_buff_attr.pool_id -
                        g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id) <
                       mlnx_sai_get_buffer_resource_limits()->num_egress_pools);
                if (true ==
                    affected_items->e_port_buffers[sx_port_reserved_buff_attr_arr[ind].attr.egress_port_buff_attr.
                                                   pool_id -
                                                   g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id]) {
                    SX_LOG_DBG("(e)port_buffers[%d], pool_id:%d\n", ind,
                               sx_port_reserved_buff_attr_arr[ind].attr.egress_port_buff_attr.pool_id);
                    assert(SAI_BUFFER_POOL_TYPE_EGRESS == sai_pool_attr->pool_type);
                    sx_port_reserved_buff_attr_arr[ind].attr.egress_port_buff_attr.size = bytes_to_mlnx_cells(
                        buff_db_entry->reserved_size);
                    log_sx_port_buffers(0, 1, &sx_port_reserved_buff_attr_arr[ind]);
                }
                break;

            case SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E:
                if (sx_port_reserved_buff_attr_arr[ind].attr.egress_port_tc_buff_attr.tc >=
                    mlnx_sai_get_buffer_resource_limits()->num_port_queue_buff) {
                    /* control traffic is not supported */
                    continue;
                }
                if (true ==
                    affected_items->tcs[sx_port_reserved_buff_attr_arr[ind].attr.egress_port_tc_buff_attr.tc]) {
                    SX_LOG_DBG("item:%d, queue:%d\n", ind,
                               sx_port_reserved_buff_attr_arr[ind].attr.egress_port_tc_buff_attr.tc);
                    assert(SAI_BUFFER_POOL_TYPE_EGRESS == sai_pool_attr->pool_type);
                    sx_port_reserved_buff_attr_arr[ind].attr.egress_port_tc_buff_attr.size = bytes_to_mlnx_cells(
                        buff_db_entry->reserved_size);
                    sx_port_reserved_buff_attr_arr[ind].attr.egress_port_tc_buff_attr.pool_id =
                        sai_pool_attr->sx_pool_id;
                    log_sx_port_buffers(0, 1, &sx_port_reserved_buff_attr_arr[ind]);
                }
                break;

            default:
                break;
            }
            break;

        default:
            break;
        }
    }
    SX_LOG_EXIT();
}

static sai_status_t mlnx_sai_shared_max_to_sx(_Inout_ sx_cos_buffer_max_t   * sx_cos_buff_max,
                                              _In_ mlnx_sai_shared_max_size_t sai_shared_max)
{
    if (SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC == sai_shared_max.mode) {
        return mlnx_buffer_convert_alpha_sai_to_sx(sai_shared_max.max.alpha, &sx_cos_buff_max->max.alpha);
    } else {
        sx_cos_buff_max->max.size = bytes_to_mlnx_cells(sai_shared_max.max.static_th);
        return SAI_STATUS_SUCCESS;
    }
}

static sai_status_t mlnx_sai_buffer_apply_profile_to_shared_structs(
    _Inout_ sx_cos_port_shared_buffer_attr_t* sx_port_shared_buff_attr_arr,
    _In_ uint32_t                             count,
    _In_ mlnx_sai_db_buffer_profile_entry_t   buff_db_entry,
    _In_ mlnx_sai_buffer_pool_attr_t          sai_pool_attr,
    _In_ mlnx_affect_port_buff_items_t const* affected_items)
{
    sai_status_t             sai_status;
    sx_cos_buffer_max_mode_e sx_pool_mode;
    uint32_t                 ind;

    SX_LOG_ENTER();
    SX_LOG_DBG("count:%d\n", count);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = convert_sai_pool_mode_to_sx_pool_mode(sai_pool_attr.pool_mode, &sx_pool_mode))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    for (ind = 0; ind < count; ind++) {
        switch (sai_pool_attr.pool_type) {
        case SAI_BUFFER_POOL_TYPE_INGRESS:
            switch (sx_port_shared_buff_attr_arr[ind].type) {
            case SX_COS_INGRESS_PORT_ATTR_E:
                if (true ==
                    affected_items->i_port_buffers[sx_port_shared_buff_attr_arr[ind].attr.ingress_port_shared_buff_attr
                                                   .pool_id -
                                                   g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id])
                {
                    SX_LOG_DBG("(i)port_buffers[%d], pool_id:%d\n", ind,
                               sx_port_shared_buff_attr_arr[ind].attr.ingress_port_shared_buff_attr.pool_id);
                    sx_port_shared_buff_attr_arr[ind].attr.ingress_port_shared_buff_attr.max.mode = sx_pool_mode;
                    if (SAI_STATUS_SUCCESS !=
                        (sai_status = mlnx_sai_shared_max_to_sx(&sx_port_shared_buff_attr_arr[ind].attr.
                                                                ingress_port_shared_buff_attr.max,
                                                                buff_db_entry.shared_max))) {
                        SX_LOG_EXIT();
                        return sai_status;
                    }
                    sx_port_shared_buff_attr_arr[ind].attr.ingress_port_shared_buff_attr.pool_id =
                        sai_pool_attr.sx_pool_id;
                    log_sx_port_shared_buffers(0, 1, &sx_port_shared_buff_attr_arr[ind]);
                }
                break;

            case SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E:
                if (sx_port_shared_buff_attr_arr[ind].attr.ingress_port_pg_shared_buff_attr.pg >=
                    mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff) {
                    /* control traffic is not supported */
                    continue;
                }
                if (true ==
                    affected_items->pgs[sx_port_shared_buff_attr_arr[ind].attr.ingress_port_pg_shared_buff_attr.pg]) {
                    SX_LOG_DBG("item:%d, pg[%d]:\n",
                               ind,
                               sx_port_shared_buff_attr_arr[ind].attr.ingress_port_pg_shared_buff_attr.pg);
                    sx_port_shared_buff_attr_arr[ind].attr.ingress_port_pg_shared_buff_attr.max.mode = sx_pool_mode;
                    if (SAI_STATUS_SUCCESS !=
                        (sai_status = mlnx_sai_shared_max_to_sx(&sx_port_shared_buff_attr_arr[ind].attr.
                                                                ingress_port_pg_shared_buff_attr.
                                                                max, buff_db_entry.shared_max))) {
                        SX_LOG_EXIT();
                        return sai_status;
                    }
                    sx_port_shared_buff_attr_arr[ind].attr.ingress_port_pg_shared_buff_attr.pool_id =
                        sai_pool_attr.sx_pool_id;
                    log_sx_port_shared_buffers(0, 1, &sx_port_shared_buff_attr_arr[ind]);
                }
                break;

            default:
                break;
            }
            break;

        case SAI_BUFFER_POOL_TYPE_EGRESS:
            switch (sx_port_shared_buff_attr_arr[ind].type) {
            case SX_COS_EGRESS_PORT_ATTR_E:
                assert((sx_port_shared_buff_attr_arr[ind].attr.egress_port_shared_buff_attr.pool_id -
                        g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id) <
                       buffer_limits.num_egress_pools);
                if (true ==
                    affected_items->e_port_buffers[sx_port_shared_buff_attr_arr[ind].attr.egress_port_shared_buff_attr.
                                                   pool_id -
                                                   g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id]) {
                    SX_LOG_DBG("(e)port_buffers[%d], pool_id:%d\n", ind,
                               sx_port_shared_buff_attr_arr[ind].attr.egress_port_shared_buff_attr.pool_id);
                    sx_port_shared_buff_attr_arr[ind].attr.egress_port_shared_buff_attr.max.mode = sx_pool_mode;
                    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_shared_max_to_sx(
                                                   &sx_port_shared_buff_attr_arr[ind].attr.egress_port_shared_buff_attr
                                                   .max, buff_db_entry.shared_max))) {
                        SX_LOG_EXIT();
                        return sai_status;
                    }
                    sx_port_shared_buff_attr_arr[ind].attr.egress_port_shared_buff_attr.pool_id =
                        sai_pool_attr.sx_pool_id;
                    log_sx_port_shared_buffers(0, 1, &sx_port_shared_buff_attr_arr[ind]);
                }
                break;

            case SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E:
                if (sx_port_shared_buff_attr_arr[ind].attr.egress_port_tc_shared_buff_attr.tc >=
                    mlnx_sai_get_buffer_resource_limits()->num_port_queue_buff) {
                    /* control traffic is not supported */
                    continue;
                }
                if (true ==
                    affected_items->tcs[sx_port_shared_buff_attr_arr[ind].attr.egress_port_tc_shared_buff_attr.tc]) {
                    SX_LOG_DBG("item:%d, queue:%d\n",
                               ind,
                               sx_port_shared_buff_attr_arr[ind].attr.egress_port_tc_shared_buff_attr.tc);
                    sx_port_shared_buff_attr_arr[ind].attr.egress_port_tc_shared_buff_attr.max.mode = sx_pool_mode;
                    if (SAI_STATUS_SUCCESS !=
                        (sai_status = mlnx_sai_shared_max_to_sx(&sx_port_shared_buff_attr_arr[ind].attr.
                                                                egress_port_tc_shared_buff_attr.
                                                                max, buff_db_entry.shared_max))) {
                        SX_LOG_EXIT();
                        return sai_status;
                    }
                    sx_port_shared_buff_attr_arr[ind].attr.egress_port_tc_shared_buff_attr.pool_id =
                        sai_pool_attr.sx_pool_id;
                    log_sx_port_shared_buffers(0, 1, &sx_port_shared_buff_attr_arr[ind]);
                }
                break;

            default:
                break;
            }
            break;

        default:
            break;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}
/* At least one optional parameter must be present */
static sai_status_t mlnx_sai_buffer_prepare_affected_buffers(_In_ const mlnx_sai_buffer_pool_attr_t     *sai_pool_attr,
                                                             _In_ mlnx_affect_port_buff_items_t const   *affected_items,
                                                             _Out_opt_ sx_cos_port_shared_buffer_attr_t *sx_port_shared_buff_attr_arr,
                                                             _Out_opt_ sx_cos_port_buffer_attr_t        *sx_port_reserved_buff_attr_arr)
{
    uint32_t cos_buffer_ind = 0;
    uint32_t ind;

    SX_LOG_ENTER();
    SX_LOG_DBG("pool_type:%d\n", sai_pool_attr->pool_type);
    log_sai_pool_attribs(sai_pool_attr);
    if (!sx_port_shared_buff_attr_arr && !sx_port_reserved_buff_attr_arr) {
        SX_LOG_ERR("At least one sx array must be allocated \n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    switch (sai_pool_attr->pool_type) {
    case SAI_BUFFER_POOL_TYPE_INGRESS:
        for (ind = 0; ind < buffer_limits.num_port_pg_buff; ind++) {
            if (affected_items->pgs[ind]) {
                assert(cos_buffer_ind < affected_items->affected_count);
                if (sx_port_reserved_buff_attr_arr) {
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].attr.ingress_port_pg_buff_attr.pg = ind;
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].attr.ingress_port_pg_buff_attr.pool_id =
                        sai_pool_attr->sx_pool_id;
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
                }
                if (sx_port_shared_buff_attr_arr) {
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].attr.ingress_port_pg_shared_buff_attr.pg = ind;
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].attr.ingress_port_pg_shared_buff_attr.pool_id =
                        sai_pool_attr->sx_pool_id;
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
                }
                cos_buffer_ind++;
            }
        }
        for (ind = 0; ind < buffer_limits.num_ingress_pools; ind++) {
            if (affected_items->i_port_buffers[ind]) {
                assert(cos_buffer_ind < affected_items->affected_count);
                if (sx_port_reserved_buff_attr_arr) {
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].attr.ingress_port_buff_attr.pool_id = ind +
                                                                                                         g_sai_buffer_db_ptr
                                                                                                         ->
                                                                                                         buffer_pool_ids
                                                                                                         .
                                                                                                         base_ingress_user_sx_pool_id;
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_INGRESS_PORT_ATTR_E;
                }
                if (sx_port_shared_buff_attr_arr) {
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].attr.ingress_port_shared_buff_attr.pool_id = ind +
                                                                                                              g_sai_buffer_db_ptr
                                                                                                              ->
                                                                                                              buffer_pool_ids
                                                                                                              .
                                                                                                              base_ingress_user_sx_pool_id;
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_INGRESS_PORT_ATTR_E;
                }
                cos_buffer_ind++;
            }
        }
        break;

    case SAI_BUFFER_POOL_TYPE_EGRESS:
        for (ind = 0; ind < buffer_limits.num_port_queue_buff; ind++) {
            if (affected_items->tcs[ind]) {
                assert(cos_buffer_ind < affected_items->affected_count);
                if (sx_port_reserved_buff_attr_arr) {
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].attr.egress_port_tc_buff_attr.pool_id =
                        sai_pool_attr->sx_pool_id;
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].attr.egress_port_tc_buff_attr.tc = ind;
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E;
                }
                if (sx_port_shared_buff_attr_arr) {
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].attr.egress_port_tc_shared_buff_attr.tc = ind;
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E;
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].attr.egress_port_tc_shared_buff_attr.pool_id =
                        sai_pool_attr->sx_pool_id;
                }
                cos_buffer_ind++;
            }
        }
        for (ind = 0; ind < buffer_limits.num_egress_pools; ind++) {
            if (affected_items->e_port_buffers[ind]) {
                assert(cos_buffer_ind < affected_items->affected_count);
                if (sx_port_reserved_buff_attr_arr) {
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].attr.egress_port_buff_attr.pool_id = ind +
                                                                                                        g_sai_buffer_db_ptr
                                                                                                        ->
                                                                                                        buffer_pool_ids
                                                                                                        .
                                                                                                        base_egress_user_sx_pool_id;
                    sx_port_reserved_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_EGRESS_PORT_ATTR_E;
                }
                if (sx_port_shared_buff_attr_arr) {
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].attr.egress_port_shared_buff_attr.pool_id = ind +
                                                                                                             g_sai_buffer_db_ptr
                                                                                                             ->
                                                                                                             buffer_pool_ids
                                                                                                             .
                                                                                                             base_egress_user_sx_pool_id;
                    sx_port_shared_buff_attr_arr[cos_buffer_ind].type =
                        SX_COS_EGRESS_PORT_ATTR_E;
                }
                cos_buffer_ind++;
            }
        }
        break;

    default:
        SX_LOG_ERR("Invalid pool type:%d\n", sai_pool_attr->pool_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_DBG("cos_buffer_ind.1:%d\n", cos_buffer_ind);
    assert(affected_items->affected_count == cos_buffer_ind);
    SX_LOG_DBG("[start]:constructed buffers buffer count:%d\n", affected_items->affected_count);
    if (sx_port_reserved_buff_attr_arr) {
        log_sx_port_buffers(0, affected_items->affected_count, sx_port_reserved_buff_attr_arr);
    }
    if (sx_port_shared_buff_attr_arr) {
        log_sx_port_shared_buffers(0, affected_items->affected_count, sx_port_shared_buff_attr_arr);
    }
    SX_LOG_DBG("[end]:constructed buffers\n");
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static void mlnx_sai_buffer_calculate_max_pool_loan_and_update_affected_items(
    _In_ sai_object_id_t                 sai_ipool_id,
    _In_ const uint32_t                 *sai_port_pg_profile_refs,
    _In_ uint32_t                        cells_coeff,
    _Out_ uint32_t                      *pool_loan,
    _Out_ mlnx_affect_port_buff_items_t *mlnx_sai_affected_items)
{
    uint32_t                                  sai_pg_ind = 0;
    uint32_t                                  sai_buff_ind = 0;
    uint32_t                                  max_pool_loan = 0;
    const mlnx_sai_db_buffer_profile_entry_t *mlnx_sai_buff_db_entry = NULL;
    uint32_t                                  result = 0;
    uint32_t                                  psb_min_size =
        SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_MIN_SIZE * cells_coeff;

    SX_LOG_ENTER();

    assert(sai_port_pg_profile_refs);
    assert(pool_loan);
    assert(mlnx_sai_affected_items);

    /* sai_pg_ind 0 ... 7 */
    for (sai_pg_ind = 0; sai_pg_ind < buffer_limits.num_port_pg_buff; sai_pg_ind++) {
        sai_buff_ind = sai_port_pg_profile_refs[sai_pg_ind];

        /* not pg relevant */
        if (SENTINEL_BUFFER_DB_ENTRY_INDEX == sai_buff_ind) {
            continue;
        }

        mlnx_sai_buff_db_entry = &g_sai_buffer_db_ptr->buffer_profiles[sai_buff_ind];

        if ((mlnx_sai_buff_db_entry->sai_pool == sai_ipool_id) &&
            (mlnx_sai_buff_db_entry->xon || mlnx_sai_buff_db_entry->xoff)) {
            /* update max pool loan for port shared headroom buffer*/
            result = mlnx_sai_buff_db_entry->xoff -
                     (mlnx_sai_buff_db_entry->reserved_size - mlnx_sai_buff_db_entry->xon);
            if (mlnx_sai_buff_db_entry->xoff < result) {
                result = 0;
            }
            max_pool_loan += result;
            mlnx_sai_affected_items->pgs[sai_pg_ind] = true;
            mlnx_sai_affected_items->affected_count++;
        }
    }

    /* compute max pool loan for port shared headroom buffer*/
    if (max_pool_loan) {
        max_pool_loan = (bytes_to_mlnx_cells(max_pool_loan) < bytes_to_mlnx_cells(psb_min_size)) ?
                        0 : mlnx_cells_to_bytes(bytes_to_mlnx_cells(max_pool_loan) -
                                                bytes_to_mlnx_cells(psb_min_size));
    }

    *pool_loan = max_pool_loan;

    SX_LOG_EXIT();
}

static sai_status_t mlnx_sai_buffer_calculate_psb_max_pool_loan(
    _In_ mlnx_affect_port_buff_items_t const      *affected_items,
    _In_ mlnx_sai_db_buffer_profile_entry_t const *buff_db_entry,
    _In_ uint32_t                                  cells_coeff,
    _In_ uint32_t                                  db_port_ind,
    _Out_ uint32_t                                *pool_loan)
{
    sai_status_t                              sai_status = SAI_STATUS_SUCCESS;
    uint32_t                                 *sai_port_pg_profile_refs = NULL;    /* do not free */
    uint32_t                                  ii = 0;
    const mlnx_sai_db_buffer_profile_entry_t *mlnx_sai_buff_db_entry = NULL;
    uint32_t                                  max_pool_loan = 0;
    uint32_t                                  result = 0;
    uint32_t                                  sai_buff_ind = 0;
    uint32_t                                  psb_min_size =
        SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_MIN_SIZE * cells_coeff;

    /* take previous pg profile indexes stored in db */
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_sai_get_port_buffer_index_array(db_port_ind,
                                                  PORT_BUFF_TYPE_PG,
                                                  &sai_port_pg_profile_refs))) {
        goto bail;
    }

    /* calculate max pool loan based on previous values and new ones */
    /* max_pool_loan = port.SUM(PG.xoff - (PG.size - PG.xon)) - PSB.size */
    for (ii = 0; ii < buffer_limits.num_port_pg_buff; ++ii) {
        if (affected_items->pgs[ii]) {
            if ((buff_db_entry->sai_pool == g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id) &&
                (buff_db_entry->xon || buff_db_entry->xoff)) {
                result = buff_db_entry->xoff - (buff_db_entry->reserved_size - buff_db_entry->xon);
                /* workaround if the result is negative */
                if (buff_db_entry->xoff < result) {
                    result = 0;
                }
                max_pool_loan += result;
            }
        } else {
            sai_buff_ind = sai_port_pg_profile_refs[ii];

            /* not pg relevant */
            if (SENTINEL_BUFFER_DB_ENTRY_INDEX == sai_buff_ind) {
                continue;
            }
            mlnx_sai_buff_db_entry = &g_sai_buffer_db_ptr->buffer_profiles[sai_buff_ind];

            if ((mlnx_sai_buff_db_entry->sai_pool == g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id) &&
                (mlnx_sai_buff_db_entry->xon || mlnx_sai_buff_db_entry->xoff)) {
                result = mlnx_sai_buff_db_entry->xoff -
                         (mlnx_sai_buff_db_entry->reserved_size - mlnx_sai_buff_db_entry->xon);
                /* sanity check */
                if (mlnx_sai_buff_db_entry->xoff < result) {
                    result = 0;
                }
                max_pool_loan += result;
            }
        }
    }

    if (max_pool_loan) {
        max_pool_loan = (bytes_to_mlnx_cells(max_pool_loan) < bytes_to_mlnx_cells(psb_min_size)) ?
                        0 : mlnx_cells_to_bytes(bytes_to_mlnx_cells(max_pool_loan) -
                                                bytes_to_mlnx_cells(psb_min_size));
    }

    *pool_loan = max_pool_loan;
bail:
    return sai_status;
}

static sai_status_t mlnx_sai_apply_buffer_settings_to_port(_In_ sx_port_log_id_t                     log_port,
                                                           _In_ mlnx_sai_db_buffer_profile_entry_t   buff_db_entry,
                                                           _In_ mlnx_affect_port_buff_items_t const* affected_items)
{
    sai_status_t                      sai_status = SAI_STATUS_SUCCESS;
    sx_cos_port_shared_buffer_attr_t *sx_port_shared_buff_attr_arr = NULL;
    sx_cos_port_buffer_attr_t        *sx_port_reserved_buff_attr_arr = NULL;
    uint32_t                          sai_reserved_buf_count = 0;
    uint32_t                          sai_shared_buf_count = 0;
    uint32_t                          db_port_ind = UINT_MAX;
    mlnx_port_config_t               *port = NULL;
    mlnx_sai_buffer_pool_attr_t       new_pool_attr = {0};
    mlnx_sai_buffer_pool_attr_t       sai_shp_pool_attr = {0};
    uint32_t                          ii = 0;
    uint32_t                          max_pool_loan = 0;
    bool                              is_update_psb = false;
    uint32_t                          cells_coeff = 1;


    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(buff_db_entry.sai_pool, &new_pool_attr))) {
        goto bail;
    }
    mlnx_port_phy_foreach(port, db_port_ind) {
        if (port->logical == log_port) {
            break;
        }
    }

    /* PSB changes are performed only when SHP is created and pg changes are involved */
    if (g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created) {
        for (ii = 0; ii < buffer_limits.num_port_pg_buff; ++ii) {
            if (affected_items->pgs[ii]) {
                is_update_psb = true;
                break;
            }
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_port_psb_cells_coefficient_get(&port->logical, &cells_coeff))) {
        goto bail;
    }

    if (is_update_psb &&
        (SAI_STATUS_SUCCESS !=
         (sai_status = mlnx_sai_buffer_calculate_psb_max_pool_loan(affected_items,
                                                                   &buff_db_entry, cells_coeff, db_port_ind,
                                                                   &max_pool_loan)))) {
        goto bail;
    }

    sai_reserved_buf_count = is_update_psb ?
                             (affected_items->affected_count + 1) :
                             (affected_items->affected_count);
    sai_shared_buf_count = affected_items->affected_count;
    SX_LOG_DBG("sai_reserved_buf_count.1:%d\n", sai_reserved_buf_count);
    SX_LOG_DBG("sai_shared_buf_count.1:%d\n", sai_shared_buf_count);

    assert(sai_reserved_buf_count <= (is_update_psb ?
                                      (buffer_limits.max_buffers_per_port + 1) :
                                      (buffer_limits.max_buffers_per_port)));
    assert(sai_shared_buf_count <= buffer_limits.max_buffers_per_port);
    sx_port_shared_buff_attr_arr = calloc(sai_shared_buf_count, sizeof(sx_cos_port_shared_buffer_attr_t));
    if (!sx_port_shared_buff_attr_arr) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto bail;
    }
    sx_port_reserved_buff_attr_arr = calloc(sai_reserved_buf_count, sizeof(sx_cos_port_buffer_attr_t));
    if (!sx_port_reserved_buff_attr_arr) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto bail;
    }

    if (is_update_psb) {
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       mlnx_get_sai_pool_data(g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id,
                                                              &sai_shp_pool_attr))) {
            goto bail;
        }

        /* Add port shared (headroom) buffer to sx attribute array as last element */
        sx_port_reserved_buff_attr_arr[sai_reserved_buf_count - 1].type = SX_COS_PORT_SHARED_HEADROOM_E;

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_buffer_construct_psb_sx_attr_internal
                              (&sx_port_reserved_buff_attr_arr[sai_reserved_buf_count -
                                                               1].attr.port_shared_headroom_attr,
                              sai_shp_pool_attr.sx_pool_id,
                              max_pool_loan,
                              &port->logical))) {
            goto bail;
        }
    }

    /* create only those buffers which are affected */
    if (SAI_STATUS_SUCCESS != (
            sai_status =
                mlnx_sai_buffer_prepare_affected_buffers(&new_pool_attr,
                                                         affected_items, sx_port_shared_buff_attr_arr,
                                                         sx_port_reserved_buff_attr_arr))) {
        SX_LOG_ERR("Failed to prepare affected buffers, status:%d\n", sai_status);
        goto bail;
    }

    mlnx_sai_buffer_apply_profile_to_reserved_structs(sx_port_reserved_buff_attr_arr,
                                                      sai_reserved_buf_count,
                                                      &buff_db_entry,
                                                      &new_pool_attr,
                                                      affected_items);

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_buffer_apply_profile_to_shared_structs(
                                   sx_port_shared_buff_attr_arr, sai_shared_buf_count, buff_db_entry, new_pool_attr,
                                   affected_items))) {
        goto bail;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_sai_buffer_configure_reserved_buffers(log_port, sx_port_reserved_buff_attr_arr,
                                                        sai_reserved_buf_count))) {
        log_sx_port_buffers(db_port_ind, sai_reserved_buf_count, sx_port_reserved_buff_attr_arr);
        goto bail;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_sai_buffer_configure_shared_buffers(log_port, sx_port_shared_buff_attr_arr, sai_shared_buf_count))) {
        log_sx_port_shared_buffers(db_port_ind, sai_shared_buf_count, sx_port_shared_buff_attr_arr);
        goto bail;
    }

bail:
    safe_free(sx_port_shared_buff_attr_arr);
    safe_free(sx_port_reserved_buff_attr_arr);
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t set_mc_sp_zero(_In_ uint32_t sp)
{
    sai_status_t                      sai_status = SAI_STATUS_FAILURE;
    sx_status_t                       sx_status;
    const sx_port_log_id_t            mc_port_log_id = SX_MC_PORT_LOG_ID;
    sx_cos_port_shared_buffer_attr_t *sx_port_shared_buff_attr_array = NULL;
    sx_cos_port_buffer_attr_t        *sx_port_reserved_buff_attr_array = NULL;
    uint32_t                          attr_count = MAX_LOSSLESS_SP;
    uint32_t                          idx = 0;
    sx_cos_buffer_max_mode_e          max_mode;

    sx_port_shared_buff_attr_array = calloc(attr_count, sizeof(sx_cos_port_shared_buffer_attr_t));
    if (!sx_port_shared_buff_attr_array) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto cleanup;
    }

    sx_port_reserved_buff_attr_array = calloc(attr_count, sizeof(sx_cos_port_buffer_attr_t));
    if (!sx_port_reserved_buff_attr_array) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto cleanup;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_cos_port_buff_type_get(gh_sdk,
                                                   mc_port_log_id,
                                                   sx_port_reserved_buff_attr_array,
                                                   &attr_count))) {
        SX_LOG_ERR("Failed to get multicast reserved buffers. Error: %s\n",
                   SX_STATUS_MSG(sx_status));
        goto cleanup;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_cos_port_shared_buff_type_get(gh_sdk,
                                                          mc_port_log_id,
                                                          sx_port_shared_buff_attr_array,
                                                          &attr_count))) {
        SX_LOG_ERR("Failed to get multicast shared buffers. Error: %s\n",
                   SX_STATUS_MSG(sx_status));
        goto cleanup;
    }
    for (idx = 0; idx < attr_count; idx++) {
        SX_LOG_DBG("sp: %d zero sp buff idx: %d, buff type: %d, pool id: %d\n",
                   sp,
                   idx,
                   sx_port_reserved_buff_attr_array[idx].type,
                   sx_port_reserved_buff_attr_array[idx].attr.multicast_buff_attr.pool_id);
        if (sp == sx_port_reserved_buff_attr_array[idx].attr.multicast_buff_attr.sp) {
            sx_port_reserved_buff_attr_array[idx].attr.multicast_buff_attr.size = 0;
        }
        if (sp == sx_port_shared_buff_attr_array[idx].attr.multicast_shared_buff_attr.sp) {
            max_mode = sx_port_shared_buff_attr_array[idx].attr.multicast_shared_buff_attr.max.mode;
            if ((SX_COS_BUFFER_MAX_MODE_STATIC_E == max_mode) || (SX_COS_BUFFER_MAX_MODE_BUFFER_UNITS_E == max_mode)) {
                sx_port_shared_buff_attr_array[idx].attr.multicast_shared_buff_attr.max.max.size = 0;
            } else if (SX_COS_BUFFER_MAX_MODE_DYNAMIC_E == max_mode) {
                sx_port_shared_buff_attr_array[idx].attr.multicast_shared_buff_attr.max.max.alpha = 0;
            }
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_configure_reserved_buffers(mc_port_log_id,
                                                                 sx_port_reserved_buff_attr_array,
                                                                 attr_count))) {
        SX_LOG_ERR("Failed to configure reserved buffers\n");
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_configure_shared_buffers(mc_port_log_id,
                                                               sx_port_shared_buff_attr_array,
                                                               attr_count))) {
        SX_LOG_ERR("Failed to configure shared buffers\n");
        goto cleanup;
    }

cleanup:
    if (sx_port_shared_buff_attr_array) {
        free(sx_port_shared_buff_attr_array);
    }

    if (sx_port_reserved_buff_attr_array) {
        free(sx_port_reserved_buff_attr_array);
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_apply_buffer_to_pg(_In_ uint32_t                           port_ind,
                                                       _In_ uint32_t                           pg_ind,
                                                       _In_ mlnx_sai_db_buffer_profile_entry_t buff_db_entry)
{
    sai_status_t                  sai_status = SAI_STATUS_FAILURE;
    mlnx_affect_port_buff_items_t affected_items;
    sx_port_log_id_t              sx_port_id;

#ifdef ACS_OS
    bool                    is_lossy = false;
    uint32_t                sp = 0;
    sx_status_t             sx_status = SX_STATUS_ERROR;
    sx_cos_port_prio_buff_t prio_buff;
#endif

    SX_LOG_ENTER();
    if (!alloc_affected_items(&affected_items)) {
        SX_LOG_EXIT();
        return SAI_STATUS_NO_MEMORY;
    }
    sx_port_id = g_sai_db_ptr->ports_db[port_ind].logical;
    affected_items.pgs[pg_ind] = true;
    affected_items.affected_count = 1;
    sai_status = mlnx_sai_apply_buffer_settings_to_port(sx_port_id,
                                                        buff_db_entry, &affected_items);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR("Error applying buffer settings to port\n");
        goto cleanup;
    }

#ifdef ACS_OS
    sx_status = sx_api_cos_port_prio_buff_map_get(gh_sdk, sx_port_id, &prio_buff);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Error getting cos port prio buff map for sx port id 0x%x, sx error message: %s\n",
                   sx_port_id,
                   SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto cleanup;
    }

    is_lossy = (0 == buff_db_entry.xoff) && (0 == buff_db_entry.xon);

    if (!is_lossy) {
        g_sai_db_ptr->ports_db[port_ind].lossless_pg[pg_ind] = true;
        for (sp = 0; sp < (RM_API_COS_PORT_PRIO_MAX + 1); sp++) {
            if ((pg_ind == prio_buff.prio_to_buff[sp]) &&
                !g_sai_db_ptr->is_switch_priority_lossless[sp]) {
                sai_status = set_mc_sp_zero(sp);
                if (SAI_STATUS_SUCCESS != sai_status) {
                    SX_LOG_ERR("Error setting mc sp to zero for sp %d\n", sp);
                    goto cleanup;
                }
                g_sai_db_ptr->is_switch_priority_lossless[sp] = true;
            }
        }
    }
#endif

cleanup:
    free_affected_items(&affected_items);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_apply_buffer_to_queue(_In_ uint32_t                           qos_db_port_ind,
                                                          _In_ uint32_t                           qos_ind,
                                                          _In_ mlnx_sai_db_buffer_profile_entry_t buff_db_entry)
{
    sai_status_t                  sai_status;
    mlnx_affect_port_buff_items_t affected_items;

    if (!alloc_affected_items(&affected_items)) {
        SX_LOG_EXIT();
        return SAI_STATUS_NO_MEMORY;
    }
    affected_items.tcs[qos_ind] = true;
    affected_items.affected_count = 1;
    SX_LOG_ENTER();
    sai_status = mlnx_sai_apply_buffer_settings_to_port(g_sai_db_ptr->ports_db[qos_db_port_ind].logical,
                                                        buff_db_entry, &affected_items);
    free_affected_items(&affected_items);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_collect_buffer_refs(_In_ sai_object_id_t                 sai_buffer_id,
                                                 _In_ uint32_t                        db_port_ind,
                                                 _Out_ mlnx_affect_port_buff_items_t* affected_items)
{
    uint32_t                    ind;
    sai_status_t                sai_status;
    uint32_t                    db_buffer_profile_index;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr;
    bool                        found_match = false;
    uint32_t                  * buff_profile_refs = NULL;
    mlnx_qos_queue_config_t   * queue_cfg = NULL;
    uint32_t                    affected_count = 0;

    SX_LOG_ENTER();

    if (NULL == affected_items) {
        SX_LOG_ERR("NULL affected_items\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (db_port_ind >= MAX_PORTS) {
        SX_LOG_ERR("Invalid db_port_ind:%d\n", db_port_ind);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_buffer_profile_data(sai_buffer_id, &db_buffer_profile_index, &sai_pool_attr))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_DBG("pool_type:%d db_port_ind:%d\n", sai_pool_attr.pool_type, db_port_ind);
    reset_affected_items(affected_items);

    switch (sai_pool_attr.pool_type) {
    case SAI_BUFFER_POOL_TYPE_INGRESS:
        buff_profile_refs = NULL;
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_sai_get_port_buffer_index_array(db_port_ind, PORT_BUFF_TYPE_PG, &buff_profile_refs))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        for (ind = 0; ind < buffer_limits.num_port_pg_buff; ind++) {
            if (buff_profile_refs[ind] == db_buffer_profile_index) {
                affected_items->pgs[ind] = true;
                SX_LOG_DBG("port[%d].pg[%d]\n", db_port_ind, ind);
                found_match = true;
                affected_count++;
            }
        }
        buff_profile_refs = NULL;
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_sai_get_port_buffer_index_array(db_port_ind, PORT_BUFF_TYPE_INGRESS, &buff_profile_refs))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        for (ind = 0; ind < buffer_limits.num_ingress_pools; ind++) {
            if (buff_profile_refs[ind] == db_buffer_profile_index) {
                affected_items->i_port_buffers[ind] = true;
                found_match = true;
                affected_count++;
                SX_LOG_DBG("port[%d].i_buff[%d]\n", db_port_ind, ind);
            }
        }
        break;

    case SAI_BUFFER_POOL_TYPE_EGRESS:
        buff_profile_refs = NULL;
        for (ind = 0; ind < buffer_limits.num_port_queue_buff; ind++) {
            if (SAI_STATUS_SUCCESS !=
                (sai_status = mlnx_queue_cfg_lookup(g_sai_db_ptr->ports_db[db_port_ind].logical, ind, &queue_cfg))) {
                SX_LOG_EXIT();
                return sai_status;
            }
            if (queue_cfg->buffer_id == sai_buffer_id) {
                affected_items->tcs[ind] = true;
                found_match = true;
                affected_count++;
                SX_LOG_DBG("port[%d].tc[%d]\n", db_port_ind, ind);
            }
        }
        buff_profile_refs = NULL;
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_sai_get_port_buffer_index_array(db_port_ind, PORT_BUFF_TYPE_EGRESS, &buff_profile_refs))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        for (ind = 0; ind < buffer_limits.num_egress_pools; ind++) {
            if (buff_profile_refs[ind] == db_buffer_profile_index) {
                affected_items->e_port_buffers[ind] = true;
                found_match = true;
                affected_count++;
                SX_LOG_DBG("port[%d].e_buff[%d]\n", db_port_ind, ind);
            }
        }
        break;

    default:
        SX_LOG_ERR("Invalid pool type:%d\n", sai_pool_attr.pool_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    SX_LOG_EXIT();
    if (!found_match) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }
    affected_items->affected_count = affected_count;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_buffer_apply_buffer_change_to_references(_In_ sai_object_id_t sai_buffer_id)
{
    sai_status_t                       sai_status = SAI_STATUS_SUCCESS;
    mlnx_affect_port_buff_items_t      affected_items = {0};
    uint32_t                           port_ind = 0;
    uint32_t                           db_buffer_profile_index = 0;
    mlnx_sai_db_buffer_profile_entry_t buff_db_entry = {0};
    mlnx_sai_buffer_pool_attr_t        sai_pool_attr = {0};
    mlnx_port_config_t                *port = NULL;

    SX_LOG_ENTER();
    if (!alloc_affected_items(&affected_items)) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto bail;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_get_sai_buffer_profile_data(sai_buffer_id, &db_buffer_profile_index, &sai_pool_attr))) {
        goto bail;
    }
    buff_db_entry = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index];
    mlnx_port_phy_foreach(port, port_ind) {
        sai_status = mlnx_sai_collect_buffer_refs(sai_buffer_id, port_ind, &affected_items);
        if (SAI_STATUS_ITEM_NOT_FOUND == sai_status) {
            sai_status = SAI_STATUS_SUCCESS;
            continue;
        }
        if (SAI_STATUS_SUCCESS != sai_status) {
            goto bail;
        }
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_sai_apply_buffer_settings_to_port(port->logical, buff_db_entry, &affected_items))) {
            goto bail;
        }
    }

bail:
    free_affected_items(&affected_items);
    SX_LOG_EXIT();
    return sai_status;
}

/** reserved buffer size in bytes [sai_uint32_t] */
static sai_status_t mlnx_sai_set_buffer_profile_size_attr(_In_ const sai_object_key_t      * key,
                                                          _In_ const sai_attribute_value_t * value,
                                                          void                             * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].reserved_size = (uint32_t)value->u64;
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_apply_buffer_change_to_references(key->key.object_id))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** dynamic threshold for the shared usage [sai_int8_t]
 * The threshold is set to the 2^n of available buffer of the pool.
 * Mandatory when SAI_BUFFER_POOL_TH_MODE = SAI_BUFFER_THRESHOLD_MODE_DYNAMIC
 */
static sai_status_t mlnx_sai_get_buffer_profile_dynamic_th_attr(_In_ const sai_object_key_t   * key,
                                                                _Inout_ sai_attribute_value_t * value,
                                                                _In_ uint32_t                   attr_index,
                                                                _Inout_ vendor_cache_t        * cache,
                                                                void                          * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->s8 = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].shared_max.max.alpha;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** dynamic threshold for the shared usage [sai_int8_t]
 * The threshold is set to the 2^n of available buffer of the pool.
 * Mandatory when SAI_BUFFER_POOL_TH_MODE = SAI_BUFFER_THRESHOLD_MODE_DYNAMIC
 */
static sai_status_t mlnx_sai_set_buffer_profile_dynamic_th_attr(_In_ const sai_object_key_t      * key,
                                                                _In_ const sai_attribute_value_t * value,
                                                                void                             * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].shared_max.max.alpha = value->s8;
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_apply_buffer_change_to_references(key->key.object_id))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** static threshold for the shared usage in bytes [sai_uint32_t]
 * Mandatory when SAI_BUFFER_POOL_TH_MODE = SAI_BUFFER_THRESHOLD_MODE_STATIC
 */
static sai_status_t mlnx_sai_get_buffer_profile_static_th_attr(_In_ const sai_object_key_t   * key,
                                                               _Inout_ sai_attribute_value_t * value,
                                                               _In_ uint32_t                   attr_index,
                                                               _Inout_ vendor_cache_t        * cache,
                                                               void                          * arg)
{
    SX_LOG_ENTER();
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->u64 = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].shared_max.max.static_th;
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** static threshold for the shared usage in bytes [sai_uint32_t]
 * Mandatory when SAI_BUFFER_POOL_TH_MODE = SAI_BUFFER_THRESHOLD_MODE_STATIC
 */
static sai_status_t mlnx_sai_set_buffer_profile_static_th_attr(_In_ const sai_object_key_t      * key,
                                                               _In_ const sai_attribute_value_t * value,
                                                               void                             * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].shared_max.max.static_th = value->u32;
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_apply_buffer_change_to_references(key->key.object_id))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** set the buffer profile XOFF threshold in bytes [sai_uint32_t]
 * Valid only for ingress PG.
 * Generate XOFF when available buffer in the PG buffer
 * is less than this threshold.
 * default to 0. */
static sai_status_t mlnx_sai_get_buffer_profile_xoff_attr(_In_ const sai_object_key_t   * key,
                                                          _Inout_ sai_attribute_value_t * value,
                                                          _In_ uint32_t                   attr_index,
                                                          _Inout_ vendor_cache_t        * cache,
                                                          void                          * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->u64 = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].xoff;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** set the buffer profile XOFF threshold in bytes [sai_uint32_t]
 * Valid only for ingress PG.
 * Generate XOFF when available buffer in the PG buffer
 * is less than this threshold.
 * default to 0. */
static sai_status_t mlnx_sai_set_buffer_profile_xoff_attr(_In_ const sai_object_key_t      * key,
                                                          _In_ const sai_attribute_value_t * value,
                                                          void                             * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].xoff = (uint32_t)value->u64;
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_apply_buffer_change_to_references(key->key.object_id))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** set the buffer profile XON threshold in byte [sai_uint32_t]
 * Valid only for ingress PG
 * Generate XON when the total buffer usage of this PG
 * is less this threshold and available buffer in the PG buffer
 * is larger than the XOFF threshold.
 * default to 0. */
static sai_status_t mlnx_sai_get_buffer_profile_xon_attr(_In_ const sai_object_key_t   * key,
                                                         _Inout_ sai_attribute_value_t * value,
                                                         _In_ uint32_t                   attr_index,
                                                         _Inout_ vendor_cache_t        * cache,
                                                         void                          * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->u64 = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].xon;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** set the buffer profile XON threshold in byte [sai_uint32_t]
 * Valid only for ingress PG
 * Generate XON when the total buffer usage of this PG
 * is less this threshold and available buffer in the PG buffer
 * is larger than the XOFF threshold.
 * default to 0. */
static sai_status_t mlnx_sai_set_buffer_profile_xon_attr(_In_ const sai_object_key_t      * key,
                                                         _In_ const sai_attribute_value_t * value,
                                                         void                             * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].xon = (uint32_t)value->u64;
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_buffer_apply_buffer_change_to_references(key->key.object_id))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* get the buffer profile threshold mode [sai_int32_t] */
static sai_status_t mlnx_sai_get_buffer_profile_th_mode(_In_ const sai_object_key_t   * key,
                                                        _Inout_ sai_attribute_value_t * value,
                                                        _In_ uint32_t                   attr_index,
                                                        _Inout_ vendor_cache_t        * cache,
                                                        void                          * arg)
{
    sai_status_t sai_status;
    uint32_t     db_buffer_profile_index;

    SX_LOG_ENTER();
    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = get_buffer_profile_db_index(key->key.object_id, &db_buffer_profile_index))) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }
    value->s32 = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].shared_max.mode;
    cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_set_buffer_profile_attr(_In_ sai_object_id_t buffer_profile_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = buffer_profile_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();
    buffer_profile_key_to_str(buffer_profile_id, key_str);
    sai_status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_BUFFER_PROFILE, buffer_profile_vendor_attribs, attr);
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_get_buffer_profile_attr(_In_ sai_object_id_t      buffer_profile_id,
                                              _In_ uint32_t             attr_count,
                                              _Inout_ sai_attribute_t * attr_list)
{
    char                   key_str[MAX_KEY_STR_LEN];
    const sai_object_key_t key = { .key.object_id = buffer_profile_id };
    sai_status_t           sai_status;

    SX_LOG_ENTER();
    buffer_profile_key_to_str(buffer_profile_id, key_str);
    if (SAI_NULL_OBJECT_ID == buffer_profile_id) {
        SX_LOG_ERR("NULL buffer profile passed in\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    sai_status = sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_BUFFER_PROFILE, buffer_profile_vendor_attribs,
                                    attr_count, attr_list);

    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_buffer_validate_port_buffer_list_and_sort_by_pool(_In_ const sai_attribute_value_t * value,
                                                                        _In_ bool                          is_ingress,
                                                                        _In_ uint32_t                      buff_count,
                                                                        _Out_ sai_object_id_t            * buffer_profiles)
{
    sai_status_t                sai_status;
    uint32_t                    ind;
    mlnx_sai_buffer_pool_attr_t sai_pool_attr;
    uint32_t                    db_buffer_profile_ind;
    uint32_t                    pool_base_ind;

    SX_LOG_ENTER();
    if (!value) {
        SX_LOG_ERR("null value\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (buff_count < value->objlist.count) {
        SX_LOG_ERR("buff_count:%d is smaller than input list size:%d\n", buff_count, value->objlist.count);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (is_ingress) {
        pool_base_ind = g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id;
    } else {
        pool_base_ind = g_sai_buffer_db_ptr->buffer_pool_ids.base_egress_user_sx_pool_id;
    }

    for (ind = 0; ind < value->objlist.count; ind++) {
        if (SAI_NULL_OBJECT_ID == value->objlist.list[ind]) {
            continue;
        }
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_get_sai_buffer_profile_data(value->objlist.list[ind], &db_buffer_profile_ind, &sai_pool_attr))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        if (is_ingress) {
            if (SAI_BUFFER_POOL_TYPE_EGRESS == sai_pool_attr.pool_type) {
                SX_LOG_ERR("Egress buffer profile:0x%" PRIx64 " specified for ingress port buffer list\n",
                           value->objlist.list[ind]);
                SX_LOG_EXIT();
                return SAI_STATUS_INVALID_PARAMETER;
            }
        } else {
            if (SAI_BUFFER_POOL_TYPE_INGRESS == sai_pool_attr.pool_type) {
                SX_LOG_ERR("Ingress buffer profile:0x%" PRIx64 " specified for egress port buffer list\n",
                           value->objlist.list[ind]);
                SX_LOG_EXIT();
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        if (SAI_NULL_OBJECT_ID != buffer_profiles[sai_pool_attr.sx_pool_id - pool_base_ind]) {
            SX_LOG_ERR("SX pool:%d specified more than once\n", sai_pool_attr.sx_pool_id);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_PARAMETER;
        }
        buffer_profiles[sai_pool_attr.sx_pool_id - pool_base_ind] = value->objlist.list[ind];
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_buffer_apply_port_buffer_profile_list(_In_ bool             is_ingress,
                                                            _In_ uint32_t         db_port_ind,
                                                            _Inout_ uint32_t    * db_port_buffers,
                                                            _In_ uint32_t         buff_count,
                                                            _In_ sai_object_id_t* buffer_profiles)
{
    sai_status_t                       sai_status;
    uint32_t                           ind;
    mlnx_sai_db_buffer_profile_entry_t buffer_entry;
    sai_object_id_t                    sai_pool;
    uint32_t                           pool_id;
    mlnx_sai_buffer_pool_attr_t        sai_pool_attr;
    mlnx_affect_port_buff_items_t      affected_items;
    uint32_t                           db_buffer_profile_ind;
    uint32_t                           pool_db_index;

    SX_LOG_ENTER();
    if (!alloc_affected_items(&affected_items)) {
        SX_LOG_EXIT();
        return SAI_STATUS_NO_MEMORY;
    }
    for (ind = 0; ind < buff_count; ind++) {
        SX_LOG_DBG("buffer_profiles[%d]:0x%" PRIx64 "\n", ind, buffer_profiles[ind]);
        reset_affected_items(&affected_items);
        memset(&buffer_entry, 0, sizeof(buffer_entry));
        if (SAI_NULL_OBJECT_ID == buffer_profiles[ind]) {
            pool_id =
                is_ingress ? g_sai_buffer_db_ptr->buffer_pool_ids.base_ingress_user_sx_pool_id : g_sai_buffer_db_ptr->
                buffer_pool_ids.base_egress_user_sx_pool_id;
            pool_id += ind;
            pool_db_index =
                (is_ingress) ? (1 + ind) : (1 + mlnx_sai_get_buffer_resource_limits()->num_ingress_pools + ind);
            if (!g_sai_buffer_db_ptr->pool_allocation[pool_db_index]) {
                SX_LOG_DBG("Skipping port pool buffer:%d index:%d, since the pool doesn't exist\n", pool_id, ind);
                continue;
            }
            if (SAI_STATUS_SUCCESS != (sai_status = mlnx_create_sai_pool_id(pool_id, &sai_pool))) {
                free_affected_items(&affected_items);
                SX_LOG_EXIT();
                return sai_status;
            }
            if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(sai_pool, &sai_pool_attr))) {
                free_affected_items(&affected_items);
                SX_LOG_EXIT();
                return sai_status;
            }
            buffer_entry.is_valid = true;
            buffer_entry.sai_pool = sai_pool;

            SX_LOG_DBG("Resetting port buffer profile reference on port[%d].buff[%d], ingress:%d\n",
                       db_port_ind, ind, is_ingress);
            db_port_buffers[ind] = SENTINEL_BUFFER_DB_ENTRY_INDEX;
        } else {
            if (SAI_STATUS_SUCCESS !=
                (sai_status =
                     mlnx_get_sai_buffer_profile_data(buffer_profiles[ind], &db_buffer_profile_ind, &sai_pool_attr))) {
                free_affected_items(&affected_items);
                SX_LOG_EXIT();
                return sai_status;
            }
            buffer_entry = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_ind];
            db_port_buffers[ind] = db_buffer_profile_ind;
        }
        if (is_ingress) {
            affected_items.i_port_buffers[ind] = true;
        } else {
            affected_items.e_port_buffers[ind] = true;
        }
        affected_items.affected_count = 1;
        /* Note: pool_id never changes for port pool buffer, hence last parameter == false */
        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_apply_buffer_settings_to_port(
                                       g_sai_db_ptr->ports_db[db_port_ind].logical, buffer_entry, &affected_items))) {
            free_affected_items(&affected_items);
            SX_LOG_EXIT();
            return sai_status;
        }
    }
    free_affected_items(&affected_items);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* db write lock is needed */
static sai_status_t mlnx_set_default_port_buffer_settings(_In_ const sx_port_log_id_t log_port, bool is_ingress)
{
    sai_status_t                      status = SAI_STATUS_SUCCESS;
    uint32_t                          ii;
    uint32_t                          port_buff_count;
    uint32_t                          port_buffers_type;
    uint32_t                         *db_port_buffers = NULL;
    uint32_t                          db_port_ind;
    mlnx_sai_buffer_pool_attr_t       sai_pool_attr = {0};
    sx_cos_port_shared_buffer_attr_t *sx_port_shared_buff_attrs = NULL;
    sx_cos_port_buffer_attr_t        *sx_port_reserved_buff_attrs = NULL;
    uint32_t                          attrs_count = 0;

    SX_LOG_ENTER();

    if (is_ingress) {
        port_buffers_type = PORT_BUFF_TYPE_INGRESS;
        port_buff_count = buffer_limits.num_ingress_pools;
    } else {
        port_buffers_type = PORT_BUFF_TYPE_EGRESS;
        port_buff_count = buffer_limits.num_egress_pools;
    }

    sx_port_reserved_buff_attrs = calloc(port_buff_count, sizeof(*sx_port_reserved_buff_attrs));
    if (sx_port_reserved_buff_attrs == NULL) {
        return SAI_STATUS_NO_MEMORY;
    }

    sx_port_shared_buff_attrs = calloc(port_buff_count, sizeof(*sx_port_shared_buff_attrs));
    if (sx_port_shared_buff_attrs == NULL) {
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    status = mlnx_port_idx_by_log_id(log_port, &db_port_ind);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port db index by log port id %#0x\n", log_port);
        goto out;
    }

    status = mlnx_sai_get_port_buffer_index_array(db_port_ind, port_buffers_type, &db_port_buffers);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port buffer index array for port index %d\n", db_port_ind);
        goto out;
    }

    for (ii = 0; ii < port_buff_count; ii++) {
        if (db_port_buffers[ii] == SENTINEL_BUFFER_DB_ENTRY_INDEX) {
            continue;
        }

        status = mlnx_get_sai_pool_data(g_sai_buffer_db_ptr->buffer_profiles[db_port_buffers[ii]].sai_pool,
                                        &sai_pool_attr);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sai pool data for port index %d, buffer index %d\n", db_port_ind, ii);
            goto out;
        }

        if (is_ingress) {
            sx_port_reserved_buff_attrs[attrs_count].type = SX_COS_INGRESS_PORT_ATTR_E;
            sx_port_reserved_buff_attrs[attrs_count].attr.ingress_port_buff_attr.pool_id = sai_pool_attr.sx_pool_id;
            sx_port_reserved_buff_attrs[attrs_count].attr.ingress_port_buff_attr.size = 0;

            sx_port_shared_buff_attrs[attrs_count].type = SX_COS_INGRESS_PORT_ATTR_E;
            sx_port_shared_buff_attrs[attrs_count].attr.ingress_port_shared_buff_attr.pool_id =
                sai_pool_attr.sx_pool_id;
            sx_port_shared_buff_attrs[attrs_count].attr.ingress_port_shared_buff_attr.max.mode =
                SX_COS_BUFFER_MAX_MODE_STATIC_E;
            sx_port_shared_buff_attrs[attrs_count].attr.ingress_port_shared_buff_attr.max.max.size = 0;
        } else {
            sx_port_reserved_buff_attrs[attrs_count].type = SX_COS_EGRESS_PORT_ATTR_E;
            sx_port_reserved_buff_attrs[attrs_count].attr.egress_port_buff_attr.pool_id = sai_pool_attr.sx_pool_id;
            sx_port_reserved_buff_attrs[attrs_count].attr.egress_port_buff_attr.size = 0;

            sx_port_shared_buff_attrs[attrs_count].type = SX_COS_EGRESS_PORT_ATTR_E;
            sx_port_shared_buff_attrs[attrs_count].attr.egress_port_shared_buff_attr.pool_id =
                sai_pool_attr.sx_pool_id;
            sx_port_shared_buff_attrs[attrs_count].attr.egress_port_shared_buff_attr.max.mode =
                SX_COS_BUFFER_MAX_MODE_STATIC_E;
            sx_port_shared_buff_attrs[attrs_count].attr.egress_port_shared_buff_attr.max.max.size = 0;
        }

        attrs_count++;
    }

    if (attrs_count > 0) {
        status = mlnx_sai_buffer_configure_reserved_buffers(log_port, sx_port_reserved_buff_attrs, attrs_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to configure buffer reserved attributes for port db idx %d\n", db_port_ind);
            goto out;
        }

        status = mlnx_sai_buffer_configure_shared_buffers(log_port, sx_port_shared_buff_attrs, attrs_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to configure buffer shared attributes for port db idx %d\n", db_port_ind);
            goto out;
        }

        for (ii = 0; ii < port_buff_count; ii++) {
            db_port_buffers[ii] = SENTINEL_BUFFER_DB_ENTRY_INDEX;
        }
    }
out:
    if (sx_port_reserved_buff_attrs) {
        free(sx_port_reserved_buff_attrs);
    }

    if (sx_port_shared_buff_attrs) {
        free(sx_port_shared_buff_attrs);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_buffer_port_profile_list_set_unlocked_impl(_In_ const sx_port_log_id_t       log_port,
                                                                    _In_ const sai_attribute_value_t *value,
                                                                    _In_ bool                         is_ingress)
{
    sai_status_t     status = SAI_STATUS_SUCCESS;
    uint32_t         db_port_ind = 0;
    uint32_t        *db_port_buffers = NULL;
    sai_object_id_t *buffer_profiles = NULL;
    uint32_t         buff_count = 0;
    uint32_t         port_buffers_type;

    assert(value);

    SX_LOG_ENTER();

    SX_LOG_DBG("is_ingress:%d\n", is_ingress);

    if (is_ingress) {
        if (value->objlist.count > buffer_limits.num_ingress_pools) {
            SX_LOG_ERR("Too many ingress entries specified\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_PARAMETER;
        }
        port_buffers_type = PORT_BUFF_TYPE_INGRESS;
        buff_count = buffer_limits.num_ingress_pools;
    } else {
        if (value->objlist.count > buffer_limits.num_egress_pools) {
            SX_LOG_ERR("Too many egress entries specified\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_PARAMETER;
        }
        port_buffers_type = PORT_BUFF_TYPE_EGRESS;
        buff_count = buffer_limits.num_egress_pools;
    }

    status = mlnx_port_idx_by_log_id(log_port, &db_port_ind);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port db index by log port id %#0x\n", log_port);
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_sai_get_port_buffer_index_array(db_port_ind, port_buffers_type, &db_port_buffers);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port buffer index array for port index %d\n", db_port_ind);
        SX_LOG_EXIT();
        return status;
    }

    buffer_profiles = calloc(buff_count, sizeof(sai_object_id_t));
    if (NULL == buffer_profiles) {
        return SAI_STATUS_NO_MEMORY;
    }

    status =
        mlnx_sai_buffer_validate_port_buffer_list_and_sort_by_pool(value, is_ingress, buff_count, buffer_profiles);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to validate and sort buffer list by pool\n");
        goto out;
    }

    status = mlnx_sai_buffer_apply_port_buffer_profile_list(is_ingress, db_port_ind, db_port_buffers, buff_count,
                                                            buffer_profiles);
    if (SAI_ERR(status)) {
        sai_qos_db_sync();
    }

out:
    free(buffer_profiles);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_buffer_port_profile_list_set_unlocked(_In_ const sai_object_id_t        port_id,
                                                        _In_ const sai_attribute_value_t *value,
                                                        _In_ bool                         is_ingress)
{
    sai_status_t     sai_status = SAI_STATUS_SUCCESS;
    sx_port_log_id_t log_port = 0;

    SX_LOG_ENTER();

    sai_status = mlnx_object_to_type(port_id, SAI_OBJECT_TYPE_PORT, &log_port, NULL);
    if (SAI_ERR(sai_status)) {
        return sai_status;
    }
    if (!value) {
        SX_LOG_ERR("NULL value\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    SX_LOG_DBG("is_ingress:%d\n", is_ingress);

    if (value->objlist.count == 0) {
        sai_status = mlnx_set_default_port_buffer_settings(log_port, is_ingress);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to set default port buffer profile data\n");
            return sai_status;
        }
    } else {
        sai_status = mlnx_buffer_port_profile_list_set_unlocked_impl(log_port, value, is_ingress);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to set port buffer profile list\n");
            return sai_status;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_buffer_port_profile_list_set(_In_ const sai_object_id_t         port_id,
                                               _In_ const sai_attribute_value_t * value,
                                               _In_ bool                          is_ingress)
{
    sai_status_t status;

    SX_LOG_ENTER();
    sai_qos_db_write_lock();

    status = mlnx_buffer_port_profile_list_set_unlocked(port_id, value, is_ingress);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set port buffer profile list\n");
        goto out;
    }

out:
    sai_qos_db_unlock();

    SX_LOG_EXIT();
    return status;
}


sai_status_t mlnx_buffer_port_profile_list_get(_In_ const sai_object_id_t      port_id,
                                               _Inout_ sai_attribute_value_t * value,
                                               _In_ bool                       is_ingress)
{
    sai_status_t     sai_status;
    uint32_t         db_port_ind;
    uint32_t         ind;
    sai_object_id_t* buffer_profiles = NULL;
    uint32_t         buff_count;
    uint32_t       * port_buff_profile_refs = NULL;
    uint32_t         ref_arr_count = 0;
    uint32_t         list_cnt = 0;
    sx_port_log_id_t log_port;

    SX_LOG_ENTER();

    sai_status = mlnx_object_to_type(port_id, SAI_OBJECT_TYPE_PORT, &log_port, NULL);
    if (SAI_ERR(sai_status)) {
        return sai_status;
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    if (mlnx_log_port_is_cpu(log_port)) {
        value->objlist.count = 0;
    } else {
        buff_count = max_value(buffer_limits.num_egress_pools, buffer_limits.num_ingress_pools);
        buffer_profiles = calloc(buff_count, sizeof(sai_object_id_t));
        if (NULL == buffer_profiles) {
            sai_status = SAI_STATUS_NO_MEMORY;
            goto out;
        }
        sai_status = mlnx_port_idx_by_log_id(log_port, &db_port_ind);
        if (sai_status != SAI_STATUS_SUCCESS) {
            goto out;
        }

        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_sai_get_port_buffer_index_array(db_port_ind,
                                                                                     (is_ingress) ?
                                                                                     PORT_BUFF_TYPE_INGRESS :
                                                                                     PORT_BUFF_TYPE_EGRESS,
                                                                                     &port_buff_profile_refs))) {
            goto out;
        }
        ref_arr_count = (is_ingress) ? buffer_limits.num_ingress_pools : buffer_limits.num_egress_pools;

        for (ind = 0; ind < ref_arr_count; ind++) {
            if (SENTINEL_BUFFER_DB_ENTRY_INDEX == port_buff_profile_refs[ind]) {
                continue;
            } else {
                if (SAI_STATUS_SUCCESS != (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_BUFFER_PROFILE,
                                                                           port_buff_profile_refs[ind], NULL,
                                                                           &buffer_profiles[list_cnt]))) {
                    goto out;
                }
                list_cnt++;
            }
        }
        sai_status = mlnx_fill_objlist(buffer_profiles, list_cnt, &value->objlist);
    }

out:
    SX_LOG_EXIT();
    cl_plock_release(&g_sai_db_ptr->p_lock);
    if (buffer_profiles) {
        free(buffer_profiles);
    }
    return sai_status;
}

sai_status_t mlnx_sai_get_buffer_pool_stats_ext(_In_ sai_object_id_t      buffer_pool_id,
                                                _In_ uint32_t             number_of_counters,
                                                _In_ const sai_stat_id_t *counter_ids,
                                                _In_ sai_stats_mode_t     mode,
                                                _Out_ uint64_t           *counters)
{
    sai_status_t                       sai_status = SAI_STATUS_SUCCESS;
    sx_status_t                        sx_status = SX_STATUS_SUCCESS;
    sx_cos_pool_occupancy_statistics_t occupancy_stats = {0};
    sx_cos_pool_occupancy_statistics_t occupancy_stats_shp = {0};
    mlnx_sai_buffer_pool_attr_t        sai_pool_attr = {0};
    mlnx_sai_buffer_pool_attr_t        sai_shp_pool_attr = {0};
    char                               key_str[MAX_KEY_STR_LEN] = {0};
    uint32_t                           ii = 0;
    sx_access_cmd_t                    cmd = SX_ACCESS_CMD_NONE;
    bool                               is_locked = false;

    SX_LOG_ENTER();
    pool_key_to_str(buffer_pool_id, key_str);
    SX_LOG_DBG("Get pool stats %s\n", key_str);

    if (!number_of_counters) {
        SX_LOG_ERR("0 number_of_counters array param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }
    if (!counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }
    if (!counters) {
        SX_LOG_ERR("NULL counters array param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_translate_sai_stats_mode_to_sdk(mode, &cmd))) {
        goto bail;
    }

    sai_db_read_lock();
    is_locked = true;
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(buffer_pool_id, &sai_pool_attr))) {
        goto bail;
    }

    if (sai_pool_attr.is_shp_mapped) {
        pool_key_to_str(g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id, key_str);
        SX_LOG_DBG("Get shp pool stats %s\n", key_str);
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_get_sai_pool_data(g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id, &sai_shp_pool_attr))) {
            goto bail;
        }
    }
    sai_db_unlock();
    is_locked = false;

    if (SX_STATUS_SUCCESS != (sx_status = sx_api_cos_pool_statistic_get(gh_sdk, cmd,
                                                                        &sai_pool_attr.sx_pool_id, 1,
                                                                        &occupancy_stats))) {
        SX_LOG_ERR("Failed to get pool stat counters - error:%s.\n", SX_STATUS_MSG(sai_status));
        sai_status = sdk_to_sai(sx_status);
        goto bail;
    }

    if (sai_pool_attr.is_shp_mapped) {
        /* make sdk request in any case when there is association between iPool and SHP */
        if (SX_STATUS_SUCCESS != (sx_status = sx_api_cos_pool_statistic_get(gh_sdk, cmd,
                                                                            &sai_shp_pool_attr.sx_pool_id, 1,
                                                                            &occupancy_stats_shp))) {
            SX_LOG_ERR("Failed to get shp pool stat counters - error:%s.\n", SX_STATUS_MSG(sai_status));
            sai_status = sdk_to_sai(sx_status);
            goto bail;
        }
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES:
            counters[ii] = (uint64_t)mlnx_cells_to_bytes(occupancy_stats.statistics.curr_occupancy);
            break;

        case SAI_BUFFER_POOL_STAT_WATERMARK_BYTES:
            counters[ii] = (uint64_t)mlnx_cells_to_bytes(occupancy_stats.statistics.watermark);
            break;

        case SAI_BUFFER_POOL_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
            counters[ii] = (uint64_t)mlnx_cells_to_bytes(sai_pool_attr.is_shp_mapped ?
                                                         occupancy_stats_shp.statistics.curr_occupancy : 0);
            break;

        case SAI_BUFFER_POOL_STAT_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_DROPPED_BYTES:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_DROPPED_BYTES:
        case SAI_BUFFER_POOL_STAT_RED_WRED_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_RED_WRED_DROPPED_BYTES:
        case SAI_BUFFER_POOL_STAT_WRED_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_WRED_DROPPED_BYTES:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_ECN_MARKED_PACKETS:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_ECN_MARKED_BYTES:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_ECN_MARKED_PACKETS:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_ECN_MARKED_BYTES:
        case SAI_BUFFER_POOL_STAT_RED_WRED_ECN_MARKED_PACKETS:
        case SAI_BUFFER_POOL_STAT_RED_WRED_ECN_MARKED_BYTES:
        case SAI_BUFFER_POOL_STAT_WRED_ECN_MARKED_PACKETS:
        case SAI_BUFFER_POOL_STAT_WRED_ECN_MARKED_BYTES:
        case SAI_BUFFER_POOL_STAT_XOFF_ROOM_WATERMARK_BYTES:
            SX_LOG_NTC("Pool counter %d set item %u not implemented\n", counter_ids[ii], ii);
            sai_status = SAI_STATUS_NOT_IMPLEMENTED;
            goto bail;

        default:
            SX_LOG_ERR("Invalid counter id:%d\n", counter_ids[ii]);
            sai_status = SAI_STATUS_INVALID_PARAMETER;
            goto bail;
        }
    }

bail:
    if (is_locked) {
        sai_db_unlock();
    }
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_get_buffer_pool_stats(_In_ sai_object_id_t       pool_id,
                                            _In_ uint32_t              number_of_counters,
                                            _In_ const sai_stat_id_t * counter_ids,
                                            _Out_ uint64_t           * counters)
{
    return mlnx_sai_get_buffer_pool_stats_ext(pool_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

sai_status_t mlnx_clear_buffer_pool_stats(_In_ sai_object_id_t      pool_id,
                                          _In_ uint32_t             number_of_counters,
                                          _In_ const sai_stat_id_t *counter_ids)
{
    sai_status_t                        sai_status = SAI_STATUS_SUCCESS;
    sx_status_t                         sx_status = SX_STATUS_SUCCESS;
    sx_cos_pool_occupancy_statistics_t *occupancy_stats = NULL;
    mlnx_sai_buffer_pool_attr_t         sai_pool_attr = {0};
    mlnx_sai_buffer_pool_attr_t         shp_sai_pool_attr = {0};
    char                                key_str[MAX_KEY_STR_LEN] = "";
    bool                                is_db_locked = false;
    sx_cos_pool_id_t                   *pool_ids = NULL;
    uint32_t                            pool_ids_count = 1;

    SX_LOG_ENTER();
    pool_key_to_str(pool_id, key_str);
    SX_LOG_DBG("Clear pool stats %s\n", key_str);
    if (!number_of_counters) {
        SX_LOG_ERR("0 number_of_counters array param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }
    if (!counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto bail;
    }

    sai_db_read_lock();
    is_db_locked = true;
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(pool_id, &sai_pool_attr))) {
        goto bail;
    }

    if (sai_pool_attr.is_shp_mapped) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_get_sai_pool_data(g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id, &shp_sai_pool_attr))) {
            goto bail;
        }
        pool_ids_count++;
        pool_key_to_str(g_sai_buffer_db_ptr->shp_ipool_map->shp_pool_id, key_str);
        SX_LOG_DBG("Clear shp pool stats %s\n", key_str);
    }
    sai_db_unlock();
    is_db_locked = false;

    if (NULL == (pool_ids = calloc(pool_ids_count, sizeof(*pool_ids)))) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto bail;
    }
    if (NULL == (occupancy_stats = calloc(pool_ids_count, sizeof(*occupancy_stats)))) {
        sai_status = SAI_STATUS_NO_MEMORY;
        goto bail;
    }

    pool_ids[0] = sai_pool_attr.sx_pool_id;

    if (pool_ids_count > 1) {
        pool_ids[1] = shp_sai_pool_attr.sx_pool_id;
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_api_cos_pool_statistic_get(gh_sdk, SX_ACCESS_CMD_READ_CLEAR,
                                                                        pool_ids, pool_ids_count,
                                                                        occupancy_stats))) {
        SX_LOG_ERR("Failed to get pool stat counters - error:%s.\n", SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto bail;
    }

bail:
    if (is_db_locked) {
        sai_db_unlock();
    }
    safe_free(pool_ids);
    safe_free(occupancy_stats);
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_fill_pg_counter_value(sai_stat_id_t                  counter_id,
                                            uint64_t                      *counter,
                                            uint32_t                       db_port_index,
                                            uint32_t                       pg_ind,
                                            const sx_port_cntr_buff_t     *pg_cnts,
                                            const sx_cos_buff_statistic_t *buff_cnts,
                                            const sx_cos_buff_statistic_t *headroom_cnts)
{
    assert(counter);
    assert(pg_cnts || buff_cnts);

    sai_status_t                        status;
    uint32_t                            buff_ind;
    uint32_t                            stat_tmp;
    uint32_t                           *port_pg_profile_refs = NULL;
    mlnx_sai_db_buffer_profile_entry_t *buff_db_entry = NULL;

    switch (counter_id) {
    case SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS:
        assert(pg_cnts);
        *counter = pg_cnts->rx_frames;
        break;

    case SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES:
        assert(pg_cnts);
        *counter = pg_cnts->rx_octet;
        break;

    case SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS:
        assert(pg_cnts);
        /* On SPC, shared buffer discards is always 0 */
        *counter = pg_cnts->rx_buffer_discard + pg_cnts->rx_shared_buffer_discard;
        break;

    case SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES:
    case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES:
        assert(buff_cnts);
        *counter = mlnx_cells_to_bytes(buff_cnts->curr_occupancy);
        break;

    case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES:
    case SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES:
        assert(buff_cnts);
        *counter = mlnx_cells_to_bytes(buff_cnts->watermark);
        break;

    case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
    /** fall through */
    case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES:
        assert(headroom_cnts);
        *counter = 0;

        cl_plock_acquire(&g_sai_db_ptr->p_lock);
        if (SAI_STATUS_SUCCESS !=
            (status =
                 mlnx_sai_get_port_buffer_index_array(db_port_index, PORT_BUFF_TYPE_PG, &port_pg_profile_refs))) {
            cl_plock_release(&g_sai_db_ptr->p_lock);
            SX_LOG_EXIT();
            return status;
        }
        buff_ind = port_pg_profile_refs[pg_ind];
        stat_tmp =
            (counter_id == SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES) ?
            mlnx_cells_to_bytes(headroom_cnts->curr_occupancy) :
            mlnx_cells_to_bytes(headroom_cnts->watermark);

        if (SENTINEL_BUFFER_DB_ENTRY_INDEX != buff_ind) {
            buff_db_entry = &g_sai_buffer_db_ptr->buffer_profiles[buff_ind];
            /* only relevant to lossless when either xon/xoff isn't 0. lossy is 0 */
            if ((buff_db_entry->xon != 0) || (buff_db_entry->xoff != 0)) {
                if ((buff_db_entry->xon != 0) && (buff_db_entry->xoff != 0) &&
                    (g_sai_buffer_db_ptr->shp_ipool_map->is_shp_created) &&
                    (g_sai_buffer_db_ptr->shp_ipool_map->sai_pool_id == buff_db_entry->sai_pool)) {
                    /* maximum consumption is returned only the xoff part */
                    /* when shared headroom is enabled and pg buffer is lossless then pg.xoff == pg.xon */
                    if (stat_tmp > buff_db_entry->xon) {
                        *counter = stat_tmp - buff_db_entry->xon;
                    }
                    /* watermark is from xoff threshold. xoff threshold is available bytes in reserved buffer */
                } else if (stat_tmp > buff_db_entry->reserved_size - buff_db_entry->xoff) {
                    *counter = stat_tmp + buff_db_entry->xoff - buff_db_entry->reserved_size;
                }
            }
        }
        cl_plock_release(&g_sai_db_ptr->p_lock);
        break;

    default:
        SX_LOG_ERR("Invalid PG stat counter id:%d\n", counter_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_get_ingress_priority_group_stats_ext(_In_ sai_object_id_t      ingress_priority_group_id,
                                                           _In_ uint32_t             number_of_counters,
                                                           _In_ const sai_stat_id_t *counter_ids,
                                                           _In_ sai_stats_mode_t     mode,
                                                           _Out_ uint64_t           *counters)
{
    sai_status_t                     sai_status;
    uint32_t                         db_port_index, pg_ind;
    sx_port_statistic_usage_params_t stats_usages[2] = {0};
    sx_port_occupancy_statistics_t   stats[2] = {0};
    uint32_t                         usage_cnt = 1;
    uint32_t                         ii;
    char                             key_str[MAX_KEY_STR_LEN];
    sx_port_cntr_buff_t              pg_cnts = { 0 };
    bool                             pg_cnts_needed = false, occupancy_stats_needed = false,
                                     headroom_occupancy_stats_needed = false;
    sx_access_cmd_t cmd;

    SX_LOG_ENTER();
    pg_key_to_str(ingress_priority_group_id, key_str);
    SX_LOG_DBG("Get PG stats %s\n", key_str);
    if (0 == number_of_counters) {
        SX_LOG_ERR("0 number_of_counters array param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (NULL == counters) {
        SX_LOG_ERR("NULL counters array param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_translate_sai_stats_mode_to_sdk(mode, &cmd))) {
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = get_pg_data(ingress_priority_group_id, &db_port_index, &pg_ind))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS:
            pg_cnts_needed = true;
            break;

        case SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES:
            occupancy_stats_needed = true;
            break;

        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES:
            headroom_occupancy_stats_needed = true;
            break;

        default:
            break;
        }
    }

    if (pg_cnts_needed) {
        if (SX_STATUS_SUCCESS !=
            (sai_status =
                 sx_api_port_counter_buff_get(gh_sdk, cmd,
                                              g_sai_db_ptr->ports_db[db_port_index].logical,
                                              pg_ind, &pg_cnts))) {
            SX_LOG_ERR("Failed to get port pg counters - %s.\n", SX_STATUS_MSG(sai_status));
            return sdk_to_sai(sai_status);
        }
    }

    memset(&stats_usages, 0, sizeof(stats_usages));
    stats_usages[0].port_cnt = 1;
    stats_usages[0].log_port_list_p = &g_sai_db_ptr->ports_db[db_port_index].logical;
    stats_usages[0].sx_port_params.port_params_type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
    stats_usages[0].sx_port_params.port_params_cnt = 1;
    stats_usages[0].sx_port_params.port_param.port_pg_list_p = &pg_ind;

    stats_usages[1].port_cnt = 1;
    stats_usages[1].log_port_list_p = &g_sai_db_ptr->ports_db[db_port_index].logical;
    stats_usages[1].sx_port_params.port_params_type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_HEADROOM_ATTR_E;
    stats_usages[1].sx_port_params.port_params_cnt = 1;
    stats_usages[1].sx_port_params.port_param.port_pg_list_p = &pg_ind;

    if (occupancy_stats_needed && headroom_occupancy_stats_needed) {
        usage_cnt = 2;
        sai_status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, cmd, stats_usages, 2,
                                                             stats, &usage_cnt);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to get PG stat counters - %s.\n", SX_STATUS_MSG(sai_status));
            return sdk_to_sai(sai_status);
        }
    } else {
        if (occupancy_stats_needed) {
            sai_status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, cmd, &stats_usages[0], 1,
                                                                 &stats[0], &usage_cnt);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Failed to get PG stat counters - %s.\n", SX_STATUS_MSG(sai_status));
                return sdk_to_sai(sai_status);
            }
        }
        if (headroom_occupancy_stats_needed) {
            sai_status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, cmd, &stats_usages[1], 1,
                                                                 &stats[1], &usage_cnt);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Failed to get PG headroom stat counters - %s.\n", SX_STATUS_MSG(sai_status));
                return sdk_to_sai(sai_status);
            }
        }
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        sai_status = mlnx_sai_fill_pg_counter_value(
            counter_ids[ii],
            &counters[ii],
            db_port_index,
            pg_ind,
            &pg_cnts,
            &stats[0].statistics,
            &stats[1].statistics);
        if (SAI_ERR(sai_status)) {
            SX_LOG_EXIT();
            return sai_status;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_get_ingress_priority_group_stats(_In_ sai_object_id_t       ingress_pg_id,
                                                       _In_ uint32_t              number_of_counters,
                                                       _In_ const sai_stat_id_t * counter_ids,
                                                       _Out_ uint64_t           * counters)
{
    return mlnx_sai_get_ingress_priority_group_stats_ext(ingress_pg_id,
                                                         number_of_counters,
                                                         counter_ids,
                                                         SAI_STATS_MODE_READ,
                                                         counters);
}

static sai_status_t mlnx_sai_clear_ingress_priority_group_stats(_In_ sai_object_id_t      ingress_pg_id,
                                                                _In_ uint32_t             number_of_counters,
                                                                _In_ const sai_stat_id_t *counter_ids)
{
    sai_status_t                     sai_status;
    sx_port_statistic_usage_params_t stats_usage;
    char                             key_str[MAX_KEY_STR_LEN];
    uint32_t                         db_port_index, pg_ind;
    sx_port_occupancy_statistics_t   occupancy_stats;
    uint32_t                         usage_cnt = 1;
    sx_port_cntr_buff_t              pg_cnts;
    bool                             pg_cnts_needed = false, occupancy_stats_needed = false,
                                     headroom_occupancy_stats_needed = false;
    uint32_t ii;

    SX_LOG_ENTER();
    pg_key_to_str(ingress_pg_id, key_str);
    SX_LOG_DBG("Clear PG stats %s\n", key_str);

    if (SAI_STATUS_SUCCESS != (sai_status = get_pg_data(ingress_pg_id, &db_port_index, &pg_ind))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS:
            pg_cnts_needed = true;
            break;

        case SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES:
            occupancy_stats_needed = true;
            break;

        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
            headroom_occupancy_stats_needed = true;
            break;

        default:
            break;
        }
    }

    if (pg_cnts_needed) {
        if (SX_STATUS_SUCCESS !=
            (sai_status =
                 sx_api_port_counter_buff_get(gh_sdk, SX_ACCESS_CMD_READ_CLEAR,
                                              g_sai_db_ptr->ports_db[db_port_index].logical,
                                              pg_ind, &pg_cnts))) {
            SX_LOG_ERR("Failed to get port pg counters - %s.\n", SX_STATUS_MSG(sai_status));
            return sdk_to_sai(sai_status);
        }
    }

    if (occupancy_stats_needed) {
        memset(&stats_usage, 0, sizeof(stats_usage));
        stats_usage.port_cnt = 1;
        stats_usage.log_port_list_p = &g_sai_db_ptr->ports_db[db_port_index].logical;
        stats_usage.sx_port_params.port_params_type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
        stats_usage.sx_port_params.port_params_cnt = 1;
        stats_usage.sx_port_params.port_param.port_pg_list_p = &pg_ind;

        if (SX_STATUS_SUCCESS !=
            (sai_status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, SX_ACCESS_CMD_READ_CLEAR, &stats_usage, 1,
                                                                  &occupancy_stats, &usage_cnt))) {
            SX_LOG_ERR("Failed to clear PG stat counters - %s.\n", SX_STATUS_MSG(sai_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sai_status);
        }
    }

    if (headroom_occupancy_stats_needed) {
        memset(&stats_usage, 0, sizeof(stats_usage));
        stats_usage.port_cnt = 1;
        stats_usage.log_port_list_p = &g_sai_db_ptr->ports_db[db_port_index].logical;
        stats_usage.sx_port_params.port_params_type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_HEADROOM_ATTR_E;
        stats_usage.sx_port_params.port_params_cnt = 1;
        stats_usage.sx_port_params.port_param.port_pg_list_p = &pg_ind;

        if (SX_STATUS_SUCCESS !=
            (sai_status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, SX_ACCESS_CMD_READ_CLEAR, &stats_usage, 1,
                                                                  &occupancy_stats, &usage_cnt))) {
            SX_LOG_ERR("Failed to clear PG headroom stat counters - %s.\n", SX_STATUS_MSG(sai_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sai_status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_bulk_ingress_priority_group_stats_get(_In_ sai_object_id_t         switch_id,
                                                            _In_ uint32_t                object_count,
                                                            _In_ const sai_object_key_t *object_key,
                                                            _In_ uint32_t                number_of_counters,
                                                            _In_ const sai_stat_id_t    *counter_ids,
                                                            _In_ sx_access_cmd_t         cmd,
                                                            _Inout_ sai_status_t        *object_statuses,
                                                            _Out_ uint64_t              *counters)
{
    sai_status_t              status = SAI_STATUS_SUCCESS;
    sai_status_t              single_status;
    bool                      any_error = false;
    bool                      occupancy_stats_needed = false, headroom_stats_needed = false;
    sai_bulk_counter_stats    occupancy_stats[MAX_PORTS_DB] = {0};
    sai_bulk_counter_stats    headroom_stats[MAX_PORTS_DB] = {0};
    uint32_t                  stats_count = 0, stats_index = 0;
    sx_status_t               sx_status = -1;
    sx_bulk_cntr_buffer_key_t occupancy_buffer_key = {0};
    sx_bulk_cntr_buffer_key_t headroom_buffer_key = {0};
    sx_bulk_cntr_buffer_t     occupancy_buff = {0};
    sx_bulk_cntr_buffer_t     headroom_buff = {0};
    sx_bulk_cntr_read_key_t   occupancy_read_key = {0};
    sx_bulk_cntr_read_key_t   headroom_read_key = {0};
    sx_port_log_id_t          port_list[MAX_PORTS_DB] = {0};
    uint32_t                  port_count = 0;
    int                       port_index = 0;
    mlnx_port_config_t       *port;
    uint32_t                  counter_index;
    uint32_t                 *port_index_per_pgs = NULL;           /* port index in port_list for each input object */
    uint32_t                 *db_port_index_per_pgs = NULL;           /* db port index for each input object */
    uint32_t                 *pgs = NULL;           /* pg index for each input object */

    SX_LOG_ENTER();

    for (uint32_t ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES:
            occupancy_stats_needed = true;
            break;

        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES:
            headroom_stats_needed = true;
            break;

        default:
            SX_LOG_INF("Not all pg statistic IDs are implemented in bulk read: %d\n", counter_ids[ii]);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

    memset(object_statuses, 0, sizeof(sai_status_t) * object_count);
    port_index_per_pgs = calloc(object_count, sizeof(uint32_t));
    if (NULL == port_index_per_pgs) {
        SX_LOG_ERR("Failed to allocate memory for port_index_per_pgs\n");
        return SAI_STATUS_NO_MEMORY;
    }

    db_port_index_per_pgs = calloc(object_count, sizeof(uint32_t));
    if (NULL == db_port_index_per_pgs) {
        SX_LOG_ERR("Failed to allocate memory for db_port_index_per_pgs\n");
        status = SAI_STATUS_NO_MEMORY;
        goto free_arrays;
    }

    pgs = calloc(object_count, sizeof(uint32_t));
    if (NULL == pgs) {
        SX_LOG_ERR("Failed to allocate memory for pgs\n");
        status = SAI_STATUS_NO_MEMORY;
        goto free_arrays;
    }

    for (uint32_t ii = 0; ii < object_count; ii++) {
        if (SAI_STATUS_SUCCESS !=
            (status = get_pg_data(object_key[ii].key.object_id, &db_port_index_per_pgs[ii], &pgs[ii]))) {
            object_statuses[ii] = SAI_STATUS_INVALID_PARAMETER;
            any_error = true;
            continue;
        }

        port = mlnx_port_by_idx(db_port_index_per_pgs[ii]);
        for (port_index = port_count - 1; port_index >= 0; port_index--) {
            if (port_list[port_index] == port->logical) {
                break;
            }
        }

        if (port_index < 0) {
            port_index = port_count++;
            port_list[port_index] = port->logical;
            headroom_buffer_key.key.headroom_key.port_list[port_index] = port->logical;
        }

        port_index_per_pgs[ii] = port_index;
    }

    if (port_count == 0) {
        SX_LOG_ERR("No valid pg found\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto free_arrays;
    }

    if (occupancy_stats_needed) {
        occupancy_buffer_key.type = SX_BULK_CNTR_KEY_TYPE_SHARED_BUFFER_E;
        occupancy_buffer_key.key.shared_buffer_key.type = SX_BULK_CNTR_SHARED_BUFFER_CURRENT_E;
        status = mlnx_prepare_bulk_counter_read(MLNX_BULK_TYPE_SHARED_BUFFER,
                                                SX_ACCESS_CMD_READ,
                                                &occupancy_buffer_key,
                                                &occupancy_buff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to prepare bulk counter for pg occupancy stats: %d.\n", status);
            any_error = true;
            goto free_occupancy_buff;
        }
    }

    if (headroom_stats_needed) {
        headroom_buffer_key.type = SX_BULK_CNTR_KEY_TYPE_HEADROOM_E;
        headroom_buffer_key.key.headroom_key.port_list_cnt = port_count;
        status = mlnx_prepare_bulk_counter_read(MLNX_BULK_TYPE_HEADROOM,
                                                SX_ACCESS_CMD_READ,
                                                &headroom_buffer_key,
                                                &headroom_buff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to prepare bulk counter for pg headroom stats: %d.\n", status);
            any_error = true;
            goto free_headroom_buff;
        }
    }


    occupancy_read_key.type = SX_BULK_CNTR_KEY_TYPE_SHARED_BUFFER_E;
    occupancy_read_key.key.shared_buffer_key.type = SX_BULK_CNTR_SHARED_BUFFER_PORT_ATTR_E;
    headroom_read_key.type = SX_BULK_CNTR_KEY_TYPE_HEADROOM_E;

    for (uint32_t ii = 0; ii < object_count; ii++) {
        stats_index = port_index_per_pgs[ii];
        if (stats_index >= stats_count) {
            ++stats_count;
            if (occupancy_stats_needed) {
                occupancy_stats[stats_index].port_num = port_list[stats_index];
                occupancy_stats[stats_index].status = SAI_STATUS_SUCCESS;
                occupancy_read_key.key.shared_buffer_key.attr.log_port = occupancy_stats[stats_index].port_num;
                sx_status = sx_api_bulk_counter_transaction_get(gh_sdk,
                                                                &occupancy_read_key,
                                                                &occupancy_buff,
                                                                &(occupancy_stats[stats_index].data));
                if (SX_ERR(sx_status)) {
                    SX_LOG_ERR("Failed to bulk read pg occupancy counters: %s.\n", SX_STATUS_MSG(sx_status));
                    occupancy_stats[stats_index].status = sdk_to_sai(sx_status);
                    any_error = true;
                }
            }

            if (headroom_stats_needed) {
                headroom_stats[stats_index].port_num = port_list[stats_index];
                headroom_stats[stats_index].status = SAI_STATUS_SUCCESS;
                headroom_read_key.key.headroom_key.log_port = headroom_stats[stats_index].port_num;
                sx_status = sx_api_bulk_counter_transaction_get(gh_sdk,
                                                                &headroom_read_key,
                                                                &headroom_buff,
                                                                &(headroom_stats[stats_index].data));
                if (SX_ERR(sx_status)) {
                    SX_LOG_ERR("Failed to bulk read pg headroom counters: %s.\n", SX_STATUS_MSG(sx_status));
                    headroom_stats[stats_index].status = sdk_to_sai(sx_status);
                    any_error = true;
                }
            }
        }

        if (object_statuses[ii] != SAI_STATUS_SUCCESS) {
            continue;
        }

        if (occupancy_stats_needed && (occupancy_stats[stats_index].status != SAI_STATUS_SUCCESS)) {
            object_statuses[ii] = occupancy_stats[stats_index].status;
            continue;
        }

        if (headroom_stats_needed && (headroom_stats[stats_index].status != SAI_STATUS_SUCCESS)) {
            object_statuses[ii] = headroom_stats[stats_index].status;
            continue;
        }

        single_status = SAI_STATUS_SUCCESS;
        for (uint32_t kk = 0; kk < number_of_counters; kk++) {
            counter_index = ii * number_of_counters + kk;
            single_status = mlnx_sai_fill_pg_counter_value(
                counter_ids[kk],
                &counters[counter_index],
                db_port_index_per_pgs[ii],
                pgs[ii],
                NULL,
                &occupancy_stats[stats_index].data.data.shared_buffer_counters.port_p->port_pg[pgs[ii]],
                &headroom_stats[stats_index].data.data.headroom_counters.headroom_p->port_pg[pgs[ii]].statistics);

            if (single_status != SAI_STATUS_SUCCESS) {
                any_error = true;
                break;
            }
        }
        object_statuses[ii] = single_status;
    }

free_headroom_buff:
    if (headroom_stats_needed) {
        status = mlnx_deallocate_sx_bulk_buffer(&headroom_buff);
        if (SAI_ERR(status)) {
            any_error = true;
            SX_LOG_ERR("Failed to deallocate SDK headroom buffer: %d.\n", status);
        }
    }

free_occupancy_buff:
    if (occupancy_stats_needed) {
        status = mlnx_deallocate_sx_bulk_buffer(&occupancy_buff);
        if (SAI_ERR(status)) {
            any_error = true;
            SX_LOG_ERR("Failed to deallocate SDK occupancy buffer: %d.\n", status);
        }
    }

free_arrays:
    if (NULL != pgs) {
        free(pgs);
    }
    if (NULL != db_port_index_per_pgs) {
        free(db_port_index_per_pgs);
    }
    if (NULL != port_index_per_pgs) {
        free(port_index_per_pgs);
    }

    SX_LOG_EXIT();
    if (SAI_ERR(status)) {
        return status;
    }

    if (any_error) {
        return SAI_STATUS_FAILURE;
    }

    if (cmd == SX_ACCESS_CMD_READ_CLEAR) {
        return mlnx_sai_bulk_ingress_priority_group_stats_clear(
            switch_id,
            object_count,
            object_key,
            number_of_counters,
            counter_ids,
            cmd,
            object_statuses);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_bulk_ingress_priority_group_stats_clear(_In_ sai_object_id_t         switch_id,
                                                              _In_ uint32_t                object_count,
                                                              _In_ const sai_object_key_t *object_key,
                                                              _In_ uint32_t                number_of_counters,
                                                              _In_ const sai_stat_id_t    *counter_ids,
                                                              _In_ sx_access_cmd_t         cmd,
                                                              _Inout_ sai_status_t        *object_statuses)
{
    sai_status_t                     status;
    sx_status_t                      sx_status = -1;
    sx_port_statistic_usage_params_t occupancy_stats_usages[MAX_PORTS_DB] = {0};
    sx_port_statistic_usage_params_t headroom_stats_usages[MAX_PORTS_DB] = {0};
    sx_port_log_id_t                 port_num;
    sx_port_log_id_t                 log_port_list[MAX_PORTS_DB] = {0};
    mlnx_port_config_t              *port;
    uint32_t                         db_port_index, pg_ind;
    uint32_t                         port_count = 0;
    int                              port_index = 0;
    uint32_t                         usage_cnt = object_count;
    bool                             any_error = false;
    bool                             occupancy_stats_needed = false, headroom_occupancy_stats_needed = false;
    sx_port_occupancy_statistics_t  *stats = NULL;
    uint32_t                         port_to_pgs[MAX_PORTS_DB][8] = {0};

    SX_LOG_ENTER();

    for (uint32_t ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES:
            occupancy_stats_needed = true;
            break;

        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
            headroom_occupancy_stats_needed = true;
            break;

        default:
            SX_LOG_INF("Not all pg statistic IDs are implemented for bulk clear: %u\n", counter_ids[ii]);
            SX_LOG_EXIT();
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

    stats = calloc(object_count, sizeof(sx_port_occupancy_statistics_t));
    if (NULL == stats) {
        SX_LOG_ERR("Failed to allocate memory for stats\n");
        return SAI_STATUS_NO_MEMORY;
    }
    /* SDK bulk clear will clear all PG/queue/buffer statistic. So, we have to use non bulk API here. */
    for (uint32_t ii = 0; ii < object_count; ii++) {
        if (SAI_STATUS_SUCCESS != (status = get_pg_data(object_key[ii].key.object_id, &db_port_index, &pg_ind))) {
            object_statuses[ii] = SAI_STATUS_INVALID_PARAMETER;
            any_error = true;
            continue;
        }

        port = mlnx_port_by_idx(db_port_index);
        port_num = port->logical;

        for (port_index = port_count - 1; port_index >= 0; port_index--) {
            if (log_port_list[port_index] == port_num) {
                break;
            }
        }

        /* New port */
        if (port_index < 0) {
            port_index = port_count++;
            log_port_list[port_index] = port_num;
            if (occupancy_stats_needed) {
                occupancy_stats_usages[port_index].port_cnt = 1;
                occupancy_stats_usages[port_index].log_port_list_p = &log_port_list[port_index];
                occupancy_stats_usages[port_index].sx_port_params.port_params_type =
                    SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
                occupancy_stats_usages[port_index].sx_port_params.port_params_cnt = 0;
                occupancy_stats_usages[port_index].sx_port_params.port_param.port_pg_list_p =
                    &(port_to_pgs[port_index][0]);
            }

            if (headroom_occupancy_stats_needed) {
                headroom_stats_usages[port_index].port_cnt = 1;
                headroom_stats_usages[port_index].log_port_list_p = &log_port_list[port_index];
                headroom_stats_usages[port_index].sx_port_params.port_params_type =
                    SX_COS_INGRESS_PORT_PRIORITY_GROUP_HEADROOM_ATTR_E;
                headroom_stats_usages[port_index].sx_port_params.port_params_cnt = 0;
                headroom_stats_usages[port_index].sx_port_params.port_param.port_pg_list_p =
                    &(port_to_pgs[port_index][0]);
            }
        }

        if (occupancy_stats_needed) {
            occupancy_stats_usages[port_index].sx_port_params.port_param.port_pg_list_p[occupancy_stats_usages[
                                                                                            port_index].sx_port_params.
                                                                                        port_params_cnt++] = pg_ind;
        }

        if (headroom_occupancy_stats_needed) {
            headroom_stats_usages[port_index].sx_port_params.port_param.port_pg_list_p[headroom_stats_usages[port_index
                                                                                       ].sx_port_params.port_params_cnt
                                                                                       ++] = pg_ind;
        }
    }

    if (occupancy_stats_needed) {
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, cmd, &occupancy_stats_usages[0], port_count,
                                                                 stats, &usage_cnt))) {
            free(stats);
            SX_LOG_ERR("Failed to bulk clear pg occupancy statistics - %s.\n", SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }
    }

    if (headroom_occupancy_stats_needed) {
        usage_cnt = object_count;
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, cmd, &headroom_stats_usages[0], port_count,
                                                                 stats, &usage_cnt))) {
            free(stats);
            SX_LOG_ERR("Failed to bulk clear pg headroom occupancy statistics - %s.\n", SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }
    }

    free(stats);
    SX_LOG_EXIT();
    return any_error ? SAI_STATUS_FAILURE : SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_buffer_apply(_In_ sai_object_id_t sai_buffer, _In_ sai_object_id_t to_obj_id)
{
    sai_status_t                       sai_status;
    uint32_t                           db_buffer_profile_index;
    uint32_t                           qos_db_port_index;
    sx_port_log_id_t                   logical_port_id;
    uint8_t                            qos_ext_data[EXTENDED_DATA_SIZE];
    mlnx_sai_buffer_pool_attr_t        sai_pool_attr;
    mlnx_sai_db_buffer_profile_entry_t buff_db_entry;
    sai_object_id_t                    default_egress_pool;
    mlnx_qos_queue_config_t           *queue_cfg = NULL;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(to_obj_id, SAI_OBJECT_TYPE_QUEUE, &logical_port_id, qos_ext_data)) {
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_sai_pool_id(g_sai_buffer_db_ptr->buffer_pool_ids.default_egress_pool_id,
                                     &default_egress_pool))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_NULL_OBJECT_ID != sai_buffer) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_get_sai_buffer_profile_data(sai_buffer, &db_buffer_profile_index, &sai_pool_attr))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        buff_db_entry = g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index];
    } else {
        memset(&buff_db_entry, 0, sizeof(buff_db_entry));
        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_get_sai_pool_data(default_egress_pool, &sai_pool_attr))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        buff_db_entry.is_valid = true;
        buff_db_entry.sai_pool = default_egress_pool;
    }
    if (buffer_limits.num_port_queue_buff <= qos_ext_data[0]) {
        SX_LOG_ERR("Queue object:0x%" PRIx64 ", refers to invalid queue index:%d\n", to_obj_id, qos_ext_data[0]);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_NULL_OBJECT_ID != sai_buffer) {
        if (SAI_BUFFER_POOL_TYPE_EGRESS != sai_pool_attr.pool_type) {
            SX_LOG_ERR(
                "Buffer profile:0x%" PRIx64 " refers to INGRESS pool:0x%" PRIx64 ". Cannot be set on queue:0x%" PRIx64 "\n",
                sai_buffer,
                g_sai_buffer_db_ptr->buffer_profiles[db_buffer_profile_index].sai_pool,
                to_obj_id);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_port_idx_by_log_id(logical_port_id, &qos_db_port_index))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_DBG("Setting ports_db[%d].queue_list[%d].buffer_id=0x%" PRIx64 "\n",
               qos_db_port_index,
               qos_ext_data[0],
               sai_buffer);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_queue_cfg_lookup(g_sai_db_ptr->ports_db[qos_db_port_index].logical, qos_ext_data[0],
                                            &queue_cfg))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_sai_buffer_apply_buffer_to_queue(qos_db_port_index, qos_ext_data[0], buff_db_entry))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    queue_cfg->buffer_id = sai_buffer;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_buffer_configure_reserved_buffers(_In_ sx_port_log_id_t            logical_port,
                                                               _Out_ sx_cos_port_buffer_attr_t* sx_port_reserved_buff_attr_arr,
                                                               _In_ uint32_t                    count)
{
    sx_status_t sx_status;

    SX_LOG_ENTER();

    sx_status = sx_api_cos_port_buff_type_set(gh_sdk, SX_ACCESS_CMD_SET, logical_port,
                                              sx_port_reserved_buff_attr_arr, count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(
            "Failed to configure reserved buffers. logical port:%x, number of items:%d sx_status:%d, message %s\n",
            logical_port,
            count,
            sx_status,
            SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }
    SX_LOG_DBG(
        "Configured bindings for sx reserved buffers for logical port:%x, number of items:%d, sx_status:%d, message %s\n",
        logical_port,
        count,
        sx_status,
        SX_STATUS_MSG(sx_status));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_buffer_configure_shared_buffers(_In_ sx_port_log_id_t                   logical_port,
                                                             _Out_ sx_cos_port_shared_buffer_attr_t* sx_port_shared_buff_attr_arr,
                                                             _In_ uint32_t                           count)
{
    sx_status_t sx_status;

    SX_LOG_ENTER();
    sx_status = sx_api_cos_port_shared_buff_type_set(gh_sdk, SX_ACCESS_CMD_SET, logical_port,
                                                     sx_port_shared_buff_attr_arr, count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(
            "Failed to configure shared buffers. logical port:%x, number of items:%d sx_status:%d, message %s\n",
            logical_port,
            count,
            sx_status,
            SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }
    SX_LOG_DBG(
        "Configured bindings for sx shared buffers for logical port:%x, number of items:%d, sx_status:%d, message %s\n",
        logical_port,
        count,
        sx_status,
        SX_STATUS_MSG(sx_status));
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_is_buffer_in_use(_In_ sai_object_id_t buffer_profile_id)
{
    sai_status_t                  sai_status;
    uint32_t                      port_ind;
    mlnx_port_config_t           *port;
    mlnx_affect_port_buff_items_t affected_items;

    SX_LOG_ENTER();
    if (!alloc_affected_items(&affected_items)) {
        SX_LOG_EXIT();
        return SAI_STATUS_NO_MEMORY;
    }
    mlnx_port_phy_foreach(port, port_ind) {
        sai_status = mlnx_sai_collect_buffer_refs(buffer_profile_id, port_ind, &affected_items);
        if (SAI_STATUS_ITEM_NOT_FOUND == sai_status) {
            continue;
        }
        if (SAI_STATUS_SUCCESS != sai_status) {
            SX_LOG_ERR("Failed to obtain references to buffer profile:0x%" PRIx64 "\n", buffer_profile_id);
            free_affected_items(&affected_items);
            SX_LOG_EXIT();
            return sai_status;
        }
        SX_LOG_ERR("Buffer profile is in use by port[%d].logical==%d\n", port_ind, port->logical);
        log_buffer_profile_refs(&affected_items);
        free_affected_items(&affected_items);
        SX_LOG_EXIT();
        return SAI_STATUS_OBJECT_IN_USE;
    }
    free_affected_items(&affected_items);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_buffer_convert_alpha_sai_to_sx(_In_ sai_int8_t sai_alpha, _Out_ sx_cos_port_buff_alpha_e   *sx_alpha)
{
    SX_LOG_ENTER();
    if (NULL == sx_alpha) {
        SX_LOG_ERR("NULL sx_alpha\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (sai_alpha <= SAI_BUFFER_ALPHA_0) {
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_0_E;
        SX_LOG_DBG("input:%d, output:%d\n", sai_alpha, *sx_alpha);
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }
    if (sai_alpha >= SAI_BUFFER_ALPHA_INFINITY) {
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_INFINITY_E;
        SX_LOG_DBG("input:%d, output:%d\n", sai_alpha, *sx_alpha);
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    switch (sai_alpha) {
    case SAI_BUFFER_ALPHA_1_128:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_128_E;
        break;

    case SAI_BUFFER_ALPHA_1_64:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_64_E;
        break;

    case SAI_BUFFER_ALPHA_1_32:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_32_E;
        break;

    case SAI_BUFFER_ALPHA_1_16:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_16_E;
        break;

    case SAI_BUFFER_ALPHA_1_8:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_8_E;
        break;

    case SAI_BUFFER_ALPHA_1_4:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_4_E;
        break;

    case SAI_BUFFER_ALPHA_1_2:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_2_E;
        break;

    case SAI_BUFFER_ALPHA_1:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_1_E;
        break;

    case SAI_BUFFER_ALPHA_2:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_2_E;
        break;

    case SAI_BUFFER_ALPHA_4:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_4_E;
        break;

    case SAI_BUFFER_ALPHA_8:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_8_E;
        break;

    case SAI_BUFFER_ALPHA_16:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_16_E;
        break;

    case SAI_BUFFER_ALPHA_32:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_32_E;
        break;

    case SAI_BUFFER_ALPHA_64:
        *sx_alpha = SX_COS_PORT_BUFF_ALPHA_64_E;
        break;

    default:
        SX_LOG_ERR("Invalid sai alpha value:%d\n", sai_alpha);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    SX_LOG_DBG("input:%d, output:%d\n", sai_alpha, *sx_alpha);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_buffer_configure_buffers(_In_ const mlnx_port_config_t         *port,
                                                      _In_ sx_cos_port_buffer_attr_t        *buff_reserved_attr_arr,
                                                      _In_ uint32_t                          buff_reserved_attr_count,
                                                      _In_ sx_cos_port_shared_buffer_attr_t *buff_shared_attr_arr,
                                                      _In_ uint32_t                          buff_shared_attr_count)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if (buff_reserved_attr_count) {
        sai_status = mlnx_sai_buffer_configure_reserved_buffers(port->logical,
                                                                buff_reserved_attr_arr,
                                                                buff_reserved_attr_count);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to configure buffer reserved attributes \n");
            goto out;
        }
    }

    if (buff_shared_attr_count) {
        sai_status = mlnx_sai_buffer_configure_shared_buffers(port->logical,
                                                              buff_shared_attr_arr,
                                                              buff_shared_attr_count);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to configure buffer shared attributes \n");
            goto out;
        }
    }
out:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_buffer_pg0_update_is_required(_In_ const mlnx_port_config_t *port,
                                                           _Inout_ bool                  *is_update)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     db_port_index = 0;
    bool         pool_creation_triggered = false;
    uint32_t    *port_pg_profile_refs = NULL;

    SX_LOG_ENTER();

    if (!port || !is_update) {
        SX_LOG_ERR("NULL param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    *is_update = false;

    pool_creation_triggered = mlnx_sai_buffer_get_pool_create_triggered_flag();
    if (!pool_creation_triggered) {
        goto out;
    }

    /* check no PG0 buffer is configured on port */
    sai_status = mlnx_port_idx_by_log_id(port->logical, &db_port_index);
    if (SAI_ERR(sai_status)) {
        goto out;
    }
    sai_status = mlnx_sai_get_port_buffer_index_array(db_port_index, PORT_BUFF_TYPE_PG, &port_pg_profile_refs);
    if (SAI_ERR(sai_status)) {
        goto out;
    }
    if (port_pg_profile_refs[PG0_PORT_IDX] != SENTINEL_BUFFER_DB_ENTRY_INDEX) {
        goto out;
    }

    *is_update = true;

out:
    SX_LOG_ENTER();
    return sai_status;
}

/* db read lock is needed */
static sai_status_t mlnx_sai_buffer_construct_pg_buffer_attr(_In_ const mlnx_port_config_t            *port,
                                                             _In_ uint32_t                             pg_index,
                                                             _Inout_ sx_cos_port_buffer_attr_t        *pgs_buff_reserved_attr_arr,
                                                             _Inout_ uint32_t                         *buff_reserved_attr_count,
                                                             _Inout_ sx_cos_port_shared_buffer_attr_t *pgs_buff_shared_attr_arr,
                                                             _Inout_ uint32_t                         *buff_shared_attr_count)
{
    sai_status_t                     sai_status = SAI_STATUS_SUCCESS;
    sx_cos_port_buffer_attr_t        pg_buff_reserved_attr = {0};
    sx_cos_port_shared_buffer_attr_t pg_buff_shared_attr = {0};

    SX_LOG_ENTER();

    if (!port || !pgs_buff_reserved_attr_arr || !buff_reserved_attr_count || !pgs_buff_shared_attr_arr ||
        !buff_shared_attr_count) {
        SX_LOG_ERR("NULL param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    pg_buff_reserved_attr.type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.size = 0;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.pg = pg_index;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.is_lossy = true;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.xon = 0;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.xoff = 0;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.pool_id =
        g_sai_buffer_db_ptr->buffer_pool_ids.default_ingress_pool_id;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.use_shared_headroom = false;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.pipeline_latency.override_default = true;
    pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.pipeline_latency.size = 0;

    memcpy(&pgs_buff_reserved_attr_arr[*buff_reserved_attr_count],
           &pg_buff_reserved_attr,
           sizeof(pgs_buff_reserved_attr_arr[0]));


    pg_buff_shared_attr.type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
    pg_buff_shared_attr.attr.ingress_port_pg_shared_buff_attr.pg = pg_index;
    pg_buff_shared_attr.attr.ingress_port_pg_shared_buff_attr.pool_id =
        g_sai_buffer_db_ptr->buffer_pool_ids.default_ingress_pool_id;
    pg_buff_shared_attr.attr.ingress_port_pg_shared_buff_attr.max.mode = SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
    pg_buff_shared_attr.attr.ingress_port_pg_shared_buff_attr.max.max.alpha = SX_COS_PORT_BUFF_ALPHA_0_E;

    memcpy(&pgs_buff_shared_attr_arr[*buff_shared_attr_count],
           &pg_buff_shared_attr,
           sizeof(pgs_buff_shared_attr_arr[0]));

    ++(*buff_reserved_attr_count);
    ++(*buff_shared_attr_count);

out:
    SX_LOG_EXIT();
    return sai_status;
}

/* db read lock is needed */
static sai_status_t mlnx_sai_buffer_construct_pg9_buffers_attrs(_In_ const mlnx_port_config_t     *port,
                                                                _Inout_ sx_cos_port_buffer_attr_t *pgs_buff_reserved_attr_arr,
                                                                _Inout_ uint32_t                  *buff_attr_count)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     pg9_profile_idx = PG9_VAL_IDX_LESS_8_LANES;

    SX_LOG_ENTER();

    if (!port || !pgs_buff_reserved_attr_arr || !buff_attr_count) {
        SX_LOG_ERR("NULL param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    pg9_profile_idx = (MAX_LANES_SPC3_4 == port->port_map.width) ? PG9_VAL_IDX_8_LANES : PG9_VAL_IDX_LESS_8_LANES;

    if (!g_sai_db_ptr->port_pg9_defaults[pg9_profile_idx].is_valid) {
        SX_LOG_ERR("Control buffer PG9 profile is not valid \n");
        sai_status = SAI_STATUS_UNINITIALIZED;
        goto out;
    }

    memcpy(&pgs_buff_reserved_attr_arr[*buff_attr_count],
           &g_sai_db_ptr->port_pg9_defaults[pg9_profile_idx].sx_pg_buff_reserved_attr,
           sizeof(pgs_buff_reserved_attr_arr[0]));

    /* on admin down state zero out headroom size and pipeline latency of control priority group */
    if (!port->admin_state) {
        pgs_buff_reserved_attr_arr[*buff_attr_count].attr.ingress_port_pg_buff_attr.size = 0;
        pgs_buff_reserved_attr_arr[*buff_attr_count].attr.ingress_port_pg_buff_attr.pipeline_latency.override_default =
            true;
        pgs_buff_reserved_attr_arr[*buff_attr_count].attr.ingress_port_pg_buff_attr.pipeline_latency.size = 0;
    }

    ++(*buff_attr_count);

out:
    SX_LOG_EXIT();
    return sai_status;
}

/* db write lock is needed */
sai_status_t mlnx_sai_buffer_update_port_buffers_internal(_In_ const mlnx_port_config_t *port)
{
    sai_status_t                     sai_status = SAI_STATUS_SUCCESS;
    sx_cos_port_buffer_attr_t        pgs_buff_reserved_attr_arr[MAX_PGS_INTERNAL_CONF] = {0};
    sx_cos_port_shared_buffer_attr_t pgs_buff_shared_attr_arr[MAX_PGS_INTERNAL_CONF] = {0};
    uint32_t                         buff_reserved_attr_count = 0;
    uint32_t                         buff_shared_attr_count = 0;
    bool                             is_update = false;

    SX_LOG_ENTER();

    sai_status = mlnx_sai_buffer_pg0_update_is_required(port, &is_update);
    if (SAI_ERR(sai_status)) {
        goto out;
    }
    if (is_update) {
        sai_status = mlnx_sai_buffer_construct_pg_buffer_attr(port, 0, pgs_buff_reserved_attr_arr,
                                                              &buff_reserved_attr_count, pgs_buff_shared_attr_arr,
                                                              &buff_shared_attr_count);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to construct lossy PG0 buffers attributes \n");
            goto out;
        }
    }

    sai_status = mlnx_sai_buffer_update_db_control_pg9_buff_profile_if_required(port);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to update SAI DB control PG9 profile.\n");
        goto out;
    }

    sai_status = mlnx_sai_buffer_construct_pg9_buffers_attrs(port,
                                                             pgs_buff_reserved_attr_arr,
                                                             &buff_reserved_attr_count);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to construct control PG9 buffers attributes \n");
        goto out;
    }

    sai_status = mlnx_sai_buffer_configure_buffers(port,
                                                   pgs_buff_reserved_attr_arr,
                                                   buff_reserved_attr_count,
                                                   pgs_buff_shared_attr_arr,
                                                   buff_shared_attr_count);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

/* db read lock is needed */
sai_status_t mlnx_sai_buffer_update_pg0_buffer_sdk_if_required(_In_ const mlnx_port_config_t *port)
{
    sai_status_t                     sai_status = SAI_STATUS_SUCCESS;
    sx_cos_port_buffer_attr_t        pg0_buff_reserved_attr = {0};
    sx_cos_port_shared_buffer_attr_t pg0_buff_shared_attr = {0};
    uint32_t                         buff_reserved_attr_count = 0;
    uint32_t                         buff_shared_attr_count = 0;
    bool                             is_update = false;

    SX_LOG_ENTER();

    sai_status = mlnx_sai_buffer_pg0_update_is_required(port, &is_update);
    if (SAI_ERR(sai_status)) {
        goto out;
    }
    if (is_update) {
        sai_status = mlnx_sai_buffer_construct_pg_buffer_attr(port, 0, &pg0_buff_reserved_attr,
                                                              &buff_reserved_attr_count, &pg0_buff_shared_attr,
                                                              &buff_shared_attr_count);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to construct lossy PG0 buffers attributes \n");
            goto out;
        }

        sai_status = mlnx_sai_buffer_configure_buffers(port,
                                                       &pg0_buff_reserved_attr,
                                                       buff_reserved_attr_count,
                                                       &pg0_buff_shared_attr,
                                                       buff_shared_attr_count);
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

/* db write lock is needed */
sai_status_t mlnx_sai_buffer_update_db_control_pg9_buff_profile_if_required(_In_ const mlnx_port_config_t *port)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    sx_status_t  sx_status = SX_STATUS_SUCCESS;
    uint32_t     pg9_profile_idx = PG9_VAL_IDX_LESS_8_LANES;
    uint32_t     buff_attr_count = 1;

    SX_LOG_ENTER();

    if (!port) {
        SX_LOG_ERR("NULL param\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    pg9_profile_idx = (MAX_LANES_SPC3_4 == port->port_map.width) ? PG9_VAL_IDX_8_LANES : PG9_VAL_IDX_LESS_8_LANES;
    if (!g_sai_db_ptr->port_pg9_defaults[pg9_profile_idx].is_valid) {
        g_sai_db_ptr->port_pg9_defaults[pg9_profile_idx].sx_pg_buff_reserved_attr.type =
            SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E;
        g_sai_db_ptr->port_pg9_defaults[pg9_profile_idx].sx_pg_buff_reserved_attr.attr.ingress_port_pg_buff_attr.pg =
            PG9_PORT_IDX;

        sx_status = sx_api_cos_port_buff_type_get(gh_sdk,
                                                  port->logical,
                                                  &g_sai_db_ptr->port_pg9_defaults[pg9_profile_idx].sx_pg_buff_reserved_attr,
                                                  &buff_attr_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get pg9 buffer reserved info sx_status:%d, message %s.\n", sx_status,
                       SX_STATUS_MSG(sx_status));
            sai_status = sdk_to_sai(sx_status);
            goto out;
        }

        g_sai_db_ptr->port_pg9_defaults[pg9_profile_idx].is_valid = true;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}


/* db read lock is needed */
sai_status_t mlnx_sai_buffer_update_pg9_buffer_sdk(_In_ const mlnx_port_config_t *port)
{
    sai_status_t              sai_status = SAI_STATUS_SUCCESS;
    sx_cos_port_buffer_attr_t pg9_buff_reserved_attr = {0};
    uint32_t                  buff_attr_count = 0;

    SX_LOG_ENTER();

    sai_status = mlnx_sai_buffer_construct_pg9_buffers_attrs(port,
                                                             &pg9_buff_reserved_attr,
                                                             &buff_attr_count);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to construct control PG9 buffer attributes \n");
        goto out;
    }

    sai_status = mlnx_sai_buffer_configure_buffers(port,
                                                   &pg9_buff_reserved_attr,
                                                   buff_attr_count,
                                                   NULL, 0);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

/* db write lock is needed */
sai_status_t mlnx_descriptor_buffer_init()
{
    sai_status_t         sai_status = SAI_STATUS_SUCCESS;
    sx_status_t          sx_status = SX_STATUS_SUCCESS;
    sx_cos_pool_attr_t   ingress_descriptor_pool_attr = {0};
    uint32_t             ingress_descriptor_pool_id;
    sx_cos_pool_attr_t   egress_descriptor_pool_attr = {0};
    uint32_t             egress_descriptor_pool_id;
    const buffer_units_t ipool_size = 5;
    const buffer_units_t pg_max = 8;
    const buffer_units_t size_per_pg = 1;
    const buffer_units_t epool_size = 96;
    const buffer_units_t tc_max = 16;
    const buffer_units_t size_per_tc = 5;
    const buffer_units_t rx_reserved_per_port = ipool_size + pg_max * size_per_pg;
    const buffer_units_t tx_reserved_per_port = epool_size + tc_max * size_per_tc;
    const buffer_units_t total_reserved = MAX_PORTS * (rx_reserved_per_port + tx_reserved_per_port);

    SX_LOG_ENTER();

    ingress_descriptor_pool_attr.pool_dir = SX_COS_PORT_BUFF_POOL_DIRECTION_INGRESS_E;
    /* shared buff def ing desc pool size:
     * SPC1: 81920,  max ports: 64
     * SPC2: 136960, max ports: 128
     * SPC3: 204800, max ports: 128
     * SPC4: 220000, max ports: 258
     * for each port, reserve 5 for ipool, 1 for each PG (total 8 PGs) */
    ingress_descriptor_pool_attr.pool_size = g_resource_limits.shared_buff_def_ing_desc_pool_size - total_reserved;
    ingress_descriptor_pool_attr.mode = SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
    ingress_descriptor_pool_attr.buffer_type = SX_COS_BUFFER_RESERVED1_E;
    ingress_descriptor_pool_attr.infinite_size = false;
    ingress_descriptor_pool_attr.pool_info = SX_COS_POOL_INFO_DEFAULT_DESCRIPTOR_INGRESS_E;

    sx_status = sx_api_cos_shared_buff_pool_set(gh_sdk, SX_ACCESS_CMD_CREATE,
                                                &ingress_descriptor_pool_attr,
                                                &ingress_descriptor_pool_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fail to create default ingress descriptor pool\n");
        sai_status = sdk_to_sai(sx_status);
        goto out;
    }
    g_sai_buffer_db_ptr->buffer_pool_ids.ingress_descriptor_pool_id = ingress_descriptor_pool_id;

    egress_descriptor_pool_attr.pool_dir = SX_COS_PORT_BUFF_POOL_DIRECTION_EGRESS_E;
    /* shared buff def ing desc pool size:
     * SPC1: 81920,  max ports: 64
     * SPC2: 136960, max ports: 128
     * SPC3: 204800, max ports: 128
     * SPC4: 220000, max ports: 258
     * for each port, reserve 96 for epool, 5 for each PG (total 16 PGs) */
    egress_descriptor_pool_attr.pool_size = g_resource_limits.shared_buff_def_egr_desc_pool_size - total_reserved;
    egress_descriptor_pool_attr.mode = SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
    egress_descriptor_pool_attr.buffer_type = SX_COS_BUFFER_RESERVED1_E;
    egress_descriptor_pool_attr.infinite_size = false;
    egress_descriptor_pool_attr.pool_info = SX_COS_POOL_INFO_DEFAULT_DESCRIPTOR_EGRESS_E;

    sx_status = sx_api_cos_shared_buff_pool_set(gh_sdk, SX_ACCESS_CMD_CREATE,
                                                &egress_descriptor_pool_attr,
                                                &egress_descriptor_pool_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fail to create default egress descriptor pool\n");
        sai_status = sdk_to_sai(sx_status);
        goto out;
    }
    g_sai_buffer_db_ptr->buffer_pool_ids.egress_descriptor_pool_id = egress_descriptor_pool_id;

out:
    SX_LOG_EXIT();
    return sai_status;
}

/* db read lock is needed */
sai_status_t mlnx_apply_descriptor_buffer_to_port(sx_port_log_id_t port_log_id, bool remove_default_descriptor_buffer)
{
    sx_cos_port_buffer_attr_t        port_buffer_attr[28] = {0};
    sx_cos_port_shared_buffer_attr_t port_shared_buffer_attr[28] = {0};
    const bool                       is_spc1_a1_and_later = g_sai_db_ptr->sx_chip_type != SX_CHIP_TYPE_SPECTRUM;
    const sx_cos_pool_id_t           ingress_pool_id =
        remove_default_descriptor_buffer ? g_sai_buffer_db_ptr->buffer_pool_ids.default_descriptor_ingress_pool_id :
        g_sai_buffer_db_ptr->buffer_pool_ids.ingress_descriptor_pool_id;
    const sx_cos_pool_id_t egress_pool_id =
        remove_default_descriptor_buffer ? g_sai_buffer_db_ptr->buffer_pool_ids.default_descriptor_egress_pool_id :
        g_sai_buffer_db_ptr->buffer_pool_ids.egress_descriptor_pool_id;
    const buffer_units_t  ingress_buffer_size = remove_default_descriptor_buffer ? 0 : 5;
    const buffer_units_t  ingress_pg_buffer_size = remove_default_descriptor_buffer ? 0 : 1;
    const buffer_units_t  egress_buffer_size = remove_default_descriptor_buffer ? 0 : 96;
    const buffer_units_t  egress_tc_buffer_size = remove_default_descriptor_buffer ? 0 : 5;
    const sx_access_cmd_t sx_cmd =
        remove_default_descriptor_buffer ? SX_ACCESS_CMD_DELETE : SX_ACCESS_CMD_SET;
    const sx_cos_priority_group_t pg_min = 0, pg_max = 7, pg_control = 9;
    const sx_cos_traffic_class_t  tc_min = 0, tc_max = 15, tc_control = 16;
    uint32_t                      count = 0;
    sx_cos_priority_group_t       pg;
    sx_cos_traffic_class_t        tc;
    sai_status_t                  sai_status = SAI_STATUS_SUCCESS;
    sx_status_t                   sx_status = SX_STATUS_SUCCESS;

    SX_LOG_ENTER();

    port_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED1_E;
    port_buffer_attr[count].attr.ingress_port_buff_attr.size = ingress_buffer_size;
    port_buffer_attr[count].attr.ingress_port_buff_attr.pool_id = ingress_pool_id;
    count++;

    /* Do not remove default port PG and TC descriptor pool as it will be reset to
     * the user defined descriptor pool.
     * Keep default port ingress and egress descriptor pool removal as the consumption
     * of default descriptor pool will not be cleared for some reason if removal is skipped. */
    if (!remove_default_descriptor_buffer) {
        for (pg = pg_min; pg <= pg_max; pg++) {
            port_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED2_E;
            port_buffer_attr[count].attr.ingress_port_pg_buff_attr.size = ingress_pg_buffer_size;
            port_buffer_attr[count].attr.ingress_port_pg_buff_attr.pool_id = ingress_pool_id;
            port_buffer_attr[count].attr.ingress_port_pg_buff_attr.pg = pg;
            count++;
        }
        port_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED2_E;
        port_buffer_attr[count].attr.ingress_port_pg_buff_attr.size = ingress_pg_buffer_size;
        port_buffer_attr[count].attr.ingress_port_pg_buff_attr.pool_id = ingress_pool_id;
        port_buffer_attr[count].attr.ingress_port_pg_buff_attr.pg = pg_control;
        count++;
    }

    port_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED3_E;
    port_buffer_attr[count].attr.egress_port_buff_attr.size = egress_buffer_size;
    port_buffer_attr[count].attr.egress_port_buff_attr.pool_id = egress_pool_id;
    count++;

    if (!remove_default_descriptor_buffer) {
        for (tc = tc_min; tc <= tc_max; tc++) {
            port_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED4_E;
            port_buffer_attr[count].attr.egress_port_tc_buff_attr.size = egress_tc_buffer_size;
            port_buffer_attr[count].attr.egress_port_tc_buff_attr.pool_id = egress_pool_id;
            port_buffer_attr[count].attr.egress_port_tc_buff_attr.tc = tc;
            count++;
        }
        port_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED4_E;
        port_buffer_attr[count].attr.egress_port_tc_buff_attr.size = egress_tc_buffer_size;
        port_buffer_attr[count].attr.egress_port_tc_buff_attr.pool_id = egress_pool_id;
        port_buffer_attr[count].attr.egress_port_tc_buff_attr.tc = tc_control;
        count++;
    }

    sx_status = sx_api_cos_port_buff_type_set(gh_sdk, sx_cmd, port_log_id,
                                              port_buffer_attr, count);
    if (SX_ERR(sx_status)) {
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_ERR("Failed to set port descriptor buffer for port %d \n", port_log_id);
        goto out;
    }

    count = 0;

    port_shared_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED1_E;
    port_shared_buffer_attr[count].attr.ingress_port_shared_buff_attr.max.mode = SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
    port_shared_buffer_attr[count].attr.ingress_port_shared_buff_attr.max.max.alpha =
        is_spc1_a1_and_later ? SX_COS_PORT_BUFF_ALPHA_8_E : SX_COS_PORT_BUFF_ALPHA_INFINITY_E;
    port_shared_buffer_attr[count].attr.ingress_port_shared_buff_attr.pool_id = ingress_pool_id;
    count++;

    if (!remove_default_descriptor_buffer) {
        for (pg = pg_min; pg <= pg_max; pg++) {
            port_shared_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED2_E;
            port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.max.mode =
                SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
            port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.max.max.alpha =
                is_spc1_a1_and_later ? SX_COS_PORT_BUFF_ALPHA_8_E : SX_COS_PORT_BUFF_ALPHA_INFINITY_E;
            port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.pool_id = ingress_pool_id;
            port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.pg = pg;
            count++;
        }
        port_shared_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED2_E;
        port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.max.mode =
            SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
        port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.max.max.alpha =
            is_spc1_a1_and_later ? SX_COS_PORT_BUFF_ALPHA_8_E : SX_COS_PORT_BUFF_ALPHA_INFINITY_E;
        port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.pool_id = ingress_pool_id;
        port_shared_buffer_attr[count].attr.ingress_port_pg_shared_buff_attr.pg = pg_control;
        count++;
    }

    port_shared_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED3_E;
    port_shared_buffer_attr[count].attr.egress_port_shared_buff_attr.max.mode = SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
    port_shared_buffer_attr[count].attr.egress_port_shared_buff_attr.max.max.alpha = SX_COS_PORT_BUFF_ALPHA_INFINITY_E;
    port_shared_buffer_attr[count].attr.egress_port_shared_buff_attr.pool_id = egress_pool_id;
    count++;

    if (!remove_default_descriptor_buffer) {
        for (tc = tc_min; tc <= tc_max; tc++) {
            port_shared_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED4_E;
            port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.max.mode =
                SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
            port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.max.max.alpha =
                SX_COS_PORT_BUFF_ALPHA_INFINITY_E;
            port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.pool_id = egress_pool_id;
            port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.tc = tc;
            count++;
        }
        port_shared_buffer_attr[count].type = SX_COS_PORT_BUFF_ATTR_RESERVED4_E;
        port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.max.mode =
            SX_COS_BUFFER_MAX_MODE_DYNAMIC_E;
        port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.max.max.alpha =
            SX_COS_PORT_BUFF_ALPHA_INFINITY_E;
        port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.pool_id = egress_pool_id;
        port_shared_buffer_attr[count].attr.egress_port_tc_shared_buff_attr.tc = tc_control;
        count++;
    }

    sx_status = sx_api_cos_port_shared_buff_type_set(gh_sdk, sx_cmd, port_log_id,
                                                     port_shared_buffer_attr, count);
    if (SX_ERR(sx_status)) {
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_ERR("Failed to set port shared descriptor buffer for port %d \n", port_log_id);
        goto out;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

const sai_buffer_api_t mlnx_buffer_api = {
    mlnx_sai_create_buffer_pool,
    mlnx_sai_remove_buffer_pool,
    mlnx_sai_set_buffer_pool_attr,
    mlnx_sai_get_buffer_pool_attr,
    mlnx_sai_get_buffer_pool_stats,
    mlnx_sai_get_buffer_pool_stats_ext,
    mlnx_clear_buffer_pool_stats,
    mlnx_create_ingress_priority_group,
    mlnx_remove_ingress_priority_group,
    mlnx_sai_set_ingress_priority_group_attr,
    mlnx_sai_get_ingress_priority_group_attr,
    mlnx_sai_get_ingress_priority_group_stats,
    mlnx_sai_get_ingress_priority_group_stats_ext,
    mlnx_sai_clear_ingress_priority_group_stats,
    mlnx_sai_create_buffer_profile,
    mlnx_sai_remove_buffer_profile,
    mlnx_sai_set_buffer_profile_attr,
    mlnx_sai_get_buffer_profile_attr
};
