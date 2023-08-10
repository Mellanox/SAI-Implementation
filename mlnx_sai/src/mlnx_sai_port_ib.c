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
#include "mlnx_sai_prm_api.h"
#include "mlnx_sai_swid_api.h"
#include <errno.h>

#undef  __MODULE__
#define __MODULE__ SAI_PORT

extern uint32_t g_device_id;
#define ADMIN_STATE_UPDATE_ENABLE 1
#define PUDE_UPDATE_ENABLE        1
#define GENRERATE_EVENT           1
#define PUDE_SINGLE_EVENT         2
#define BASE_SPEED                0x0000ffff
#define REG_PTYS_PROTO_MASK_IB    1 << 0
#define BER_EVENT_ALARM           4
#define MAX_PDDR_MSG_BUFFER       512

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
sai_status_t mlnx_sai_port_hw_lanes_get(_In_ sx_port_log_id_t *port_id, _Inout_ sai_attribute_value_t *value);
extern uint32_t mlnx_cells_to_bytes(uint32_t cells);
extern sai_status_t mlnx_get_default_label_port_from_local_port(mlnx_port_config_t* port);
extern bool g_is_chipsim;
static sai_status_t mlnx_port_state_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_port_mtu_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static sai_status_t mlnx_port_fec_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static sai_status_t mlnx_port_attr_set(_In_ const sai_object_key_t      *key,
                                       _In_ const sai_attribute_value_t *value,
                                       void                             *arg);
static sai_status_t mlnx_port_type_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg);
static sai_status_t mlnx_port_state_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_port_hw_lanes_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_port_supported_breakout_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_port_current_breakout_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_port_supported_speed_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_port_supported_fec_mode_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_port_oper_speed_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_port_fec_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_port_attr_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg);
static sai_status_t mlnx_port_mtu_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_port_speed_get_impl(_In_ sx_port_log_id_t sx_port,
                                             _Out_ uint32_t       *oper_speed,
                                             _Out_ uint32_t       *admin_speed);
static sai_status_t mlnx_port_supported_speeds_get_impl(_In_ sx_port_log_id_t sx_port, _Inout_ sai_u32_list_t *list);
static sai_status_t mlnx_port_speed_get_ib(_In_ sx_port_log_id_t sx_port,
                                           _Out_ uint32_t       *oper_speed,
                                           _Out_ uint32_t       *admin_speed);
static sai_status_t mlnx_port_supported_speeds_get_ib(_In_ sx_port_log_id_t sx_port,
                                                      _Out_ uint32_t       *speeds,
                                                      _Inout_ uint32_t     *speeds_count);
static sai_status_t mlnx_port_advertised_speeds_get_ib(_In_ mlnx_port_config_t *port,
                                                       _Out_ uint32_t          *speeds,
                                                       _Inout_ uint32_t        *speeds_count);
static sai_status_t mlnx_port_update_speed(_In_ mlnx_port_config_t *port);
static sai_status_t mlnx_port_update_speed_ib(_In_ sx_port_log_id_t sx_port,
                                              _In_ uint64_t         bitmap);
static sai_status_t mlnx_port_ib_lanes_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_port_ib_lanes_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static sai_status_t mlnx_port_ib_subnet_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_port_signal_degrade_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_port_signal_degrade_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_port_max_mtu_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_port_ib_vl_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_port_ib_vl_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_port_states_get(_In_ mlnx_port_config_t  *port,
                                         _In_ uint32_t             number_of_states,
                                         _In_ const sai_stat_id_t *states_ids,
                                         _Out_ uint64_t           *states);
static sai_status_t mlnx_port_counters_get(_In_ mlnx_port_config_t  *port,
                                           _In_ uint32_t             number_of_counters,
                                           _In_ const sai_stat_id_t *counters_ids,
                                           _Out_ uint64_t           *counters);
static sai_status_t mlnx_port_link_diagnostic_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_port_speed_by_width_get(_In_ sx_port_log_id_t sx_port,
                                                 _Out_ uint32_t       *oper_speed);
static sai_status_t mlnx_port_state_admin_by_sd_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_port_internal_loopback_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_port_internal_loopback_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_port_internal_loopback_set_impl(_In_ uint32_t                          local_port,
                                                         _In_ uint32_t                          swid_id,
                                                         _In_ sai_port_internal_loopback_mode_t loop_mode);
static sai_status_t mlnx_port_fnm_port_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_aggregation_port_data_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg);
static sai_status_t mlnx_aggregation_port_data_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_port_protocol_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_connection_type_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_is_maf_get(_In_ const sai_object_key_t   *key,
                                    _Inout_ sai_attribute_value_t *value,
                                    _In_ uint32_t                  attr_index,
                                    _Inout_ vendor_cache_t        *cache,
                                    void                          *arg);
static sai_status_t mlnx_port_remote_id_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static bool mlnx_port_is_ib_state_stat(_In_ const sai_stat_id_t states_id);
static bool mlnx_port_is_ib_counter_stat(_In_ const sai_stat_id_t states_id);
extern bool g_is_chipsim;

enum mlnx_speed_bitmap_ib {
    IB_SDR_10G   = 1 << 0,
    IB_DDR_20G   = 1 << 1,
    IB_QDR_40G   = 1 << 2,
    IB_FDR10_40G = 1 << 3,
    IB_FDR_56G   = 1 << 4,
    IB_EDR_100G  = 1 << 5,
    IB_HDR_200G  = 1 << 6,
    IB_NDR_400G  = 1 << 7,
    IB_XDR_800G  = 1 << 8,
};

uint64_t mlnx_port_speed_bitmap_ib[MAX_NUM_PORT_SPEEDS] = {
    (0),
    (0),
    (0),
    (IB_SDR_10G),
    (IB_DDR_20G),
    (0),
    (IB_QDR_40G),
    (IB_FDR10_40G),
    (IB_FDR_56G),
    (IB_EDR_100G),
    (IB_HDR_200G),
    (IB_NDR_400G),
    (IB_XDR_800G),
};

typedef sai_status_t (*mlnx_port_speed_set_fn)(_In_ sx_port_log_id_t sx_port, _In_ uint32_t speed);
typedef sai_status_t (*mlnx_port_speed_get_fn)(_In_ sx_port_log_id_t sx_port, _Out_ uint32_t *oper_speed,
                                               _Out_ uint32_t *admin_speed);
typedef sai_status_t (*mlnx_port_supported_speeds_get_fn)(_In_ sx_port_log_id_t sx_port, _Out_ uint32_t *speeds,
                                                          _Inout_ uint32_t      *speeds_count);
typedef sai_status_t (*mlnx_port_advertised_speeds_get_fn)(_In_ mlnx_port_config_t *port, _Out_ uint32_t *speeds,
                                                           _Inout_ uint32_t      *speeds_count);
typedef sai_status_t (*mlnx_port_update_speed_fn)(_In_ sx_port_log_id_t sx_port,
                                                  _In_ uint64_t         bitmap);

typedef struct _mlnx_port_cb_t {
    mlnx_port_speed_get_fn             speed_get;
    mlnx_port_supported_speeds_get_fn  supported_speeds_get;
    mlnx_port_advertised_speeds_get_fn advertised_speeds_get;
    mlnx_port_update_speed_fn          update_speed;
    uint64_t                          *speed_bitmap;
} mlnx_port_cb_table_t;


static mlnx_port_cb_table_t               mlnx_port_cb_ib = {
    mlnx_port_speed_get_ib,
    mlnx_port_supported_speeds_get_ib,
    mlnx_port_advertised_speeds_get_ib,
    mlnx_port_update_speed_ib,
    mlnx_port_speed_bitmap_ib,
};
static mlnx_port_cb_table_t             * mlnx_port_cb = NULL;
static const sai_vendor_attribute_entry_t port_vendor_attribs[] = {
    { SAI_PORT_ATTR_TYPE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_type_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_OPER_STATUS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_state_get, (void*)SAI_PORT_ATTR_OPER_STATUS,
      NULL, NULL },
    { SAI_PORT_ATTR_HW_LANE_LIST,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_port_hw_lanes_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_SUPPORTED_BREAKOUT_MODE_TYPE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_supported_breakout_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_CURRENT_BREAKOUT_MODE_TYPE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_current_breakout_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_SUPPORTED_SPEED,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_supported_speed_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_SUPPORTED_FEC_MODE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_supported_fec_mode_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_OPER_SPEED,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_oper_speed_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_SPEED,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_attr_get, (void*)SAI_PORT_ATTR_SPEED,
      mlnx_port_attr_set, (void*)SAI_PORT_ATTR_SPEED },
    { SAI_PORT_ATTR_AUTO_NEG_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_attr_get, (void*)SAI_PORT_ATTR_AUTO_NEG_MODE,
      mlnx_port_attr_set, (void*)SAI_PORT_ATTR_AUTO_NEG_MODE },
    { SAI_PORT_ATTR_ADVERTISED_SPEED,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_attr_get, (void*)SAI_PORT_ATTR_ADVERTISED_SPEED,
      mlnx_port_attr_set, (void*)SAI_PORT_ATTR_ADVERTISED_SPEED },
    { SAI_PORT_ATTR_SIGNAL_DEGRADE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_signal_degrade_get, (void*)SAI_PORT_ATTR_SIGNAL_DEGRADE,
      mlnx_port_signal_degrade_set, (void*)SAI_PORT_ATTR_SIGNAL_DEGRADE },
    { SAI_PORT_ATTR_ADMIN_STATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_state_get, (void*)SAI_PORT_ATTR_ADMIN_STATE,
      mlnx_port_state_set, NULL },
    { SAI_PORT_ATTR_FEC_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_fec_get, NULL,
      mlnx_port_fec_set, NULL },
    { SAI_PORT_ATTR_MTU,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_mtu_get, NULL,
      mlnx_port_mtu_set, NULL },
    { SAI_PORT_ATTR_TECHNOLOGY,
      { true, false, true, true },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_SUPPORTED_HW_LANES,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_ib_lanes_get, (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_SUPPORTED_HW_LANES,
      NULL, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_LANES,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_ib_lanes_get, (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_LANES,
      NULL, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_ADMIN_LANES,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_ib_lanes_get, (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_ADMIN_LANES,
      mlnx_port_ib_lanes_set, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_SUPPORTED_VL,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_ib_vl_get, (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_SUPPORTED_VL,
      NULL, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_VL,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_ib_vl_get, (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_VL,
      NULL, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_ADMIN_VL,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_ib_vl_get, (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_ADMIN_VL,
      mlnx_port_ib_vl_set, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_IB_SUBNET,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_ib_subnet_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_CUSTOM_INFINIBAND_MAX_MTU,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_max_mtu_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_DOWN_BY_SIGNAL_DEGRADE,
      { false, false, true, false },
      { false, false, true, false },
      NULL, NULL,
      mlnx_port_state_admin_by_sd_set, NULL },
    { SAI_PORT_ATTR_LINK_DIAGNOSTIC,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_port_link_diagnostic_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_internal_loopback_get, NULL,
      mlnx_port_internal_loopback_set, NULL },
    { SAI_PORT_ATTR_FNM_PORT,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_port_fnm_port_get, NULL, NULL, NULL },
    { SAI_PORT_ATTR_MAF,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_is_maf_get, NULL, NULL, NULL },
    { SAI_PORT_ATTR_AGGREGATE_PORT_DATA,
      {true, false, true, false},
      {true, false, true, false},
      mlnx_aggregation_port_data_get, NULL,
      mlnx_aggregation_port_data_set, NULL },
    { SAI_PORT_ATTR_PROTOCOL,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_port_protocol_get, NULL, NULL, NULL },
    { SAI_PORT_ATTR_CONNECTION_TYPE,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_connection_type_get, NULL, NULL, NULL },
    { SAI_PORT_ATTR_REMOTE_ID,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_port_remote_id_get, NULL, NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        port_enum_info[] = {
    [SAI_PORT_ATTR_TYPE] =
        ATTR_ENUM_VALUES_ALL(),

    [SAI_PORT_ATTR_OPER_STATUS] = ATTR_ENUM_VALUES_LIST(
        SAI_PORT_OPER_STATUS_UP,
        SAI_PORT_OPER_STATUS_DOWN,
        SAI_PORT_OPER_STATUS_UNKNOWN),

    [SAI_PORT_ATTR_SUPPORTED_BREAKOUT_MODE_TYPE] =
        ATTR_ENUM_VALUES_ALL(),

    [SAI_PORT_ATTR_CURRENT_BREAKOUT_MODE_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_PORT_BREAKOUT_MODE_TYPE_1_LANE,
        SAI_PORT_BREAKOUT_MODE_TYPE_2_LANE,
        SAI_PORT_BREAKOUT_MODE_TYPE_4_LANE),

    [SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE] = ATTR_ENUM_VALUES_LIST(
        SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY,
        SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE),

    [SAI_PORT_ATTR_FEC_MODE] = ATTR_ENUM_VALUES_LIST(
        SAI_PORT_FEC_MODE_AUTO,
        SAI_PORT_FEC_MODE_NONE,
        SAI_PORT_FEC_MODE_ON,
        SAI_PORT_FEC_MODE_FC,
        SAI_PORT_FEC_MODE_RS),

    [SAI_PORT_ATTR_SUPPORTED_FEC_MODE] = ATTR_ENUM_VALUES_LIST(
        SAI_PORT_FEC_MODE_AUTO,
        SAI_PORT_FEC_MODE_NONE,
        SAI_PORT_FEC_MODE_ON,
        SAI_PORT_FEC_MODE_FC,
        SAI_PORT_FEC_MODE_RS),
};
static const sai_stat_capability_t        port_stats_capabilities[] = {
    { SAI_PORT_STAT_INFINIBAND_IF_IN_OCTETS_EXT, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_IF_IN_PKTS_EXT, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_IF_OUT_OCTETS_EXT, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_IF_OUT_PKTS_EXT, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_IF_OUT_WAIT, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_PC_ERR_SYM_F, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_PC_ERR_RCV_F, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_PC_VL15_DROPPED_F, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_PC_XMT_DISCARDS_F, SAI_STATS_MODE_READ },
    { SAI_PORT_STAT_INFINIBAND_ERR_XMTCONSTR_F, SAI_STATS_MODE_READ },
};
const mlnx_obj_type_attrs_info_t          mlnx_port_obj_type_info =
{ port_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(port_enum_info), OBJ_STAT_CAP_INFO(port_stats_capabilities)};

/**
 * Function set port's aggregated data configuration via PPCR register.
 *
 * @param swid        - swid id of the port.
 * @param dev_id      - device id of the port.
 * @param local_port  - local number of the port.
 * @param aport       - port's aggregated port
 * @param plane       - port's plane
 * @return            - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_aport_set_impl(uint8_t      swid,
                                        sxd_dev_id_t dev_id,
                                        uint32_t     local_port,
                                        uint32_t     aport,
                                        uint32_t     plane,
                                        uint32_t     num_of_planes)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    struct ku_ppcr_reg ppcr_reg;

    SX_LOG_ENTER();
    /* MOCK */
    if (mlnx_chip_is_qtm2()) {
        SX_LOG_NTC("Can't write aggregated data to FW on QTM2\n");
        goto out;
    }
    memset(&ppcr_reg, 0, sizeof(ppcr_reg));
    ppcr_reg.local_port = local_port;
    ppcr_reg.aggregated_port = aport;
    ppcr_reg.plane = plane;
    ppcr_reg.num_of_planes = num_of_planes;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ppcr_register(SXD_ACCESS_CMD_SET,
                                                                   swid,
                                                                   dev_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ppcr_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PPCR for local port: [%u], device: [%u], swid [%u]\n",
                         ppcr_reg.local_port, dev_id, swid);
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

/**
 * Function set port's signal degrade configuration via PPBMC register.
 *
 * @param swid        - swid id of the port.
 * @param dev_id      - device id of the port.
 * @param local_port  - local number of the port.
 * @param enable_ber  - BER status to configure (true/false).
 * @return            - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_port_signal_degrade_impl(uint8_t      swid,
                                                      sxd_dev_id_t dev_id,
                                                      uint32_t     local_port,
                                                      bool         enable_ber)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    struct ku_ppbmc_reg ppbmc_reg;

    SX_LOG_ENTER();
    if (g_is_chipsim) {
        goto out;
    }

    memset(&ppbmc_reg, 0, sizeof(ppbmc_reg));
    ppbmc_reg.local_port = local_port;
    ppbmc_reg.e =
        (enable_ber == true) ? SXD_PORT_EVENT_GENERATE_MODE_GENERATE_SINGLE : SXD_PORT_EVENT_GENERATE_MODE_DONT;           /* Generate event or disable events */
    ppbmc_reg.event_ctrl = BER_EVENT_ALARM;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ppbmc_register(SXD_ACCESS_CMD_SET,
                                                                    swid,
                                                                    dev_id,
                                                                    NULL,
                                                                    NULL,
                                                                    &ppbmc_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PPBMC for local port: [%u], device: [%u], swid [%u]\n",
                         ppbmc_reg.local_port, dev_id, swid);
        goto out;
    }
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's ib subnet number (0...7)
 *
 * @param key        - sai port object
 * @param value      - value.u8 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_ib_subnet_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    value->u8 = port->swid_id;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function set port's admin state via PAOS register.
 *
 * @param swid        - swid id of the port.
 * @param dev_id      - device id of the port.
 * @param local_port  - local number of the port.
 * @param admin_state - admin state to configure (true/false).
 * @return            - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_set_port_state_admin(uint8_t swid, sxd_dev_id_t dev_id, uint32_t local_port, bool admin_state)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    struct ku_paos_reg paos_reg;

    memset(&paos_reg, 0, sizeof(paos_reg));
    paos_reg.local_port = local_port;
    paos_reg.admin_status = admin_state ? SXD_PAOS_ADMIN_STATUS_UP_E : SXD_PAOS_ADMIN_STATUS_DOWN_BY_CONFIGURATION_E;
    /* Admin state update enable. If this bit is set, admin state will be updated based on admin_state field. */
    paos_reg.ase = ADMIN_STATE_UPDATE_ENABLE;
    /* Event update enable. If this bit is set, event generation will be updated based on the e field. */
    paos_reg.ee = PUDE_UPDATE_ENABLE;
    /* Event generation on operational state change. */
    paos_reg.e = GENRERATE_EVENT;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_paos_register(SXD_ACCESS_CMD_SET,
                                                                   swid,
                                                                   dev_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &paos_reg))) {
        MLNX_SAI_LOG_ERR(
            "Failed set PAOS for local port: [%u], device: [%u], swid [%u], admin requested state: [%u]\n",
            local_port,
            dev_id,
            swid,
            admin_state);
    }

    return status;
}

/**
 * Function set port's admin mtu via PMTU register.
 *
 * @param swid       - swid id of the port.
 * @param dev_id     - device id of the port.
 * @param local_port - local number of the port.
 * @param mtu_value  - mtu value to configure.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_mtu_admin(uint8_t swid, sxd_dev_id_t dev_id, uint32_t local_port, uint32_t mtu_value)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    struct ku_pmtu_reg pmtu_reg;

    memset(&pmtu_reg, 0, sizeof(pmtu_reg));
    pmtu_reg.local_port = local_port;
    pmtu_reg.admin_mtu = (uint16_t)mtu_value;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pmtu_register(SXD_ACCESS_CMD_SET,
                                                                   swid,
                                                                   dev_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pmtu_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PMTU for local port: [%u], device: [%u], swid [%u], requested mtu [%u]\n",
                         pmtu_reg.local_port, dev_id, swid, mtu_value);
    }
    return status;
}


/**
 * Function set port's admin state (true - up , false - down).
 *
 * @param key   - sai port object
 * @param value - value.booldata is the configured value.
 * @param arg   - not used.
 * @return      - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_state_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t        status;
    mlnx_port_config_t *port;
    bool                sdk_state = value->booldata;
    bool                is_warmboot_init_stage = false;

    SX_LOG_ENTER();
    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);

    port->admin_state = sdk_state;

    if (is_warmboot_init_stage) {
        status = mlnx_port_update_speed(port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update speed.\n");
            goto out;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_set_port_state_admin(port->swid_id, g_device_id, port->port_map.local_port, sdk_state))) {
        MLNX_SAI_LOG_ERR("Failed to set port admin state.\n");
        goto out;
    }
    /*Setting this value to false when setting port up or down. Setting it to true will happen only from attribute's function */
    else {
        port->down_by_signal_degrade = false;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}


/**
 * Function set port's mtu.
 *
 * @param key   - sai port object
 * @param value - value.u32 is the configured value.
 * @param arg   - not used.
 * @return      - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_mtu_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_set_mtu_admin(port->swid_id, g_device_id, port->port_map.local_port, value->u32))) {
        MLNX_SAI_LOG_ERR("Failed to set mtu to port %u \n", port->port_map.local_port);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/* FEC information */
#define ERR_CORRECTION_STATUS_NONE_FEC       0X0000 /*No FEC*/
#define ERR_CORRECTION_STATUS_NO_FEC         0X0001 /*No FEC*/
#define ERR_CORRECTION_STATUS_FIRECODE_FEC   0X0002 /*Firecode FEC*/
#define ERR_CORRECTION_PROFILE_AUTO_MODE     0x0003
#define ERR_CORRECTION_STATUS_RS_FEC         0X0004 /*Standard RS FEC- RS(528,514)*/
#define ERR_CORRECTION_PROFILE_DISABLE_FEC   0x0007
#define ERR_CORRECTION_PROFILE_DEFAULT_FEC   0x0008
#define ERR_CORRECTION_STATUS_LL_RS_FEC      0X0008 /*Standard LL RS FEC- RS(271,257)*/
#define ERR_CORRECTION_STATUS_MLNX_RS_FEC    0X0010 /*Mellanox Strong RS FEC- RS(277,257)*/
#define ERR_CORRECTION_STATUS_MLNX_LL_RS_FEC 0X0020 /*Mellanox LL RS FEC- RS(163,155)*/
#define ERR_CORRECTION_STATUS_RS_544_514_FEC 0X0080 /*Standard RS FEC(544,514)*/
#define ERR_CORRECTION_STATUS_ZL_FEC         0X0100 /*Zero Latency FEC*/
#define ERR_CORRECTION_STATUS_RS_PLR_FEC     0X1000 /*RS FEC(544,514) + PLR*/
#define ERR_CORRECTION_STATUS_LL_PLR_FEC     0X2000 /*LL FEC(271,257) + PLR*/
#define ERR_CORRECTION_STATUS_ETH_LL_PLR     0X4000 /*Ethernet_Consortium_LL_50G_RS_FEC_PLR - (272,257+1)*/
#define ERR_CORRECTION_STATUS_XDR            0x0040

/**
 * Function set port's fec via PPLM register.
 *
 * @param swid       - swid id of the port.
 * @param dev_id     - device id of the port.
 * @param local_port - local number of the port.
 * @param value      - fec value to configure (auto/none/on).
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_fec_set_impl(uint8_t swid, sxd_dev_id_t dev_id, uint32_t local_port, int32_t value)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    struct ku_pplm_reg pplm_reg;

    memset(&pplm_reg, 0, sizeof(struct ku_pplm_reg));
    pplm_reg.local_port = local_port;

    switch (value) {
    case SAI_PORT_FEC_MODE_AUTO:
        pplm_reg.port_profile_mode |= ERR_CORRECTION_STATUS_XDR;
        break;

    case SAI_PORT_FEC_MODE_NONE:
        /*first clear bit0 & bit1 in port_profile_mode */
        pplm_reg.port_profile_mode &= ~ERR_CORRECTION_PROFILE_AUTO_MODE;
        /*set static_port_profile*/
        pplm_reg.static_port_profile = ERR_CORRECTION_PROFILE_DISABLE_FEC;
        break;

    case SAI_PORT_FEC_MODE_ON:
        /*first clear bit0 & bit1 in port_profile mode */
        pplm_reg.port_profile_mode &= ~ERR_CORRECTION_PROFILE_AUTO_MODE;
        /*set static_port_profile*/
        pplm_reg.static_port_profile = ERR_CORRECTION_PROFILE_DEFAULT_FEC;
        break;

    default:
        SX_LOG_ERR("Invalid FEC mode %d\n", value);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0;
        goto out;
    }

    MLNX_SAI_LOG_NTC("Set PPLM reg - local port [%u], port_profile_mode [%u], static_port_profile [%u]\n",
                     local_port, pplm_reg.port_profile_mode, pplm_reg.static_port_profile);

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pplm_register(SXD_ACCESS_CMD_SET,
                                                                   swid,
                                                                   dev_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pplm_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PPLM Fec value %d for local port: [%u], device: [%u], swid [%u],"
                         "requested profile mode [%u], requested static port profile [%u]\n",
                         value,
                         local_port,
                         dev_id,
                         swid,
                         pplm_reg.port_profile_mode,
                         pplm_reg.static_port_profile);
    }

out:
    return status;
}

/**
 * Function set port's fec.
 *
 * @param key   - sai port object
 * @param value - value.u32 is the configured value.
 * @param arg   - not used.
 * @return      - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_fec_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t        status;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_fec_set_impl(port->swid_id, g_device_id, port->port_map.local_port, value->u32))) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's type. for now we return logical for all.
 *
 * @param key        - sai port object
 * @param value      - value.u32 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_type_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    value->s32 = SAI_PORT_TYPE_LOGICAL;
    return SAI_STATUS_SUCCESS;
}

/**
 * Function return port's operational state or admin state.
 *
 * @param key        - sai port object
 * @param value      - value.s32 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - get operational state (SAI_PORT_ATTR_OPER_STATUS) or admin state (SAI_PORT_ATTR_ADMIN_STATE).
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_state_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_paos_reg  paos_reg;

    SX_LOG_ENTER();

    assert((SAI_PORT_ATTR_OPER_STATUS == (long)arg) || (SAI_PORT_ATTR_ADMIN_STATE == (long)arg));
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out_unlock;
    }

    memset(&paos_reg, 0, sizeof(struct ku_paos_reg));
    paos_reg.local_port = port->port_map.local_port;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_paos_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &paos_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PAOS for local port: [%u], device: [%u], swid [%u]\n",
                         port->port_map.local_port, g_device_id, port->swid_id);
        goto out_unlock;
    }

    if (SAI_PORT_ATTR_OPER_STATUS == (long)arg) {
        switch (paos_reg.oper_status) {
        case SX_PORT_OPER_STATUS_UP:
            value->s32 = SAI_PORT_OPER_STATUS_UP;
            break;

        case SX_PORT_OPER_STATUS_DOWN:
        case SX_PORT_OPER_STATUS_DOWN_BY_FAIL:
            value->s32 = SAI_PORT_OPER_STATUS_DOWN;
            break;

        default:
            value->s32 = SAI_PORT_OPER_STATUS_UNKNOWN;
            break;
        }
    } else {
        switch (paos_reg.admin_status) {
        case SX_PORT_ADMIN_STATUS_UP:
            value->booldata = true;
            break;

        case SX_PORT_ADMIN_STATUS_DOWN:
            value->booldata = false;
            break;

        default:
            value->booldata = false;
            break;
        }
    }

out_unlock:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's index by port sai object.
 *
 * @param port  - sai port object
 * @param index - port's index to return.
 * @return      - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t find_port_in_db(_In_ sai_object_id_t port, _Out_ uint32_t *index)
{
    mlnx_port_config_t *port_cfg;
    uint32_t            ii;

    if (NULL == index) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    mlnx_port_foreach(port_cfg, ii) {
        if (port == port_cfg->saiport) {
            *index = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Port %" PRIx64 " not found in DB\n", port);
    return SAI_STATUS_INVALID_PORT_NUMBER;
}

/**
 * Function return port's max lanes.
 *
 * @return - the max lanes number for port.
 */
static uint32_t mlnx_port_max_lanes_get(void)
{
    return MAX_LANES_IB;
}

/**
 * Function return port's hw lanes map by calculating it from port.module * max_lanes + (1..max lanes)
 *
 * @param port_map - port's map to get port's module  and width.
 * @param lanes    - the hw lanes that was calculated.
 * @param value    - the copy of the hw lanes list.
 * @return         - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t copy_port_hw_lanes(_In_ sx_port_mapping_t        *port_map,
                                       _In_ uint32_t                 *lanes,
                                       _Inout_ sai_attribute_value_t *value)
{
    uint32_t     ii = 0;
    uint32_t     jj;
    sai_status_t sai_status = SAI_STATUS_FAILURE;

    assert(NULL != port_map);
    assert(NULL != lanes);

    for (jj = 0; jj < mlnx_port_max_lanes_get(); jj++) {
        if (port_map->lane_bmap & (1 << jj)) {
            lanes[ii++] = port_map->module_port * mlnx_port_max_lanes_get() + jj;
        }
    }
    assert(ii == port_map->width);
    sai_status = mlnx_fill_u32list(lanes, port_map->width, &value->u32list);
    return sai_status;
}

/**
 * Function copies lanes list from hw into value u32list.list
 * DB read lock is needed
 *
 * @param port_id - sx port index
 * @param value   - it is expected that value.u32list.list [sai_u32_list_t] is allocated
 *                  and has enough space to keep all elements obtained from hw
 * @return        - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_sai_port_hw_lanes_get(_In_ sx_port_log_id_t *port_id, _Inout_ sai_attribute_value_t *value)
{
    sai_status_t        sai_status = SAI_STATUS_SUCCESS;
    uint32_t            port_db_idx = 0;
    uint32_t            lanes[MAX_LANES_IB] = {0};
    sx_port_mapping_t   port_map = {0};
    const bool          is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);
    mlnx_port_config_t *port;
    struct ku_pmlp_reg  pmlp_reg;
    u_int32_t           divider;

    SX_LOG_ENTER();

    memset(lanes, 0, sizeof(lanes));

    if (is_warmboot_init_stage) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_port_idx_by_log_id(*port_id, &port_db_idx))) {
            SX_LOG_ERR("Error getting port idx using port id %x\n", *port_id);
            goto out;
        }
        sai_status = copy_port_hw_lanes(&(mlnx_ports_db[port_db_idx].port_map), lanes, value);
    } else {
        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_port_by_log_id(*port_id, &port))) {
            SX_LOG_ERR("Error getting port using port id %x\n", *port_id);
            goto out;
        }
        memset(&pmlp_reg, 0, sizeof(struct ku_pmlp_reg));
        memset(&port_map, 0, sizeof(sx_port_mapping_t));
        pmlp_reg.local_port = port->port_map.local_port;
        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_set_get_pmlp_register(SXD_ACCESS_CMD_GET,
                                                                           port->swid_id,
                                                                           g_device_id,
                                                                           NULL,
                                                                           NULL,
                                                                           &pmlp_reg))) {
            MLNX_SAI_LOG_ERR("Failed get PMLP for local port: [%u], device: [%u], swid [%u]\n",
                             port->port_map.local_port, g_device_id, port->swid_id);
            goto out;
        }
        /* When breakout mode is enabled in FW IB port index is different, and modifications have to be made in the following calculation */
        divider = (g_sai_db_ptr->breakout_mode_en && port->is_split == false) ? 2 : 1;
        /*
         *  When creating port we use 'module' not as module_port by PRM but as (ib_port - 1).
         *  It means each port (even in QTM2) has it's own module.
         *  in QTM and QTM2 module 0 will represent lanes [0 1 2 3]
         *               module 1 will represent lanes [4 5 6 7] etc
         *  In the following calculation we use this logic with the help of data from PRM
         */
        for (uint8_t i = 0; i < pmlp_reg.width; i++) {
            lanes[i] = (port->ib_port - 1) * pmlp_reg.width / divider + (pmlp_reg.lane[i] % pmlp_reg.width);
        }
        sai_status = mlnx_fill_u32list(lanes, pmlp_reg.width, &value->u32list);
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

/**
 * Function return port's HW lanes list.
 *
 * @param key        - sai port object
 * @param value      - value.u32list is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_hw_lanes_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t     sai_status;
    sx_port_log_id_t port_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_id, NULL))) {
        goto bail;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_port_hw_lanes_get(&port_id, value))) {
        SX_LOG_ERR("Error getting port hw lanes for port id %x\n", port_id);
        goto bail;
    }

bail:
    SX_LOG_EXIT();
    return sai_status;
}

/**
 * Function return port's supported breakout mode list.
 *
 * @param key        - sai port object
 * @param value      - value.u32list is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_supported_breakout_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    int32_t             modes[SAI_PORT_BREAKOUT_MODE_TYPE_MAX];
    sx_port_log_id_t    port_log_id;
    uint32_t            modes_num;
    sai_status_t        status;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_log_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();

    status = mlnx_port_by_log_id(port_log_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    modes[0] = SAI_PORT_BREAKOUT_MODE_TYPE_1_LANE;
    modes_num = 1;

    switch (port->breakout_modes) {
    case MLNX_PORT_BREAKOUT_CAPABILITY_NONE:
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_TWO:
        modes[1] = SAI_PORT_BREAKOUT_MODE_TYPE_2_LANE;
        modes_num = 2;
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_FOUR:
        modes[1] = SAI_PORT_BREAKOUT_MODE_TYPE_4_LANE;
        modes_num = 2;
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR:
        modes[1] = SAI_PORT_BREAKOUT_MODE_TYPE_2_LANE;
        modes[2] = SAI_PORT_BREAKOUT_MODE_TYPE_4_LANE;
        modes_num = 3;
        break;

    default:
        SX_LOG_ERR("Invalid breakout capability %d port %" PRIx64 "\n",
                   port->breakout_modes, key->key.object_id);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = mlnx_fill_s32list(modes, modes_num, &value->s32list);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's current breakout mode.
 *
 * @param key        - sai port object
 * @param value      - value.s32 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_current_breakout_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    sx_port_log_id_t    port_log_id;
    mlnx_port_config_t *port;
    sai_status_t        status;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_log_id, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    sai_db_read_lock();

    status = mlnx_port_by_log_id(port_log_id, &port);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    value->s32 = port->split_count;

out_unlock:
    sai_db_unlock();
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's supported speed list in mbps.
 * it get the  ib_proto_capability field from PTYS register . (this is all the speeds
 * that supported in that port).
 *
 * @param key        - sai port object
 * @param value      - value.u32list is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_supported_speed_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t     status;
    sx_port_log_id_t port_id;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_id, NULL))) {
        return status;
    }

    status = mlnx_port_supported_speeds_get_impl(port_id, &value->u32list);

    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's supported port FEC mode
 *
 * @param key        - sai port object
 * @param value      - value.s32list is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_supported_fec_mode_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    int32_t             modes[] = { SAI_PORT_FEC_MODE_AUTO, SAI_PORT_FEC_MODE_NONE, SAI_PORT_FEC_MODE_ON };
    sai_status_t        status;
    sx_port_log_id_t    port_id;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert port oid to logical port id\n");
        goto out;
    }

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup port by log id %x\n", port_id);
        goto out;
    }
    status = mlnx_fill_s32list(modes, sizeof(modes) / sizeof(modes[0]), &value->s32list);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's Operational speed in Mbps.
 *
 * @param key        - sai port object
 * @param value      - value.u32 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_oper_speed_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t     status;
    sx_port_log_id_t port_id;
    uint32_t         admin_speed;
    long             state_id;

    SX_LOG_ENTER();
    state_id = (long)arg;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_id, NULL))) {
        return status;
    }
    if (state_id == SAI_PORT_STAT_INFINIBAND_SPEED_OPER_BY_LANES) {
        status = mlnx_port_speed_by_width_get(port_id, &value->u32);
    } else {
        status = mlnx_port_speed_get_impl(port_id, &value->u32, &admin_speed);
    }

    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's attribute (SAI_PORT_ATTR_SPEED or SAI_PORT_ATTR_AUTO_NEG_MODE).
 *
 * @param key        - sai port object
 * @param value      - value.u32 or value.booldata is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - attribute to get (SAI_PORT_ATTR_SPEED or SAI_PORT_ATTR_AUTO_NEG_MODE)
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_attr_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    sai_status_t        status;
    mlnx_port_config_t *port;
    long                attr_id = (long)arg;
    uint32_t            speeds[MAX_NUM_PORT_SPEEDS] = {0}, speeds_count = MAX_NUM_PORT_SPEEDS;

    SX_LOG_ENTER();

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    switch (attr_id) {
    case SAI_PORT_ATTR_SPEED:
        value->u32 = port->speed;
        break;

    case SAI_PORT_ATTR_AUTO_NEG_MODE:
        value->booldata = true;
        break;

    case SAI_PORT_ATTR_ADVERTISED_SPEED:
        status = mlnx_port_cb->advertised_speeds_get(port, speeds, &speeds_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get advertised speeds for port ib %u.\n", port->ib_port);
            goto out;
        }
        status = mlnx_fill_u32list(port->adv_speeds, port->adv_speeds_num, &value->u32list);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to fill list.\n");
            goto out;
        }
        break;

    default:
        SX_LOG_ERR("Not supported attr_id: %ld\n", attr_id);
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function set port's attribute (SAI_PORT_ATTR_SPEED or SAI_PORT_ATTR_AUTO_NEG_MODE).
 *
 * @param key   - sai port object
 * @param value - value.u32 or value.booldata is the configured value.
 * @param arg   - attribute to configure (SAI_PORT_ATTR_SPEED or SAI_PORT_ATTR_AUTO_NEG_MODE)
 * @return      - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_attr_set(_In_ const sai_object_key_t      *key,
                                       _In_ const sai_attribute_value_t *value,
                                       void                             *arg)
{
    sai_status_t        status;
    sx_port_log_id_t    port_id;
    mlnx_port_config_t *port;
    long                attr_id = (long)arg;
    uint32_t            old_speed = 0;
    uint32_t            old_adv_speeds[MAX_PORT_ATTR_ADV_SPEEDS_NUM] = {0};
    uint32_t            old_adv_speeds_num = 0;
    bool                is_warmboot_init_stage = false;

    assert((SAI_PORT_ATTR_ADVERTISED_SPEED == attr_id) ||
           (SAI_PORT_ATTR_SPEED == attr_id) ||
           (SAI_PORT_ATTR_AUTO_NEG_MODE == attr_id));

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();

    is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup port by log id %x\n", port_id);
        goto out;
    }

    switch (attr_id) {
    case SAI_PORT_ATTR_SPEED:
        old_speed = port->speed;
        port->speed = value->u32;
        break;

    case SAI_PORT_ATTR_AUTO_NEG_MODE:
        port->auto_neg = AUTO_NEG_ENABLE;
        break;

    case SAI_PORT_ATTR_ADVERTISED_SPEED:
        old_adv_speeds_num = port->adv_speeds_num;
        for (uint32_t ii = 0; ii < old_adv_speeds_num; ++ii) {
            old_adv_speeds[ii] = port->adv_speeds[ii];
        }
        port->adv_speeds_num = value->u32list.count;
        for (uint32_t ii = 0; ii < port->adv_speeds_num; ++ii) {
            port->adv_speeds[ii] = value->u32list.list[ii];
        }
        break;

    default:
        SX_LOG_ERR("Not supported attr_id: %ld\n", attr_id);
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (!is_warmboot_init_stage) {
        status = mlnx_port_update_speed(port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update speed.\n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0;
            goto out;
        }
    }

out:
    if (SAI_ERR(status)) {
        if (port) {
            switch (attr_id) {
            case SAI_PORT_ATTR_SPEED:
                port->speed = old_speed;
                break;

            case SAI_PORT_ATTR_AUTO_NEG_MODE:
                port->auto_neg = AUTO_NEG_ENABLE;
                break;

            case SAI_PORT_ATTR_ADVERTISED_SPEED:
                port->adv_speeds_num = old_adv_speeds_num;
                for (uint32_t ii = 0; ii < port->adv_speeds_num; ++ii) {
                    port->adv_speeds[ii] = old_adv_speeds[ii];
                }
                break;

            default:
                break;
            }
        }
    }
    sai_db_unlock();
    return status;
}

/**
 * Function return port's speed offset - this is the index of the bitmap in the mlnx_port_speed_bitmap_ib
 * of the spesific speed. from this bitmap , we calculate the total speed bitmap and configure it in FW.
 *
 * @param speed  - speed in mbps.
 * @param offset - the speed index in the map (mlnx_port_speed_bitmap_ib).
 * @return       - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_sai_offset_get(_In_ uint32_t speed, _Out_ uint64_t *offset)
{
    assert(offset);
    switch (speed) {
    case PORT_SPEED_800:
        *offset = 12;
        break;

    case PORT_SPEED_400:
        *offset = 11;
        break;

    case PORT_SPEED_200:
        *offset = 10;
        break;

    case PORT_SPEED_100:
        *offset = 9;
        break;

    case PORT_SPEED_56:
        *offset = 8;
        break;

    case PORT_SPEED_50:
        *offset = 7;
        break;

    case PORT_SPEED_40:
        *offset = 6;
        break;

    case PORT_SPEED_25:
        *offset = 5;
        break;

    case PORT_SPEED_20:
        *offset = 4;
        break;

    case PORT_SPEED_10:
        *offset = 3;
        break;

    case PORT_SPEED_1:
        *offset = 2;
        break;

    case PORT_SPEED_100M:
        *offset = 1;
        break;

    case PORT_SPEED_0:
        *offset = 0;
        break;

    default:
        SX_LOG_ERR("Unsupported speed [%u].\n", speed);
        return SAI_STATUS_FAILURE;
    }
    return SAI_STATUS_SUCCESS;
}

/**
 * Function return port's speed bitmap from list of speeds in mbps.
 *
 * @param speeds     - list of speeds in mbps.
 * @param speeds_num - number of speeds.
 * @param bitmap     - the speeds bitmap to configure in FW.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_fill_speeds(_In_ uint32_t *speeds, _In_ uint32_t speeds_num, _Out_ uint64_t *bitmap)
{
    sai_status_t status;
    uint64_t     offset = 0;

    assert(bitmap);

    if (!speeds || (speeds_num == 0)) {
        for (int32_t ii = 0; ii < MAX_NUM_PORT_SPEEDS; ii++) {
            *bitmap |= mlnx_port_cb->speed_bitmap[ii];
        }
        return SAI_STATUS_SUCCESS;
    }

    for (uint32_t ii = 0; ii < speeds_num; ++ii) {
        status = mlnx_port_sai_offset_get(speeds[ii], &offset);
        if (SAI_ERR(status)) {
            return SAI_STATUS_FAILURE;
        }
        *bitmap |= mlnx_port_cb->speed_bitmap[offset];
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * Function return port's speed bitmap from list of speeds in mbps.
 *
 * @param speeds     - list of speeds in mbps.
 * @param speeds_num - number of speeds.
 * @param bitmap     - the speeds bitmap to configure in FW.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_speeds_merge(_In_ uint32_t *speeds, _In_ uint32_t speeds_num, _Out_ uint64_t *bitmap)
{
    sai_status_t status;

    *bitmap = 0;

    status = mlnx_port_fill_speeds(speeds, speeds_num, bitmap);
    if (SAI_ERR(status)) {
        return status;
    }

    return status;
}

typedef enum sys_ib_speed {
    /* These values are for marking the indexes of ALL speeds in the all_speeds_map array */
    SYS_IB_SPEED_SDR,                   /* !< SYS_IB_SPEED_SDR */
    SYS_IB_SPEED_DDR,                   /* !< SYS_IB_SPEED_DDR */
    SYS_IB_SPEED_QDR,                   /* !< SYS_IB_SPEED_QDR */
    SYS_IB_SPEED_FDR10,                 /* !< SYS_IB_SPEED_FDR10 */
    SYS_IB_SPEED_FDR,                   /* !< SYS_IB_SPEED_FDR */
    SYS_IB_SPEED_EDR,                   /* !< SYS_IB_SPEED_EDR */
    SYS_IB_SPEED_HDR,                   /* !< SYS_IB_SPEED_HDR */
    SYS_IB_SPEED_NDR,                   /* !< SYS_IB_SPEED_NDR */
    SYS_IB_SPEED_XDR,                   /* !< SYS_IB_SPEED_XDR */
    SYS_IB_SPEED_UNDEFINED,
} sys_ib_speed_t;

/**
 * Function update port speed in PTYS register.
 *
 * @param sx_port  - port id.
 * @param bitmap   - the speeds bitmap to configure in FW.
 * @return         - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_update_speed_ib(_In_ sx_port_log_id_t sx_port, _In_ uint64_t bitmap)
{
    mlnx_port_config_t *port;
    sai_status_t        status = SAI_STATUS_SUCCESS;
    struct ku_ptys_reg  ptys_reg;
    uint64_t            fdr10_mask = (1 << SYS_IB_SPEED_FDR10);

    if (SAI_STATUS_SUCCESS != (status = mlnx_port_by_log_id(sx_port, &port))) {
        MLNX_SAI_LOG_ERR("Failed get port by log id %x \n", sx_port);
        goto out;
    }

    memset(&ptys_reg, 0, sizeof(ptys_reg));
    ptys_reg.local_port = port->port_map.local_port;
    ptys_reg.proto_mask = REG_PTYS_PROTO_MASK_IB;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PTYS for local port: [%u], device: [%u], swid [%u]\n",
                         ptys_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }

    if (bitmap == fdr10_mask) {
        bitmap = (1 << SYS_IB_SPEED_QDR) | (1 << SYS_IB_SPEED_SDR);
    }
    ptys_reg.ib_proto_admin = ((ptys_reg.ib_proto_admin & 0xff00) | bitmap);
    ptys_reg.an_disable_admin = false;

    if ((0 == ptys_reg.ib_link_width_admin) || (0 == ptys_reg.ib_proto_admin)) {
        MLNX_SAI_LOG_ERR("Can not set PTYS with 0 speed or width."
                         "required speed:[%d], required width:[%d]",
                         ptys_reg.ib_proto_admin, ptys_reg.ib_link_width_admin);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    MLNX_SAI_LOG_NTC("Set PTYS register to ib port [%u], local port [%u], speed [%u], an_disable [%u]\n",
                     port->ib_port, port->port_map.local_port, ptys_reg.ib_proto_admin, false);

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_SET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PTYS for local port: [%u], speed: [%u]\n",
                         ptys_reg.local_port, ptys_reg.ib_proto_admin);
        goto out;
    }

out:
    return status;
}

/**
 * Function update port admin speed.
 *
 * @param port - port object (have the speeds to configure).
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_update_speed(_In_ mlnx_port_config_t *port)
{
    sai_status_t status;
    uint64_t     bitmap = 0;
    uint32_t    *speeds = 0;
    uint32_t     speeds_num = 0;

    assert(port);

    speeds = port->adv_speeds;
    speeds_num = port->adv_speeds_num;

    status = mlnx_port_speeds_merge(speeds, speeds_num, &bitmap);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to merge speeds \n");
        return status;
    }

    status = mlnx_port_cb->update_speed(port->logical, bitmap);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to apply speed bitmap [0x%" PRIx64 "] for port[0x%x].\n", bitmap, port->logical);
        return status;
    }

    return status;
}


/**
 * Function return port's mtu operational value by PMTU register.
 *
 * @param key        - sai port object
 * @param value      - value.u32 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_mtu_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_pmtu_reg  pmtu_reg;

    SX_LOG_ENTER();

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&pmtu_reg, 0, sizeof(struct ku_pmtu_reg));
    pmtu_reg.local_port = port->port_map.local_port;
    ;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pmtu_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pmtu_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PMTU for local port: [%u], device: [%u], swid [%u]\n",
                         pmtu_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }
    value->u32 = pmtu_reg.oper_mtu;
    MLNX_SAI_LOG_DBG("Get PMTU reg - label port [%u], local port [%u], oper_mtu [%u]\n",
                     port->ib_port, port->port_map.local_port, pmtu_reg.oper_mtu);
out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's mtu max value by PMTU register.
 *
 * @param key        - sai port object
 * @param value      - value.u32 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_max_mtu_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_pmtu_reg  pmtu_reg;

    SX_LOG_ENTER();

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&pmtu_reg, 0, sizeof(struct ku_pmtu_reg));
    pmtu_reg.local_port = port->port_map.local_port;
    ;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pmtu_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pmtu_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PMTU for local port: [%u], device: [%u], swid [%u]\n",
                         pmtu_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }
    MLNX_SAI_LOG_DBG("Get PMTU reg - label port [%u], local port [%u], max_mtu [%u]\n",
                     port->ib_port, port->port_map.local_port, pmtu_reg.max_mtu);
    value->u32 = pmtu_reg.max_mtu;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's fec value by PPLM register (fec_mode_active).
 * return value is sai_port_fec_mode_t.
 *
 * @param key        - sai port object
 * @param value      - value.u32 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_fec_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_pplm_reg  pplm_reg;

    SX_LOG_ENTER();

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&pplm_reg, 0, sizeof(struct ku_pplm_reg));
    pplm_reg.local_port = port->port_map.local_port;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pplm_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pplm_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PPLM for local port: [%u], device: [%u], swid [%u]\n",
                         pplm_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }
    MLNX_SAI_LOG_DBG("Get PPLM reg - label port [%u], local port [%u], fec_mode_active [%u]\n",
                     port->ib_port, port->port_map.local_port, pplm_reg.fec_mode_active);
    switch (pplm_reg.fec_mode_active) {
    case ERR_CORRECTION_STATUS_NONE_FEC:
    case ERR_CORRECTION_STATUS_NO_FEC:
        value->s32 = SAI_PORT_FEC_MODE_NONE;
        break;

    case ERR_CORRECTION_STATUS_FIRECODE_FEC:
    case ERR_CORRECTION_STATUS_RS_FEC:
    case ERR_CORRECTION_STATUS_LL_RS_FEC:
    case ERR_CORRECTION_STATUS_MLNX_RS_FEC:
    case ERR_CORRECTION_STATUS_MLNX_LL_RS_FEC:
    case ERR_CORRECTION_STATUS_RS_544_514_FEC:
    case ERR_CORRECTION_STATUS_ZL_FEC:
    case ERR_CORRECTION_STATUS_RS_PLR_FEC:
    case ERR_CORRECTION_STATUS_LL_PLR_FEC:
    case ERR_CORRECTION_STATUS_ETH_LL_PLR:
        value->s32 = SAI_PORT_FEC_MODE_ON;
        break;

    default:
        SX_LOG_ERR("Invalid fec mode %u\n", pplm_reg.fec_mode_active);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's key as string.
 *
 * @param port_id - sai port id
 * @param key_str - returned value as a string.
 */
static void port_key_to_str(_In_ sai_object_id_t port_id, _Out_ char *key_str)
{
    char        *type_str = "port";
    sai_status_t status;
    uint32_t     port;

    status = mlnx_object_to_log_port(port_id, &port);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid port");
        return;
    }

    snprintf(key_str, MAX_KEY_STR_LEN, "%s %x", type_str, port);
}


/*
 * Routine Description:
 *   Set port attribute value.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_port_attribute(_In_ sai_object_id_t port_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = port_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();

    port_key_to_str(port_id, key_str);
    sai_status = sai_set_attribute(&key, key_str,  SAI_OBJECT_TYPE_PORT, port_vendor_attribs, attr);
    if (sai_status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed set port attribute key %s\n", key_str);
    }
    SX_LOG_EXIT();
    return sai_status;
}

/*
 * Routine Description:
 *   Get port attribute value.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_port_attribute(_In_ sai_object_id_t     port_id,
                                            _In_ uint32_t            attr_count,
                                            _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = port_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();

    port_key_to_str(port_id, key_str);
    sai_status = sai_get_attributes(&key, key_str,  SAI_OBJECT_TYPE_PORT, port_vendor_attribs, attr_count, attr_list);
    if (sai_status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed get port attribute key %s\n", key_str);
    }
    SX_LOG_EXIT();
    return sai_status;
}

/**
 * @brief Get port statistics counters extended.
 *
 * @param[in] port_id Port id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t mlnx_get_port_stats_ext(_In_ sai_object_id_t      port_id,
                                     _In_ uint32_t             number_of_counters,
                                     _In_ const sai_stat_id_t *counter_ids,
                                     _In_ sai_stats_mode_t     mode,
                                     _Out_ uint64_t           *counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/*
 * Routine Description:
 *   Get port statistics counters.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] number_of_counters - number of counters in the array
 *    [in] counter_ids - specifies the array of counter ids
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_port_stats(_In_ sai_object_id_t      port_id,
                                        _In_ uint32_t             number_of_counters,
                                        _In_ const sai_stat_id_t *counter_ids,
                                        _Out_ uint64_t           *counters)
{
    sai_status_t        status = SAI_STATUS_FAILURE;
    char                key_str[MAX_KEY_STR_LEN];
    mlnx_port_config_t *port = NULL;
    bool                require_port_state = false;
    bool                require_port_counters = false;

    SX_LOG_ENTER();

    port_key_to_str(port_id, key_str);
    SX_LOG_DBG("Get port stats %s\n", key_str);

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL stats ids array param.\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == counters) {
        SX_LOG_ERR("NULL stats array param.\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (0 == number_of_counters) {
        SX_LOG_ERR("Empty stats ids param (number_of_counters is 0).\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(port_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", port_id);
        goto out;
    }

    for (uint32_t ii = 0; ii < number_of_counters; ii++) {
        if (mlnx_port_is_ib_state_stat(counter_ids[ii])) {
            require_port_state = true;
        } else if (mlnx_port_is_ib_counter_stat(counter_ids[ii])) {
            require_port_counters = true;
        } else {
            SX_LOG_ERR("Unexpected port stat-id %d.\n", (int)counter_ids[ii]);
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
    }

    if (require_port_state) {
        status = mlnx_port_states_get(port, number_of_counters, counter_ids, counters);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to get port states %" PRIx64 " , ib port %u \n", port_id, port->ib_port);
        }
    }
    if (require_port_counters) {
        if (port->ib_port == 0) {
            /* Reading counters from IB port 0 is not possible */
            memset(&counters, 0, sizeof(counters[0]) * number_of_counters);
            status = SAI_STATUS_SUCCESS;
            goto out;
        }
        status = mlnx_port_counters_get(port, number_of_counters, counter_ids, counters);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to get port counters %" PRIx64 " , ib port %u \n", port_id, port->ib_port);
        }
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *   Clear port statistics counters.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] number_of_counters - number of counters in the array
 *    [in] counter_ids - specifies the array of counter ids
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_clear_port_stats(_In_ sai_object_id_t      port_id,
                                          _In_ uint32_t             number_of_counters,
                                          _In_ const sai_stat_id_t *counter_ids)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/*
 * Routine Description:
 *   Clear port's all statistics counters.
 *
 * Arguments:
 *    [in] port_id - port id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_clear_port_all_stats(_In_ sai_object_id_t port_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Set port log level.
 *
 * @param level - log level.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t mlnx_port_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_port_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

/*
 * Get index of port configuration in port db
 *
 * Arguments:
 *    [in]  log_port_id - logical port id
 *    [out] index       - index of the port in db
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
/* DB read lock is needed */
sai_status_t mlnx_port_idx_by_log_id(sx_port_log_id_t log_port_id, uint32_t *index)
{
    mlnx_port_config_t *port;
    uint32_t            ii = 0;

    assert(index != NULL);

    mlnx_port_foreach(port, ii) {
        if (log_port_id == port->logical) {
            *index = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Port index not found in DB by log id 0x%x\n", log_port_id);
    return SAI_STATUS_INVALID_PORT_NUMBER;
}

/*
 * Get port object in port db by log id.
 *
 * Arguments:
 *    [in]  log_id - logical port id
 *    [out] port   - port object in db
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
/* DB read lock is needed */
sai_status_t mlnx_port_by_log_id_soft(sx_port_log_id_t log_id, mlnx_port_config_t **port)
{
    mlnx_port_config_t *port_cfg;
    uint32_t            ii;

    assert(port != NULL);

    mlnx_port_foreach(port_cfg, ii) {
        if (port_cfg->logical == log_id) {
            *port = port_cfg;
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_INVALID_PORT_NUMBER;
}

/*
 * Get port object in port db by log id.
 *
 * Arguments:
 *    [in]  log_id - logical port id
 *    [out] port   - port object in db
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
/* DB read lock is needed */
sai_status_t mlnx_port_by_log_id(sx_port_log_id_t log_id, mlnx_port_config_t **port)
{
    sai_status_t status;

    status = mlnx_port_by_log_id_soft(log_id, port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed lookup port config by log id 0x%x\n", log_id);
    }

    return status;
}

/*
 * Get port object in port db by object id.
 *
 * Arguments:
 *    [in]  obj_id - port object id
 *    [out] port   - port object in db
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
/* DB read lock is needed */
sai_status_t mlnx_port_by_obj_id(sai_object_id_t obj_id, mlnx_port_config_t **port)
{
    mlnx_port_config_t *port_cfg;
    uint32_t            ii;

    assert(port != NULL);

    mlnx_port_foreach(port_cfg, ii) {
        if (port_cfg->saiport == obj_id) {
            *port = port_cfg;
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Failed lookup port config by object id %" PRIx64 "\n", obj_id);
    return SAI_STATUS_INVALID_PORT_NUMBER;
}

/**
 * @brief Get if port is phy or not by port logical id
 *
 * @param[in] port Port object
 *
 * @return true if port is phy, else false.
 */
bool mlnx_port_is_phy(const mlnx_port_config_t *port)
{
    return SX_PORT_TYPE_ID_GET(port->logical) == SX_PORT_TYPE_NETWORK;
}

/**
 * @brief Get port from DB by index
 *
 * @param[in] id Port id
 *
 * @return port object from the port DB.
 */
mlnx_port_config_t * mlnx_port_by_idx(uint16_t id)
{
    uint32_t db_len = sizeof(mlnx_ports_db) / sizeof(mlnx_ports_db[0]);

    if (id >= db_len) {
        MLNX_SAI_LOG_ERR("Failed get port by index %u. valid index < %u \n", id, db_len);
        return NULL;
    }
    return &mlnx_ports_db[id];
}

/**
 * @brief Get port from DB by local id
 *
 * @param[in] local_port Port local id
 *
 * @return port object from the port DB.
 */
mlnx_port_config_t * mlnx_port_by_local_id(uint16_t local_port)
{
    mlnx_port_config_t *port;
    uint32_t            ii;

    for (ii = 0; ii < MAX_LOGICAL_PORTS; ii++) {
        port = &mlnx_ports_db[ii];

        if (port->port_map.local_port == local_port) {
            return port;
        }
    }

    assert(false);
    return NULL;
}

/**
 * Function return port's speeds in mbps and speeds count by speeds bitmap.
 *
 * @param speed_bitmap - speeds bitmap.
 * @param speeds       - list of speeds in mbps return value.
 * @param speeds_count - number of speeds return value.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_speed_bitmap_to_speeds(_In_ uint32_t     speed_bitmap,
                                                     _Out_ uint32_t   *speeds,
                                                     _Inout_ uint32_t *speeds_count)
{
    uint32_t speeds_count_tmp = 0;

    assert(speed_bitmap);
    assert(speeds);
    assert(speeds_count && (*speeds_count >= MAX_NUM_PORT_SPEEDS));

    if (speed_bitmap & 1 << 8) {
        speeds[speeds_count_tmp++] = PORT_SPEED_800;
    }

    if (speed_bitmap & 1 << 7) {
        speeds[speeds_count_tmp++] = PORT_SPEED_400;
    }

    if (speed_bitmap & 1 << 6) {
        speeds[speeds_count_tmp++] = PORT_SPEED_200;
    }

    if (speed_bitmap & 1 << 5) {
        speeds[speeds_count_tmp++] = PORT_SPEED_100;
    }

    if (speed_bitmap & 1 << 4) {
        speeds[speeds_count_tmp++] = PORT_SPEED_56;
    }

    if (speed_bitmap & 1 << 2) {
        speeds[speeds_count_tmp++] = PORT_SPEED_40;
    }

    if (speed_bitmap & 1 << 1) {
        speeds[speeds_count_tmp++] = PORT_SPEED_20;
    }

    if (speed_bitmap & 1 << 0) {
        speeds[speeds_count_tmp++] = PORT_SPEED_10;
    }

    *speeds_count = speeds_count_tmp;

    return SAI_STATUS_SUCCESS;
}

/**
 * Function return port's speeds in mbps and speeds count by speeds bitmap.
 *
 * @param speed_bitmap - speeds bitmap.
 * @param oper_width   - port operational width.
 * @param speeds       - list of speeds in mbps return value.
 * @param speeds_count - number of speeds return value.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_oper_speed_bitmap_to_speeds(_In_ uint32_t     speed_bitmap,
                                                          _In_ uint16_t     oper_width,
                                                          _Out_ uint32_t   *speeds,
                                                          _Inout_ uint32_t *speeds_count)
{
    uint32_t speeds_count_tmp = 0;

    assert(speed_bitmap);
    assert(speeds);
    assert(speeds_count && (*speeds_count >= MAX_NUM_PORT_SPEEDS));

    if (speed_bitmap & 1 << 8) {
        speeds[speeds_count_tmp++] = PORT_SPEED_XDR * oper_width;
    }

    if (speed_bitmap & 1 << 7) {
        speeds[speeds_count_tmp++] = PORT_SPEED_NDR * oper_width;
    }

    if (speed_bitmap & 1 << 6) {
        speeds[speeds_count_tmp++] = PORT_SPEED_HDR * oper_width;
    }

    if (speed_bitmap & 1 << 5) {
        speeds[speeds_count_tmp++] = PORT_SPEED_EDR * oper_width;
    }

    if (speed_bitmap & 1 << 4) {
        speeds[speeds_count_tmp++] = PORT_SPEED_FDR * oper_width;
    }

    if (speed_bitmap & 1 << 2) {
        speeds[speeds_count_tmp++] = PORT_SPEED_QDR * oper_width;
    }

    if (speed_bitmap & 1 << 1) {
        speeds[speeds_count_tmp++] = PORT_SPEED_DDR * oper_width;
    }

    if (speed_bitmap & 1 << 0) {
        speeds[speeds_count_tmp++] = PORT_SPEED_SDR * oper_width;
    }

    *speeds_count = speeds_count_tmp;

    return SAI_STATUS_SUCCESS;
}

/**
 * Function return port's operational speed by PTYS register.
 * The speed will be calculated according to port oper width.
 *
 * @param sx_port     - port log id.
 * @param oper_speed  - return operational speed in mbps.
 * @return            - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_speed_by_width_get(_In_ sx_port_log_id_t sx_port, _Out_ uint32_t       *oper_speed)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    uint32_t            speeds[MAX_NUM_PORT_SPEEDS] = {0}, speeds_count = MAX_NUM_PORT_SPEEDS;
    uint16_t            speed_bitmask = 0;
    mlnx_port_config_t *port;
    struct ku_ptys_reg  ptys_reg;

    if (!oper_speed) {
        status = SAI_STATUS_INVALID_PARAMETER;
        return status;
    }

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS != (status = mlnx_port_by_log_id(sx_port, &port))) {
        MLNX_SAI_LOG_ERR("Failed get port by log id %x\n", sx_port);
        goto out;
    }

    memset(&ptys_reg, 0, sizeof(ptys_reg));
    ptys_reg.local_port = port->port_map.local_port;
    ptys_reg.proto_mask = REG_PTYS_PROTO_MASK_IB;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PTYS for local port: [%u], ib port: [%u]\n", ptys_reg.local_port, port->ib_port);
        goto out;
    }

    speed_bitmask = (u_int16_t)(BASE_SPEED & ptys_reg.ib_proto_oper);
    if (speed_bitmask &&
        (SAI_STATUS_SUCCESS !=
         (status =
              mlnx_port_oper_speed_bitmap_to_speeds(speed_bitmask, ptys_reg.ib_link_width_oper, speeds,
                                                    &speeds_count)))) {
        MLNX_SAI_LOG_ERR("Failed to map oper speed bitmask to speed %u\n", speed_bitmask);
        goto out;
    }
    if (speeds_count == 0) {
        /* After warm boot, without explicit call to set speed, SDK returns empty bitmask, and this is valid */
        *oper_speed = PORT_SPEED_0;
    } else {
        *oper_speed = speeds[0];
    }
out:
    sai_db_unlock();
    return status;
}

/**
 * Function return port's operational & admin speed by PTYS register.
 *
 * @param sx_port     - port log id.
 * @param oper_speed  - return operational speed in mbps.
 * @param admin_speed - return admin speed in mbps.
 * @return            - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_speed_get_ib(_In_ sx_port_log_id_t sx_port,
                                           _Out_ uint32_t       *oper_speed,
                                           _Out_ uint32_t       *admin_speed)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    uint32_t            speeds[MAX_NUM_PORT_SPEEDS] = {0}, speeds_count = MAX_NUM_PORT_SPEEDS;
    uint16_t            speed_bitmask = 0;
    mlnx_port_config_t *port;
    struct ku_ptys_reg  ptys_reg;

    if (!oper_speed || !admin_speed) {
        status = SAI_STATUS_INVALID_PARAMETER;
        return status;
    }

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS != (status = mlnx_port_by_log_id(sx_port, &port))) {
        MLNX_SAI_LOG_ERR("Failed get port by log id %x\n", sx_port);
        goto out;
    }

    memset(&ptys_reg, 0, sizeof(ptys_reg));
    ptys_reg.local_port = port->port_map.local_port;
    ptys_reg.proto_mask = REG_PTYS_PROTO_MASK_IB;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PTYS for local port: [%u], ib port: [%u]\n", ptys_reg.local_port, port->ib_port);
        goto out;
    }

    speed_bitmask = (u_int16_t)(BASE_SPEED & ptys_reg.ib_proto_admin);
    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_port_speed_bitmap_to_speeds(speed_bitmask, speeds, &speeds_count))) {
        MLNX_SAI_LOG_ERR("Failed to map admin speed bitmask to speed %u\n", speed_bitmask);
        goto out;
    }
    if (speeds_count == 0) {
        /* After warm boot, without explicit call to set speed, SDK returns empty bitmask, and this is valid */
        *admin_speed = PORT_SPEED_0;
    } else {
        *admin_speed = speeds[0];
    }
    memset(speeds, 0, sizeof(speeds));
    speeds_count = MAX_NUM_PORT_SPEEDS;
    speed_bitmask = (u_int16_t)(BASE_SPEED & ptys_reg.ib_proto_oper);
    if (speed_bitmask &&
        (SAI_STATUS_SUCCESS !=
         (status =
              mlnx_port_speed_bitmap_to_speeds(speed_bitmask, speeds,
                                               &speeds_count)))) {
        MLNX_SAI_LOG_ERR("Failed to map oper speed bitmask to speed %u\n", speed_bitmask);
        goto out;
    }
    if (speeds_count == 0) {
        /* After warm boot, without explicit call to set speed, SDK returns empty bitmask, and this is valid */
        *oper_speed = PORT_SPEED_0;
    } else {
        *oper_speed = speeds[0];
    }
out:
    sai_db_unlock();
    return status;
}

/**
 * Function return port's supported speeds by PTYS register.
 *
 * @param sx_port      - port log id.
 * @param speeds       - return list of supported speeds in mbps.
 * @param speeds_count - return supported speeds amount.
 * @return             - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_supported_speeds_get_ib(_In_ sx_port_log_id_t sx_port,
                                                      _Out_ uint32_t       *speeds,
                                                      _Inout_ uint32_t     *speeds_count)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    uint32_t            speed_capa;
    struct ku_ptys_reg  ptys_reg;

    assert(speeds);
    assert(speeds_count);
    memset(&ptys_reg, 0, sizeof(ptys_reg));

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS != (status = mlnx_port_by_log_id(sx_port, &port))) {
        MLNX_SAI_LOG_ERR("Failed get port by log id %x\n", sx_port);
        goto out;
    }

    ptys_reg.local_port = port->port_map.local_port;
    ptys_reg.proto_mask = REG_PTYS_PROTO_MASK_IB;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PTYS for local port: [%u], ib port: [%u]\n", ptys_reg.local_port, port->ib_port);
        goto out;
    }

    speed_capa = (uint32_t)(BASE_SPEED & ptys_reg.ib_proto_capability);
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_speed_bitmap_to_speeds(speed_capa, speeds, speeds_count))) {
        MLNX_SAI_LOG_ERR("Failed map speed capability bitmask to list: %u\n", speed_capa);
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}


/**
 * Function return port's admin speeds by PTYS register.
 *
 * @param sx_port      - port log id.
 * @param speeds       - return list of admin speeds in mbps.
 * @param speeds_count - return supported speeds amount.
 * @return             - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_advertised_speeds_get_ib(_In_ mlnx_port_config_t *port,
                                                       _Out_ uint32_t          *speeds,
                                                       _Inout_ uint32_t        *speeds_count)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    uint32_t           adv_speeds;
    struct ku_ptys_reg ptys_reg;

    assert(speeds);
    assert(speeds_count);
    memset(&ptys_reg, 0, sizeof(ptys_reg));

    ptys_reg.local_port = port->port_map.local_port;
    ptys_reg.proto_mask = REG_PTYS_PROTO_MASK_IB;
    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PTYS for local port: [%u], ib port: [%u]\n", ptys_reg.local_port, port->ib_port);
        goto out;
    }

    adv_speeds = (uint32_t)(BASE_SPEED & ptys_reg.ib_proto_admin);
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_speed_bitmap_to_speeds(adv_speeds, speeds, speeds_count))) {
        MLNX_SAI_LOG_ERR("Failed map speed capability bitmask to list: %u\n", adv_speeds);
        goto out;
    }
    port->adv_speeds_num = *speeds_count;
    for (uint32_t ii = 0; ii < *speeds_count; ++ii) {
        port->adv_speeds[ii] = speeds[ii];
    }

out:
    return status;
}

/**
 * Function return the callback port table (have all the functions that config speed...)
 *
 * @return - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_cb_table_init(void)
{
    mlnx_port_cb = &mlnx_port_cb_ib;

    return SAI_STATUS_SUCCESS;
}

/**
 * Function return port's operational & admin speed by calling the port callback table.
 *
 * @param sx_port     - port log id.
 * @param oper_speed  - return operational speed in mbps.
 * @param admin_speed - return admin speed in mbps.
 * @return            - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_speed_get_impl(_In_ sx_port_log_id_t sx_port,
                                             _Out_ uint32_t       *oper_speed,
                                             _Out_ uint32_t       *admin_speed)
{
    assert(mlnx_port_cb);

    return mlnx_port_cb->speed_get(sx_port, oper_speed, admin_speed);
}

/**
 * Function return port's supported speeds by calling the port callback table.
 *
 * @param sx_port - port log id.
 * @param list    - return list of supported speeds in mbps.
 * @return        - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_supported_speeds_get_impl(_In_ sx_port_log_id_t sx_port, _Inout_ sai_u32_list_t *list)
{
    sai_status_t status;
    uint32_t     speeds[MAX_NUM_PORT_SPEEDS] = {0}, speeds_count = MAX_NUM_PORT_SPEEDS;

    assert(list);
    assert(mlnx_port_cb);

    status = mlnx_port_cb->supported_speeds_get(sx_port, speeds, &speeds_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return mlnx_fill_u32list(speeds, speeds_count, list);
}

/**
 * Function initialize port mandatory after creation (configure swid to the port).
 *
 * @param port - port object.
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_config_init_mandatory(mlnx_port_config_t *port)
{
    sai_status_t status;
    const bool   is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);

    assert(port != NULL);

    /* Configure regular (network) port type only */
    if (mlnx_port_is_phy(port)) {
        if (!is_warmboot_init_stage) {
            status = sx_api_port_swid_bind_set(gh_sdk, port->logical, port->swid_id);
            if (SX_ERR(status)) {
                SX_LOG_ERR("Port swid %u bind %x failed - %s\n", port->swid_id, port->logical, SX_STATUS_MSG(status));
                return sdk_to_sai(status);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * Function initialize port - config port as present.
 *
 * @param port - port object.
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_config_init(mlnx_port_config_t *port)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    assert(port != NULL);
    port->is_present = true;
    return status;
}

/** Function initialize port data from PLLP. required when new port is created
 *
 * @param port - port object.
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_data_init(mlnx_port_config_t *port)
{
    return mlnx_get_default_label_port_from_local_port(port);
}

/**
 * Function add port - config port.
 *
 * @param port - port object.
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_add(mlnx_port_config_t *port)
{
    sai_status_t status;
    const bool   is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);

    assert(port != NULL);
    if (!is_warmboot_init_stage) {
        status = mlnx_port_config_init_mandatory(port);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    status = mlnx_port_config_init(port);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_port_data_init(port);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * Function set port's hw lanes by PMLP register.we do it when we create/remove port. (in split its necessary)
 *
 * @param port_map    - port mapping object (have the width, module of the port).
 * @param lanes_count - number of port's lanes.
 * @param port     - the port(have the swid, label_index and split_index).
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_port_hw_lanes_set(sx_port_mapping_t * port_map,
                                               uint32_t            lanes_count,
                                               mlnx_port_config_t* port)
{
    /*
     * port_max_lanes: indicates the maximum value of lanes per port.
     * label_idx: label index per ASIC. 1 for non-gorilla systems and first label index (like 1/1) in gorilla. 2 for seconds in label index in gorilla.
     * split_index: 1 for unsplit device and for first subport on splitted devices. 2 for second subport on splitted devices.
     * split_base: if we set 4x port, base is  0. Otherwise, we set 2x port, therefore we have 2 options: master (split_index = 1, lower HW lanes) or slave (split_index  = 2, higher HW lanes).
     * port_base: 4x base calculated by label index and 4x lanes.
     * num_base: finial calculation based on port base (4x) and split base (2x).
     *
     * Remainder: HW lanes are associated per Module, therefore in gorilla (where module includes 2 4x ports), we will have 8 HW lanes numbered from 0 to 7.
     * Port examples:
     * 1. Local port 125 (2x):
     *      port_max_lanes = 4, label_idx = 0, split_index = 1, split_base = 0, port_base = 0, num_base = 0
     * 2. Local port 126 (2x):
     *      port_max_lanes = 4, label_idx = 0, split_index = 2, split_base = 2, port_base = 0, num_base = 2
     * 3. Local port 127 (2x):
     *      port_max_lanes = 4, label_idx = 1, split_index = 1, split_base = 0, port_base = 4, num_base = 4
     * 4. Local port 128 (2x):
     *      port_max_lanes = 4, label_idx = 1, split_index = 2, split_base = 2, port_base = 4, num_base = 6
     * 5. Local port 125 (4x):
     *      port_max_lanes = 4, label_idx = 0, split_index = 1, split_base = 0, port_base = 0, num_base = 0
     * 6. Local port 127 (4x):
     *      port_max_lanes = 4, label_idx = 1, split_index = 1, split_base = 0, port_base = 4, num_base = 4
     */
    sai_status_t       sai_status;
    struct ku_pmlp_reg pmlp_reg;
    uint8_t            i;
    uint32_t           port_max_lanes = mlnx_port_max_lanes_get();
    uint8_t            label_idx = (mlnx_chip_is_qtm()) ? port->label_index : (port->label_index - 1);
    uint8_t            split_base =
        (port_max_lanes == lanes_count) ? 0 : ((port_max_lanes / 2) * (port->split_index - 1));
    uint8_t port_base = port_max_lanes * label_idx;
    uint8_t base_num = port_base + split_base;

    assert(port_map != NULL);
    memset(&pmlp_reg, 0, sizeof(struct ku_pmlp_reg));
    pmlp_reg.local_port = port_map->local_port;
    pmlp_reg.width = port_map->width;

    for (i = 0; i < lanes_count; i++) {
        pmlp_reg.module[i] = port_map->module_port;
        pmlp_reg.lane[i] = base_num + i;
    }
    MLNX_SAI_LOG_DBG(
        "Setting PMLP reg auto split %u lane [%u %u %u %u %u %u %u %u] "
        "local port %u module [%u %u %u %u %u %u %u %u] rx lane [%u %u %u %u %u %u %u %u]"
        "slot [%u %u %u %u %u %u %u %u] use different %u width %u",
        pmlp_reg.autosplit,
        pmlp_reg.lane[0],
        pmlp_reg.lane[1],
        pmlp_reg.lane[2],
        pmlp_reg.lane[3],
        pmlp_reg.lane[4],
        pmlp_reg.lane[5],
        pmlp_reg.lane[6],
        pmlp_reg.lane[7],
        pmlp_reg.local_port,
        pmlp_reg.module[0],
        pmlp_reg.module[1],
        pmlp_reg.module[2],
        pmlp_reg.module[3],
        pmlp_reg.module[4],
        pmlp_reg.module[5],
        pmlp_reg.module[6],
        pmlp_reg.module[7],
        pmlp_reg.rx_lane[0],
        pmlp_reg.rx_lane[1],
        pmlp_reg.rx_lane[2],
        pmlp_reg.rx_lane[3],
        pmlp_reg.rx_lane[4],
        pmlp_reg.rx_lane[5],
        pmlp_reg.rx_lane[6],
        pmlp_reg.rx_lane[7],
        pmlp_reg.slot[0],
        pmlp_reg.slot[1],
        pmlp_reg.slot[2],
        pmlp_reg.slot[3],
        pmlp_reg.slot[4],
        pmlp_reg.slot[5],
        pmlp_reg.slot[6],
        pmlp_reg.slot[7],
        pmlp_reg.use_different_rx_tx,
        pmlp_reg.width);

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_set_get_pmlp_register(SXD_ACCESS_CMD_SET,
                                                                       port->swid_id,
                                                                       g_device_id,
                                                                       NULL,
                                                                       NULL,
                                                                       &pmlp_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PMLP for local port: [%u], device: [%u], swid [%u]\n",
                         port_map->local_port, g_device_id, port->swid_id);
    }

    return sai_status;
}

/**
 * Function uninit port - remove port's swid, config 0 lanes.
 *
 * @param port - port object.
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_config_uninit(mlnx_port_config_t *port)
{
    sx_port_mapping_t port_map;
    sai_status_t      status;
    sx_status_t       sx_status;
    const bool        is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);

    /** When switch is raised we create all ports without init them and binding to swid to be synced with FW.
    * FW loads data from INI file to several register as PMLP.
    *  If user wants to create 2X ports at the beginning of the world it needs to reset PMLP values first. */
    if (mlnx_port_is_phy(port)) {
        if (!is_warmboot_init_stage) {
            sx_status = sx_api_port_deinit_set(gh_sdk, port->logical);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Port de-init set %x failed - %s\n", port->logical, SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
            sx_status = sx_api_port_swid_bind_set(gh_sdk, port->logical, SX_SWID_ID_DISABLED);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Port swid unbind %x failed - %s\n", port->logical, SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
        }

        memset(&port_map, 0, sizeof(port_map));
        port_map.mapping_mode = SX_PORT_MAPPING_MODE_DISABLE;
        port_map.local_port = port->port_map.local_port;
        port_map.module_port = port->module;
        port_map.lane_bmap = 0x0;

        if (!is_warmboot_init_stage) {
            status = mlnx_sai_port_hw_lanes_set(&port_map, 0, port);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Set disable port mapping- local port %x failed\n", port->port_map.local_port);
                goto out;
            }
        }
    }
    port->is_present = false;
    status = SAI_STATUS_SUCCESS;

out:
    return status;
}

/**
 * Function delete port - set admin state down.
 *
 * @param port - port object.
 * @return     - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_del(mlnx_port_config_t *port)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    const bool   is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);

    if (!is_warmboot_init_stage && (SAI_STATUS_SUCCESS !=
                                    (status =
                                         mlnx_set_port_state_admin(port->swid_id,
                                                                   g_device_id,
                                                                   port->port_map.
                                                                   local_port,
                                                                   false)))) {
        MLNX_SAI_LOG_ERR("Set port %x down failed.\n", port->logical);
    }

    status = mlnx_port_config_uninit(port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed un-init port %x\n", port->logical);
    }

    return status;
}

/**
 * Function return port's module by the lane (lane / max lanes)
 *
 * @param lane - port's lane.
 * @return     - port's module.
 */
static inline uint32_t lane2module(uint32_t lane)
{
    return lane / mlnx_port_max_lanes_get();
}

/**
 * Function return port's py lane for by lane  : lane - (lane / max lanes) * max_lanes
 *
 * @param lane - port's lane.
 * @return     - port's py lane.
 */
static inline uint32_t sai_lane2phy_lane(uint32_t lane)
{
    return (lane - lane2module(lane) * mlnx_port_max_lanes_get());
}

/**
 * Function return port object in db by port's ib label.
 *
 * @param module - port's module.
 * @return     - port object in db.
 */
static mlnx_port_config_t * mlnx_port_by_ib_label(uint32_t module)
{
    mlnx_port_config_t *port;
    uint32_t            ii;
    uint32_t            ib_port;

    if (g_sai_db_ptr->breakout_mode_en) {
        ib_port = 2 * (module + 1) - 1;
    } else {
        ib_port = module + 1;
    }

    mlnx_port_local_foreach(port, ii) {
        if (port->width && (port->ib_port == ib_port)) {
            return port;
        }
    }

    return NULL;
}

/* TODO: replace with cap_num_local_ports_in_2x when available */
static uint32_t mlnx_platform_num_local_ports_in_2x_get(void)
{
    return 1;
}

/* TODO: replace with cap_num_local_ports_in_4x when available */
static uint32_t mlnx_platform_num_local_ports_in_4x_get(void)
{
    return 2;
}

/* module -> port local idx
 * IB : (1, 2) / (1, 2, 3, 4) / (3, 4)
 */
static mlnx_port_config_t * mlnx_port_split_idx_to_local_port(_In_ const mlnx_port_config_t *father,
                                                              _In_ uint32_t                  base_lane_idx,
                                                              _In_ uint32_t                  lane_count)
{
    uint32_t step;

    if (lane_count == 2) {
        step = mlnx_platform_num_local_ports_in_2x_get();
    } else if (lane_count == 4) {
        step = mlnx_platform_num_local_ports_in_4x_get();
    } else {
        step = 1;
    }

    if ((father->port_map.local_port + base_lane_idx * step) > MAX_PORTS) {
        SX_LOG_ERR("Failed to find a port by local port %u\n", father->port_map.local_port + base_lane_idx * step);
        SX_LOG_ERR("Local port = father local port %u + base lane index %u * step %u \n",
                   father->port_map.local_port, base_lane_idx, step);
        return NULL;
    }

    return mlnx_port_by_local_id(father->port_map.local_port + base_lane_idx * step);
}

static mlnx_port_config_t * sai_lane2child_port(mlnx_port_config_t *father, const sai_u32_list_t *lanes)
{
    uint32_t new_port_idx = sai_lane2phy_lane(lanes->list[0]) / lanes->count;

    return mlnx_port_split_idx_to_local_port(father, new_port_idx, lanes->count);
}

static sai_status_t check_lanes_limitations(_In_ sai_object_id_t port_id, _In_ uint32_t lanes_count)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    if ((lanes_count == 0) || (lanes_count == 3)) {
        SX_LOG_ERR("Port HW lanes count %u is invalid (supported only 1,2,4)\n", lanes_count);
        status = SAI_STATUS_INVALID_PARAMETER;
    }

    if (lanes_count > mlnx_port_max_lanes_get()) {
        SX_LOG_ERR("Port HW lanes count %u is bigger than %u\n", lanes_count, mlnx_port_max_lanes_get());
        status = SAI_STATUS_INVALID_PARAMETER;
    }

    return status;
}


/**
 * Routine Description:
 *    @brief Create port
 *
 * Arguments:
 *    @param[out] port_id - port id
 *    @param[in] attr_count - number of attributes
 *    @param[in] attr_list - array of attributes
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 *
 */
static sai_status_t mlnx_create_port(_Out_ sai_object_id_t     * port_id,
                                     _In_ sai_object_id_t        switch_id,
                                     _In_ uint32_t               attr_count,
                                     _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *lanes_list = NULL;
    const sai_attribute_value_t *value = NULL;
    const sai_attribute_value_t *fec;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    uint32_t                     fec_index, lane_index;
    uint32_t                     lanes_count;
    uint32_t                     index;
    mlnx_port_config_t          *father_port;
    mlnx_port_config_t          *new_port = NULL;
    sx_port_mapping_t           *port_map;
    sai_status_t                 status;
    uint32_t                     module;
    uint32_t                     ii;
    uint32_t                     port_plane = 0;
    uint32_t                     port_aport = 0;
    uint32_t                     num_of_planes = 0;
    const bool                   is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type);
    uint32_t                     speeds[MAX_NUM_PORT_SPEEDS] = {0}, speeds_count = MAX_NUM_PORT_SPEEDS;

    SX_LOG_EXIT();

    if (NULL == port_id) {
        SX_LOG_ERR("NULL port id param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list,  SAI_OBJECT_TYPE_PORT,
                                    port_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    status = sai_attr_list_to_str(attr_count, attr_list,  SAI_OBJECT_TYPE_PORT, MAX_LIST_VALUE_STR_LEN, list_str);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed convert attribute list to string.\n");
    }
    SX_LOG_NTC("Create port, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_HW_LANE_LIST, &lanes_list, &lane_index);
    if (SAI_ERR(status)) {
        goto out;
    }
    lanes_count = lanes_list->u32list.count;

    status = check_lanes_limitations((*port_id), lanes_count);
    if (SAI_ERR(status)) {
        SX_LOG_NTC("Failed in check lanes");
        goto out;
    }
    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_AGGREGATE_PORT_DATA, &value, &index);
    if (SAI_ERR(status)) {
        SX_LOG_NTC("Failed in check aggregation data");
        goto out;
    }

    port_aport = value->aport_data.aport;
    port_plane = value->aport_data.plane;
    num_of_planes = value->aport_data.num_of_planes;

    module = lane2module(lanes_list->u32list.list[0]);

    /* Validate that all lanes in the list belongs to the same module */
    for (ii = 1; ii < lanes_count; ii++) {
        if (lane2module(lanes_list->u32list.list[ii]) != module) {
            SX_LOG_ERR("Port HW lanes belongs to the different modules. module %u , lane %u \n",
                       module, lanes_list->u32list.list[ii]);
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
    }

    sai_db_write_lock();

    father_port = mlnx_port_by_ib_label(module);
    if (!father_port) {
        SX_LOG_ERR("Failed to find father's port by module %u\n", module);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out_unlock;
    }

    new_port = sai_lane2child_port(father_port, &lanes_list->u32list);
    if (!new_port) {
        status = SAI_STATUS_FAILURE;
        goto out_unlock;
    }

    if (new_port->is_present) {
        SX_LOG_ERR("Failed create port - lanes already allocated by port oid %lx (local %u, module %u)\n",
                   new_port->saiport, new_port->port_map.local_port, new_port->module);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out_unlock;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_CUSTOM_INFINIBAND_IB_SUBNET, &value, &index);
    if (SAI_OK(status)) {
        if (value->u8 > 7) {
            SX_LOG_ERR("Port subnet id %u is invalid (supported only 0-7)\n", value->u8);
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out_unlock;
        }
        new_port->swid_id = value->u8;
    } else {
        new_port->swid_id = (uint8_t)DEFAULT_IB_SWID;
    }

    port_map = &new_port->port_map;

    port_map->mapping_mode = SX_PORT_MAPPING_MODE_ENABLE;
    port_map->module_port = father_port->module;
    port_map->width = lanes_count;
    port_map->lane_bmap = 0x0;

    /* Map local lanes to the new port */
    for (ii = 0; ii < lanes_count; ii++) {
        port_map->lane_bmap |= 1 << sai_lane2phy_lane(lanes_list->u32list.list[ii]);
    }

    if (!is_warmboot_init_stage) {
        status = mlnx_sai_port_hw_lanes_set(port_map, lanes_count, new_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR(
                "Failed enable port mapping (lane_bmap 0x%x,  width %u, module %u, local port %u) for port %x - %s\n",
                port_map->lane_bmap,
                port_map->width,
                port_map->module_port,
                port_map->local_port,
                new_port->logical,
                SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out_unlock;
        }
    }

    SX_LOG_NTC("Initialize new port oid %" PRIx64 "\n", new_port->saiport);

    status = mlnx_port_add(new_port);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_SPEED, &value, &index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }
    new_port->speed = value->u32;

    new_port->adv_speeds_num = 0;
    memset(new_port->adv_speeds, 0, sizeof(new_port->adv_speeds));
    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_ADVERTISED_SPEED, &value, &index);
    if (SAI_OK(status)) {
        new_port->adv_speeds_num = value->u32list.count;
        for (uint32_t ii = 0; ii < value->u32list.count; ++ii) {
            new_port->adv_speeds[ii] = value->u32list.list[ii];
        }
        if (!is_warmboot_init_stage) {
            status = mlnx_port_update_speed(new_port);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to update speed.\n");
                goto out_unlock;
            }
        }
    } else {
        status = mlnx_port_cb->advertised_speeds_get(new_port, speeds, &speeds_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get advertised speeds for port ib %u.\n", new_port->ib_port);
            goto out;
        }
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_MTU, &value, &index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_set_mtu_admin(new_port->swid_id, g_device_id, port_map->local_port, value->u32);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set port mtu.\n");
            goto out_unlock;
        }
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, &value, &index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_port_internal_loopback_set_impl(port_map->local_port, new_port->swid_id, value->u32);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set port loopback.\n");
            goto out_unlock;
        }
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_ADMIN_STATE, &value, &index);
    if (status == SAI_STATUS_SUCCESS) {
        if (SAI_STATUS_SUCCESS != (status = mlnx_set_port_state_admin(new_port->swid_id,
                                                                      g_device_id,
                                                                      port_map->local_port,
                                                                      value->booldata))) {
            MLNX_SAI_LOG_ERR("Failed to set port admin state\n");
            goto out_unlock;
        }
        new_port->admin_state = value->booldata;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_FEC_MODE, &fec, &fec_index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_port_fec_set_impl(new_port->swid_id, g_device_id, port_map->local_port, fec->s32);
        if (SAI_ERR(status)) {
            goto out_unlock;
        }
    } else {
        if (!is_warmboot_init_stage) {
            status = mlnx_port_fec_set_impl(new_port->swid_id,
                                            g_device_id,
                                            port_map->local_port,
                                            SAI_PORT_FEC_MODE_AUTO);
            if (SAI_ERR(status)) {
                goto out_unlock;
            }
        }
    }
    status = find_attrib_in_list(attr_count, attr_list, SAI_PORT_ATTR_SIGNAL_DEGRADE, &value, &index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_set_port_signal_degrade_impl(new_port->swid_id,
                                                   g_device_id,
                                                   port_map->local_port,
                                                   value->booldata);
        if (SAI_ERR(status)) {
            goto out_unlock;
        }
    }

    status = mlnx_aport_set_impl(new_port->swid_id,
                                 g_device_id,
                                 port_map->local_port,
                                 port_aport,
                                 port_plane,
                                 num_of_planes);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    /* Mark port as splitted only if the new width != initial width */
    new_port->is_split = new_port->width != port_map->width;
    /* Clear port counters cache */
    memset(&(new_port->counters_cache), 0, sizeof(new_port->counters_cache));
    SX_LOG_NTC("Created port %" PRIx64 ": ib_port=%u ,local=%u, width=%u, module=%u, lane_bmap=0x%x\n",
               new_port->saiport, new_port->ib_port, new_port->port_map.local_port, port_map->width,
               port_map->module_port, port_map->lane_bmap);

    g_sai_db_ptr->ports_number++;
    *port_id = new_port->saiport;
    status = SAI_STATUS_SUCCESS;

out_unlock:
    sai_db_unlock();
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * Routine Description:
 *    @brief Remove port
 *
 * Arguments:
 *    @param[in] port_id - port id
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
sai_status_t mlnx_remove_port(_In_ sai_object_id_t port_id)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    sx_port_log_id_t    port_log_id;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    SX_LOG_NTC("Remove port %" PRIx64 "\n", port_id);

    status = mlnx_object_to_type(port_id, SAI_OBJECT_TYPE_PORT, &port_log_id, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    sai_db_write_lock();

    status = mlnx_port_by_log_id(port_log_id, &port);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    status = mlnx_port_del(port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed remove port 0x%x\n", port->logical);
        goto out_unlock;
    }

    SX_LOG_NTC("Removed port %" PRIx64 ": ib_port=%u, local=%u, module=%u, lane_bmap=0x%x\n",
               port->saiport, port->ib_port, port->port_map.local_port,
               port->port_map.module_port,
               port->port_map.lane_bmap);

    port->is_split = false;

    g_sai_db_ptr->ports_number--;

out_unlock:
    sai_db_unlock();
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * Function return port's supported hw lanes list by PTYS reg.
 *
 * @param key        - sai port object
 * @param value      - value.u32list is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_ib_lanes_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_ptys_reg  ptys_reg;
    long                attr_id = (long)arg;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&ptys_reg, 0, sizeof(ptys_reg));
    ptys_reg.local_port = port->port_map.local_port;
    ptys_reg.proto_mask = REG_PTYS_PROTO_MASK_IB;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PTYS for local port: [%u], device: [%u], swid [%u]\n",
                         ptys_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }

    switch (attr_id) {
    case SAI_PORT_ATTR_CUSTOM_INFINIBAND_SUPPORTED_HW_LANES:
        value->u8 = ptys_reg.ib_link_width_capability;
        MLNX_SAI_LOG_DBG("Get port [%u] width capabilities [%u]\n", port->ib_port, ptys_reg.ib_link_width_capability);
        break;

    case SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_LANES:
        value->u8 = ptys_reg.ib_link_width_oper;
        MLNX_SAI_LOG_DBG("Get port [%u] width oper [%u]\n", port->ib_port, ptys_reg.ib_link_width_oper);
        break;

    case SAI_PORT_ATTR_CUSTOM_INFINIBAND_ADMIN_LANES:
        value->u8 = ptys_reg.ib_link_width_admin;
        MLNX_SAI_LOG_DBG("Get port [%u] width oper [%u]\n", port->ib_port, ptys_reg.ib_link_width_admin);
        break;

    default:
        SX_LOG_ERR("Not supported attr_id: %ld\n", attr_id);
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function set port's lanes (width) by PTYS reg.
 *
 * @param key   - port's sai object.
 * @param value - value.u8 is the lane value to configure.
 * @param arg   - not used.
 * @return      - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_ib_lanes_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_ptys_reg  ptys_reg;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&ptys_reg, 0, sizeof(ptys_reg));
    ptys_reg.local_port = port->port_map.local_port;
    ptys_reg.proto_mask = REG_PTYS_PROTO_MASK_IB;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PTYS for local port: [%u], device: [%u], swid [%u]\n",
                         ptys_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }

    ptys_reg.ib_link_width_admin = ((ptys_reg.ib_link_width_admin & 0xff00) | value->u8);

    if ((0 == ptys_reg.ib_link_width_admin) || (0 == ptys_reg.ib_proto_admin)) {
        MLNX_SAI_LOG_ERR("Can not set PTYS with 0 speed or width."
                         "required width:[%d]", ptys_reg.ib_link_width_admin);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    MLNX_SAI_LOG_NTC("Set PTYS register to ib port [%u], local port [%u], width [%u]\n",
                     port->ib_port, port->port_map.local_port, ptys_reg.ib_link_width_admin);

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ptys_register(SXD_ACCESS_CMD_SET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ptys_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PTYS for ib port [%u], local port: [%u], width: [%u]\n",
                         port->ib_port, ptys_reg.local_port, ptys_reg.ib_link_width_admin);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}


/**
 * Function return port's operational/supported vl by PVLC reg.
 *
 * @param key        - sai port object
 * @param value      - value.u8 is the return value.
 * @param attr_index - not used.
 * @param cache      - not used.
 * @param arg        - SAI_PORT_ATTR_CUSTOM_INFINIBAND_SUPPORTED_VL / SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_VL / SAI_PORT_ATTR_CUSTOM_INFINIBAND_ADMIN_VL.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_ib_vl_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_pvlc_reg  pvlc_reg;
    long                attr_id = (long)arg;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&pvlc_reg, 0, sizeof(pvlc_reg));
    pvlc_reg.local_port = port->port_map.local_port;


    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pvlc_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pvlc_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PVLC for local port: [%u], device: [%u], swid [%u]\n",
                         pvlc_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }

    switch (attr_id) {
    case SAI_PORT_ATTR_CUSTOM_INFINIBAND_SUPPORTED_VL:
        value->u8 = pvlc_reg.vl_cap;
        break;

    case SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_VL:
        value->u8 = pvlc_reg.vl_operational;
        break;

    case SAI_PORT_ATTR_CUSTOM_INFINIBAND_ADMIN_VL:
        value->u8 = pvlc_reg.vl_admin;
        break;

    default:
        SX_LOG_ERR("Not supported attr_id: %ld\n", attr_id);
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}


/**
 * Function set port's admin vl by PVLC reg.
 *
 * @param key   - port's sai object.
 * @param value - value.u8 is the vl value to configure.
 * @param arg   - not used.
 * @return           - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_port_ib_vl_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_pvlc_reg  pvlc_reg;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&pvlc_reg, 0, sizeof(pvlc_reg));
    pvlc_reg.local_port = port->port_map.local_port;
    pvlc_reg.vl_admin = value->u8;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pvlc_register(SXD_ACCESS_CMD_SET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pvlc_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PVLC for local port: [%u], device: [%u], swid [%u], required vl: [%u]\n",
                         pvlc_reg.local_port, g_device_id, port->swid_id, value->u8);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 * Function return port's logical and physical states by sending MAD and accesing PRM.
 *
 * Arguments:
 *    [in] port - port oject
 *    [in] number_of_states - number of states in the array
 *    [in] states_ids - specifies the array of state ids
 *    [out] states - array of resulting states values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_port_states_get(_In_ mlnx_port_config_t  *port,
                                         _In_ uint32_t             number_of_states,
                                         _In_ const sai_stat_id_t *states_ids,
                                         _Out_ uint64_t           *states)
{
    sai_status_t           status = SAI_STATUS_FAILURE;
    const sai_object_key_t key = { .key.object_id = port->saiport };
    sai_attribute_value_t  return_value;
    vendor_cache_t         cache;
    sa_port_state_t        result;

    SX_LOG_ENTER();

    memset(&result, 0, sizeof(result));
    if (!g_sai_db_ptr->swidapi_handles[port->swid_id]) {
        SX_LOG_DBG("RPC port for sending MADs was not initialized for swid %u\n", port->swid_id);
        goto out;
    }

    status = sa_get_port_info(g_sai_db_ptr->swidapi_handles[port->swid_id], port->ib_port, &result);
    if (SAI_STATUS_SUCCESS != status) {
        MLNX_SAI_LOG_ERR("Failed Get Port info for ib port %u \n", port->ib_port);
    }

    for (uint32_t ii = 0; ii < number_of_states; ii++) {
        switch ((int)states_ids[ii]) {
        case SAI_PORT_STAT_INFINIBAND_LOGICAL_STATE:
            states[ii] = result.port_logical_state;
            break;

        case SAI_PORT_STAT_INFINIBAND_PHYSICAL_STATE:
            states[ii] = result.port_phy_state;
            if ((states[ii] != IB_LINK_ACTIVE) && (port->down_by_signal_degrade == true)) {
                states[ii] = PORT_STATE_DOWN_BY_SIGNAL_DEGRADE;
            }
            break;

        case SAI_PORT_STAT_INFINIBAND_MTU_OPER:
            if (SAI_STATUS_SUCCESS == mlnx_port_mtu_get(&key, &return_value, 0, &cache, NULL)) {
                states[ii] = return_value.u32;
            }
            break;

        case SAI_PORT_STAT_INFINIBAND_LANES_OPER:
            if (SAI_STATUS_SUCCESS ==
                mlnx_port_ib_lanes_get(&key, &return_value, 0, &cache,
                                       (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_LANES)) {
                states[ii] = return_value.u8;
            }
            break;

        case SAI_PORT_STAT_INFINIBAND_VL_OPER:
            if (SAI_STATUS_SUCCESS ==
                mlnx_port_ib_vl_get(&key, &return_value, 0, &cache, (void*)SAI_PORT_ATTR_CUSTOM_INFINIBAND_OPER_VL)) {
                states[ii] = return_value.u8;
            }
            break;

        case SAI_PORT_STAT_INFINIBAND_SPEED_OPER:
            if (SAI_STATUS_SUCCESS == mlnx_port_oper_speed_get(&key, &return_value, 0, &cache, NULL)) {
                states[ii] = return_value.u32;
            }
            break;

        case SAI_PORT_STAT_INFINIBAND_SPEED_OPER_BY_LANES:
            if (SAI_STATUS_SUCCESS ==
                mlnx_port_oper_speed_get(&key, &return_value, 0, &cache,
                                         (void*)SAI_PORT_STAT_INFINIBAND_SPEED_OPER_BY_LANES)) {
                states[ii] = return_value.u32;
            }
            break;

        default:
            SX_LOG_ERR("Invalid port state %d\n", states_ids[ii]);
            status = SAI_STATUS_INVALID_PARAMETER;
            break;
        }
    }

out:
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 * Function return port's counters by sending MAD.
 *
 * Arguments:
 *    [in] port - port object
 *    [in] number_of_states - number of counters in the array
 *    [in] states_ids - specifies the array of stat-ids
 *    [out] states - array of resulting counters values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_port_counters_get(_In_ mlnx_port_config_t  *port,
                                           _In_ uint32_t             number_of_counters,
                                           _In_ const sai_stat_id_t *counters_ids,
                                           _Out_ uint64_t           *counters)
{
    sai_status_t       status = SAI_STATUS_FAILURE;
    sai_status_t       cnt_status = SAI_STATUS_FAILURE;
    sa_port_counters_t ret_counters;
    sa_port_state_t    port_state;
    ib_portid_t        portid;
    uint16_t           lid = 0;

    SX_LOG_ENTER();

    if (!g_sai_db_ptr->swidapi_handles[port->swid_id]) {
        SX_LOG_DBG("RPC port for sending MADs was not initialized for swid %u\n", port->swid_id);
        goto out;
    }

    status = sa_get_port_info(g_sai_db_ptr->swidapi_handles[port->swid_id], port->ib_port, &port_state);
    if (SAI_STATUS_SUCCESS != status) {
        MLNX_SAI_LOG_ERR("Failed Get Port info for ib port %u \n", port->ib_port);
        goto out;
    }

    /* if the port state is active - update counters cache */
    if (IB_LINK_ACTIVE == port_state.port_logical_state) {
        /* fetch the LID of the swid */
        status = sa_get_swid_lid(g_sai_db_ptr->swidapi_handles[port->swid_id], &lid);
        if (SAI_STATUS_SUCCESS != status) {
            MLNX_SAI_LOG_ERR("Failed Get LID for SWID %u \n", port->swid_id);
            goto out;
        }
        /* set dr_path and LID of port-id */
        sa_set_dr_path(&portid);
        ib_portid_set(&portid, lid, 0, 0);
        /* try to get the port counters */
        cnt_status = sa_get_port_cnt(g_sai_db_ptr->swidapi_handles[port->swid_id],
                                     g_device_id, port->ib_port, &portid,
                                     &ret_counters);
        /* it is possible to fail to get the counters - in this case returned the cached value */
        if (cnt_status != SAI_STATUS_SUCCESS) {
            SX_LOG_ERR("Failed get port counters for ib port %u \n", port->ib_port);
        } else {
            /* Update cache with the port counters */
            memcpy(&port->counters_cache, &ret_counters, sizeof(port->counters_cache));
            /* try to get the extended counters when possible and use them on success */
            cnt_status = sa_get_ext_port_cnt(g_sai_db_ptr->swidapi_handles[port->swid_id],
                                             g_device_id, port->ib_port, &portid,
                                             &ret_counters);
            if (cnt_status == SAI_STATUS_SUCCESS) {
                /* Update cache with the extended port counters */
                memcpy(&port->counters_cache, &ret_counters, sizeof(port->counters_cache));
            } else {
                SX_LOG_ERR("Failed get port extended counters for ib port %u \n", port->ib_port);
            }
        }
    }

    for (uint32_t ii = 0; ii < number_of_counters; ii++) {
        switch ((int)counters_ids[ii]) {
        case SAI_PORT_STAT_INFINIBAND_IF_IN_OCTETS_EXT:
            counters[ii] = port->counters_cache.rcv_data_bytes;
            break;

        case SAI_PORT_STAT_INFINIBAND_IF_IN_PKTS_EXT:
            counters[ii] = port->counters_cache.rcv_pkts;
            break;

        case SAI_PORT_STAT_INFINIBAND_IF_OUT_OCTETS_EXT:
            counters[ii] = port->counters_cache.xmit_data_bytes;
            break;

        case SAI_PORT_STAT_INFINIBAND_IF_OUT_PKTS_EXT:
            counters[ii] = port->counters_cache.xmit_pkts;
            break;

        case SAI_PORT_STAT_INFINIBAND_IF_OUT_WAIT:
            counters[ii] = port->counters_cache.xmit_wait;
            break;

        case SAI_PORT_STAT_INFINIBAND_PC_ERR_SYM_F:
            counters[ii] = port->counters_cache.symbol_err_cnt;
            break;

        case SAI_PORT_STAT_INFINIBAND_PC_ERR_RCV_F:
            counters[ii] = port->counters_cache.rcv_err;
            break;

        case SAI_PORT_STAT_INFINIBAND_PC_VL15_DROPPED_F:
            counters[ii] = port->counters_cache.vl15_dropped;
            break;

        case SAI_PORT_STAT_INFINIBAND_PC_XMT_DISCARDS_F:
            counters[ii] = port->counters_cache.xmit_discards;
            break;

        case SAI_PORT_STAT_INFINIBAND_ERR_XMTCONSTR_F:
            counters[ii] = port->counters_cache.xmit_constraint_err;
            break;

        default:
            SX_LOG_INF("Invalid port counter %d for ib port %u\n", counters_ids[ii], port->ib_port);
            status = SAI_STATUS_NOT_IMPLEMENTED;
            goto out;
        }
    }
out:
    SX_LOG_EXIT();
    return status;
}


/*
 * Routine Description:
 * Function returns if a given stat-id is one of the IB state stats
 *
 * Arguments:
 *    [in] states_id - specifies the stat-id
 *
 * Return Values:
 *    True if stat_id is one of the IB state stats
 *    False - otherwise
 */
static bool mlnx_port_is_ib_state_stat(_In_ const sai_stat_id_t stat_id)
{
    return ((int)stat_id >= SAI_PORT_STAT_INFINIBAND_STATE_RANGE_BASE &&
            (int)stat_id < SAI_PORT_STAT_INFINIBAND_STATE_RANGE_END);
}

/*
 * Routine Description:
 * Function returns if a given stat-id is one of a supported IB port counter
 *
 * Arguments:
 *    [in] states_id - specifies the stat-id
 *
 * Return Values:
 *    True if stat_id is one of a supported IB port counter
 *    False - otherwise
 */
static bool mlnx_port_is_ib_counter_stat(_In_ const sai_stat_id_t stat_id)
{
    return ((int)stat_id >= SAI_PORT_STAT_INFINIBAND_IF_RANGE_BASE &&
            (int)stat_id < SAI_PORT_STAT_INFINIBAND_IF_RANGE_END);
}

static sai_status_t mlnx_port_signal_degrade_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }
    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_set_port_signal_degrade_impl(port->swid_id, g_device_id, port->port_map.local_port,
                                               value->booldata))) {
        goto out;
    }


out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}
static sai_status_t mlnx_port_signal_degrade_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_ppbmc_reg ppbmc_reg;
    bool                event_enabled;

    SX_LOG_ENTER();

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&ppbmc_reg, 0, sizeof(struct ku_ppbmc_reg));
    ppbmc_reg.local_port = port->port_map.local_port;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ppbmc_register(SXD_ACCESS_CMD_GET,
                                                                    port->swid_id,
                                                                    g_device_id,
                                                                    NULL,
                                                                    NULL,
                                                                    &ppbmc_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PPBMC for local port: [%u], device: [%u], swid [%u]\n",
                         ppbmc_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }
    event_enabled = (ppbmc_reg.e > 0);
    MLNX_SAI_LOG_DBG("Get PPBMC reg - label port [%u], local port [%u], event enabled [%u]\n",
                     port->ib_port, port->port_map.local_port, ppbmc_reg.e);
    value->booldata = event_enabled;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_port_state_admin_by_sd_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (value->booldata == false) {
        port->down_by_signal_degrade = false;
        goto out;
    }
    /*Only used when setting port admin state to SX_PORT_ADMIN_STATUS_DOWN */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_set_port_state_admin(port->swid_id, g_device_id, port->port_map.local_port, false))) {
        MLNX_SAI_LOG_ERR("Failed to set port admin state.\n");
        goto out;
    }
    port->down_by_signal_degrade = true;


out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_port_link_diagnostic_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_pddr_reg  pddr_reg;
    char              * opcode_status = "OPCODE_STATUS";
    char              * message_status = "MESSAGE_STATUS";
    char                return_msg[MAX_PDDR_MSG_BUFFER];
    int32_t             count;

    SX_LOG_ENTER()
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&pddr_reg, 0, sizeof(pddr_reg));
    pddr_reg.local_port = port->port_map.local_port;
    pddr_reg.page_select = SXD_PDDR_PAGE_SELECT_TROUBLESHOOTING_INFO_PAGE_E;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pddr_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pddr_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PDDR for local port: [%u], device: [%u], swid [%u]\n",
                         pddr_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }

    /* Return message will be in following format OPCODE_STATUS=<opcode>###STATUS_MESSAGE=<message>" */
    count = sprintf(return_msg, "%s=%u###%s=%s", opcode_status,
                    pddr_reg.page_data.pddr_troubleshooting_page.status_opcode.pddr_monitor_opcode.monitor_opcode,
                    message_status,
                    (char*)pddr_reg.page_data.pddr_troubleshooting_page.status_message);

    if (count <= 0) {
        status = SAI_STATUS_FAILURE;
        MLNX_SAI_LOG_ERR("Failed copying Link Diagnostic data\n");
        goto out;
    }

    mlnx_fill_s8list((int8_t*)return_msg, count + 1, &value->s8list);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Function set port's physical loopback via PPLR register.
 *
 * @param local_port  - local number of the port.
 * @param swid        - swid id of the port.
 * @param loop_mode  - loopback mode to configure.
 * @return            - #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_port_internal_loopback_set_impl(_In_ uint32_t                          local_port,
                                                  _In_ uint32_t                          swid_id,
                                                  _In_ sai_port_internal_loopback_mode_t loop_mode)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    struct ku_pplr_reg pplr_reg;
    uint8_t            system_err = 0;
    char               cmd[512] = {0};

    SX_LOG_ENTER();

    memset(&pplr_reg, 0, sizeof(pplr_reg));
    pplr_reg.local_port = local_port;

    switch (loop_mode) {
    case SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE:
        pplr_reg.lb_en = SXD_PPLR_LB_EN_EXTERNAL_LOCAL_LOOPBACK_E;
        break;

    case SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY:
        pplr_reg.lb_en = SXD_PPLR_LB_EN_PHY_LOCAL_LOOPBACK_E;
        break;

    default:
        SX_LOG_ERR("Invalid port internal loopback value %d\n", loop_mode);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }
    /* MOCK */
    if (g_is_chipsim && mlnx_chip_is_qtm3() && (loop_mode == SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY)) {
        sprintf(cmd,
                "mlxreg -d /dev/mst/mt54004_pciconf0 --reg_name PTYS --set=ib_proto_admin=256,an_disable_admin=1,ib_link_width_admin=1 --indexes=local_port=%d,pnat=0,lp_msb=0,port_type=0,proto_mask=1 --yes > /dev/null 2>&1",
                local_port);
        system_err = system(cmd);
        if (0 != system_err) {
            SX_LOG_ERR("Failed running \"%s\".\n", cmd);
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        sprintf(cmd,
                "mlxreg -d /dev/mst/mt54004_pciconf0 --set=ib_fec_override_admin_xdr=64 --reg_name PPLM --indexes=local_port=%d,lp_msb=0,test_mode=0,port_type=0,pnat=0 --yes > /dev/null 2>&1",
                local_port);
        system_err = system(cmd);
        if (0 != system_err) {
            SX_LOG_ERR("Failed running \"%s\".\n", cmd);
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        sprintf(cmd,
                "mlxreg -d /dev/mst/mt54004_pciconf0 --reg_name PLTC --indexes=local_port=%d,lp_msb=0,lane_mask=15,pnat=0 --set=local_tx_precoding_admin=2,local_rx_precoding_admin=2 --yes > /dev/null 2>&1",
                local_port);
        system_err = system(cmd);
        if (0 != system_err) {
            SX_LOG_ERR("Failed running \"%s\".\n", cmd);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pplr_register(SXD_ACCESS_CMD_SET,
                                                                   swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pplr_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PPLR for local port: [%u], device: [%u], swid [%u], status: [%u]\n",
                         pplr_reg.local_port, g_device_id, swid_id, loop_mode);
    }
out:
    return status;
}

sai_status_t mlnx_port_internal_loopback_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();
    sai_db_read_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_port_internal_loopback_set_impl(port->port_map.local_port,
                                                                             port->swid_id,
                                                                             value->s32))) {
        SX_LOG_ERR("Failed setting loopback configuration [%u] for port [%u]\n", value->s32,
                   port->port_map.local_port);
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_port_internal_loopback_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_pplr_reg  pplr_reg;

    SX_LOG_ENTER();

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    memset(&pplr_reg, 0, sizeof(struct ku_pplr_reg));
    pplr_reg.local_port = port->port_map.local_port;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pplr_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pplr_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PPLR for local port: [%u], device: [%u], swid [%u]\n",
                         pplr_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }
    MLNX_SAI_LOG_DBG("Get PPLR reg - label port [%u], local port [%u], lb_en [%u], lb_cap [%u]\n",
                     port->ib_port, port->port_map.local_port, pplr_reg.lb_en, pplr_reg.lb_cap);
    if (pplr_reg.lb_en == (SXD_PPLR_LB_EN_EXTERNAL_LOCAL_LOOPBACK_E | SXD_PPLR_LB_EN_PHY_LOCAL_LOOPBACK_E)) {
        value->s32 = SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY;
    } else {
        value->s32 = SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_port_fnm_port_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    value->booldata = port->is_fnm;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_aggregation_port_data_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();
    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }
    if (SAI_STATUS_SUCCESS != (status = mlnx_aport_set_impl(port->swid_id,
                                                            g_device_id,
                                                            port->port_map.local_port,
                                                            value->aport_data.aport,
                                                            value->aport_data.plane,
                                                            value->aport_data.num_of_planes))) {
        MLNX_SAI_LOG_ERR("Failed setting aggregation port data for local port: %u\n", port->port_map.local_port);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT()
    return status;
}

static sai_status_t mlnx_port_protocol_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    value->s32 = port->protocol;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}


static sai_status_t mlnx_aggregation_port_data_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    struct ku_ppcr_reg  ppcr_reg;

    SX_LOG_ENTER();

    memset(&ppcr_reg, 0, sizeof(ppcr_reg));

    sai_db_write_lock();
    /* MOCK */
    if (mlnx_chip_is_qtm2()) {
        SX_LOG_NTC("Can't read aggregated data from FW on QTM2\n");
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    ppcr_reg.local_port = port->port_map.local_port;
    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_ppcr_register(SXD_ACCESS_CMD_GET,
                                                                   port->swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &ppcr_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PPCR for local port: [%u], device: [%u], swid [%u]\n",
                         ppcr_reg.local_port, g_device_id, port->swid_id);
        goto out;
    }

    value->aport_data.aport = ppcr_reg.aggregated_port;
    value->aport_data.plane = ppcr_reg.plane;
    value->aport_data.num_of_planes = ppcr_reg.num_of_planes;


out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_connection_type_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    value->s32 = port->conn_type;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_is_maf_get(_In_ const sai_object_key_t   *key,
                                    _Inout_ sai_attribute_value_t *value,
                                    _In_ uint32_t                  attr_index,
                                    _Inout_ vendor_cache_t        *cache,
                                    void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    value->s32 = port->is_maf;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}
static sai_status_t mlnx_port_remote_id_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_port_by_obj_id(key->key.object_id, &port))) {
        SX_LOG_ERR("Failed to lookup port by object id %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    value->s32 = port->remote_id;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

const sai_port_api_t mlnx_port_api = {
    mlnx_create_port,
    mlnx_remove_port,
    mlnx_set_port_attribute,
    mlnx_get_port_attribute,
    mlnx_get_port_stats,
    mlnx_get_port_stats_ext,
    mlnx_clear_port_stats,
    mlnx_clear_port_all_stats,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
