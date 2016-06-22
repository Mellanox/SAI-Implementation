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
#include "syslog.h"
#include <errno.h>
#include "assert.h"
#ifndef _WIN32
#include <netinet/ether.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/mman.h>
#include <pthread.h>
#endif
#include <complib/cl_mem.h>
#include <complib/cl_passivelock.h>
#include <complib/cl_shared_memory.h>
#include <complib/cl_thread.h>

#undef  __MODULE__
#define __MODULE__ SAI_SWITCH

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
sx_api_handle_t                  gh_sdk = 0;
static sai_switch_notification_t g_notification_callbacks;
static sai_switch_profile_id_t   g_profile_id;
rm_resources_t                   g_resource_limits;
sai_db_t                        *g_sai_db_ptr         = NULL;
sai_qos_db_t                    *g_sai_qos_db_ptr     = NULL;
uint32_t                         g_sai_qos_db_size    = 0;
sai_buffer_db_t                 *g_sai_buffer_db_ptr  = NULL;
uint32_t                         g_sai_buffer_db_size = 0;
static cl_thread_t               event_thread;
static bool                      event_thread_asked_to_stop = false;
static bool                      g_log_init                 = false;

void log_cb(sx_log_severity_t severity, const char *module_name, char *msg);
#ifdef ACS_OS
static sx_log_cb_t sai_log_cb = log_cb;
#else
static sx_log_cb_t sai_log_cb = NULL;
static sai_status_t mlnx_switch_fan_set(uint8_t power_percent);
#endif

typedef struct _sx_pool_info {
    uint32_t           pool_id;
    sx_cos_pool_attr_t pool_attr;
} sx_pool_info_t;
typedef struct _pool_array_info_t {
    sx_pool_info_t* pool_arr;
    uint32_t        pool_cnt;
} pool_array_info_t;

static sai_status_t switch_open_traps(void);
static sai_status_t switch_close_traps(void);
static void event_thread_func(void *context);
static sai_status_t sai_db_create();
static void sai_db_values_init();
static sai_status_t mlnx_parse_config(const char *config_file);
static uint32_t sai_qos_db_size_get();
static void sai_qos_db_init();
static sai_status_t sai_qos_db_unload(boolean_t erase_db);
static sai_status_t sai_qos_db_create();
static void sai_buffer_db_values_init();
static sai_status_t sai_buffer_db_switch_connect_init(int shmid);
static void sai_buffer_db_data_reset();
static uint32_t sai_buffer_db_size_get();
static void sai_buffer_db_pointers_init();
#ifdef SAI_BUFFER_SELF_CHECK
bool self_check_buffer_db();
#endif /* SAI_BUFFER_SELF_CHECK */

static sai_status_t sai_buffer_db_unload(boolean_t erase_db);
static sai_status_t sai_buffer_db_create();
static sai_status_t mlnx_switch_port_number_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_switch_port_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_switch_cpu_port_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_switch_max_mtu_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_switch_max_vr_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_switch_on_link_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_switch_oper_status_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_switch_max_temp_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static sai_status_t mlnx_switch_acl_table_min_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_switch_acl_table_max_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_switch_acl_entry_min_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_switch_acl_entry_max_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_switch_acl_trap_range_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_switch_max_lag_members_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_switch_max_lag_number_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_switch_mode_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_switch_src_mac_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_switch_aging_time_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_switch_ecmp_hash_param_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_switch_ecmp_max_paths_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_switch_counter_refresh_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_switch_default_trap_group_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_switch_default_vrid_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_switch_sched_group_levels_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_switch_sched_groups_count_per_level_get(_In_ const sai_object_key_t   *key,
                                                                 _Inout_ sai_attribute_value_t *value,
                                                                 _In_ uint32_t                  attr_index,
                                                                 _Inout_ vendor_cache_t        *cache,
                                                                 void                          *arg);
static sai_status_t mlnx_switch_sched_max_child_groups_count_get(_In_ const sai_object_key_t   *key,
                                                                 _Inout_ sai_attribute_value_t *value,
                                                                 _In_ uint32_t                  attr_index,
                                                                 _Inout_ vendor_cache_t        *cache,
                                                                 void                          *arg);
static sai_status_t mlnx_switch_queue_num_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_switch_lag_hash_seed_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_switch_lag_hash_algo_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_switch_mode_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
static sai_status_t mlnx_switch_aging_time_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_switch_ecmp_hash_param_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_switch_counter_refresh_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_switch_lag_hash_seed_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg);
static sai_status_t mlnx_switch_lag_hash_algo_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg);
static sai_status_t mlnx_switch_qos_map_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_switch_qos_map_id_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_switch_default_tc_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_switch_default_tc_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_switch_hash_object_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_switch_hash_object_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_switch_total_pool_buffer_size_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg);
static sai_status_t mlnx_switch_ingress_pool_num_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_switch_egress_pool_num_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static const sai_attribute_entry_t        switch_attribs[] = {
    { SAI_SWITCH_ATTR_PORT_NUMBER, false, false, false, true,
      "Switch ports number", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_PORT_LIST, false, false, false, true,
      "Switch ports list", SAI_ATTR_VAL_TYPE_OBJLIST },
    { SAI_SWITCH_ATTR_PORT_MAX_MTU, false, false, false, true,
      "Switch max MTU", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_CPU_PORT, false, false, false, true,
      "Switch CPU port", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS, false, false, false, true,
      "Switch max virtual routers", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_FDB_TABLE_SIZE, false, false, false, true,
      "Switch FDB table size", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ON_LINK_ROUTE_SUPPORTED, false, false, false, true,
      "Switch on link route supported", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_OPER_STATUS, false, false, false, true,
      "Switch operational status", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_MAX_TEMP, false, false, false, true,
      "Switch maximum temperature", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_ACL_TABLE_MINIMUM_PRIORITY, false, false, false, true,
      "Switch ACL table min prio", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ACL_TABLE_MAXIMUM_PRIORITY, false, false, false, true,
      "Switch ACL table max prio", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY, false, false, false, true,
      "Switch ACL entry min prio", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY, false, false, false, true,
      "Switch ACL entry max prio", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE, false, false, false, true,
      "Switch FDB DST meta range", SAI_ATTR_VAL_TYPE_U32RANGE },
    { SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE, false, false, false, true,
      "Switch Route DST meta range", SAI_ATTR_VAL_TYPE_U32RANGE },
    { SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE, false, false, false, true,
      "Switch Neighbor DST meta range", SAI_ATTR_VAL_TYPE_U32RANGE },
    { SAI_SWITCH_ATTR_PORT_USER_META_DATA_RANGE, false, false, false, true,
      "Switch Port meta range", SAI_ATTR_VAL_TYPE_U32RANGE },
    { SAI_SWITCH_ATTR_VLAN_USER_META_DATA_RANGE, false, false, false, true,
      "Switch Vlan meta range", SAI_ATTR_VAL_TYPE_U32RANGE },
    { SAI_SWITCH_ATTR_ACL_USER_META_DATA_RANGE, false, false, false, true,
      "Switch ACL meta range", SAI_ATTR_VAL_TYPE_U32RANGE },
    { SAI_SWITCH_ATTR_ACL_USER_TRAP_ID_RANGE, false, false, false, true,
      "Switch ACL trap range", SAI_ATTR_VAL_TYPE_U32RANGE },
    { SAI_SWITCH_ATTR_DEFAULT_STP_INST_ID, false, false, false, true,
      "Switch maximum temperature", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_LAG_MEMBERS, false, false, false, true,
      "Switch number of LAG members", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_NUMBER_OF_LAGS, false, false, false, true,
      "Switch number of LAGs", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_SWITCHING_MODE, false, false, true, true,
      "Switch switching mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE, false, false, true, true,
      "Switch broadcast flood control to cpu", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE, false, false, true, true,
      "Switch multicast flood control to cpu", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, false, false, true, true,
      "Switch source MAC address", SAI_ATTR_VAL_TYPE_MAC },
    { SAI_SWITCH_ATTR_MAX_LEARNED_ADDRESSES, false, false, true, true,
      "Switch maximum number of learned MAC addresses", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_FDB_AGING_TIME, false, false, true, true,
      "Switch FDB aging time", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_FDB_UNICAST_MISS_ACTION, false, false, true, true,
      "Switch flood control for unknown unicast address", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_ACTION, false, false, true, true,
      "Switch flood control for unknown broadcast address", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_ACTION, false, false, true, true,
      "Switch flood control for unknown multicast address", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED, false, false, true, true,
      "Switch LAG hash seed", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM, false, false, true, true,
      "Switch LAG hash algorithm", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_LAG_DEFAULT_SYMMETRIC_HASH, false, false, true, true,
      "Switch LAG symmetric hash", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED, false, false, true, true,
      "Switch ECMP hash seed", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM, false, false, true, true,
      "Switch ECMP hash algorithm", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH, false, false, true, true,
      "Switch ECMP symmetric hash", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_ECMP_MEMBERS, false, false, false, true,
      "Switch number of ECMP members", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, false, false, true, true,
      "Switch counter refresh interval", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_QOS_DEFAULT_TC, false, false, true, true,
      "Switch default tc", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP, false, false, true, true,
      "Switch dot1p to tc mapping", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP, false, false, true, true,
      "Switch dot1p to color mapping", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, false, false, true, true,
      "Switch dscp to tc mapping", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP, false, false, true, true,
      "Switch dscp to color mapping", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, false, false, true, true,
      "Switch tc to queue mapping", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP, false, false, true, true,
      "Switch tc & color to dot1p mapping", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP, false, false, true, true,
      "Switch tc & color to dscp mapping", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP, false, false, false, true,
      "Switch default trap group", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_PORT_BREAKOUT, false, false, true, false,
      "Switch port breakout mode", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID, false, false, false, true,
      "Switch default router", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUP_HIERARCHY_LEVELS, false, false, false, true,
      "Switch scheduler group levels", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUPS_PER_HIERARCHY_LEVEL, false, false, false, true,
      "Switch scheduler groups number per level", SAI_ATTR_VAL_TYPE_U32LIST },
    { SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_CHILDS_PER_SCHEDULER_GROUP, false, false, false, true,
      "Switch scheduler max child groups per group", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES, false, false, false, true,
      "Switch unicast queue number", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES, false, false, false, true,
      "Switch multicast queue number", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_NUMBER_OF_QUEUES, false, false, false, true,
      "Switch total queue number", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES, false, false, false, true,
      "Switch CPU queue number", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ECMP_HASH, false, false, false, true,
      "Switch ECMP hash OID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_LAG_HASH, false, false, false, true,
      "Switch LAG hash OID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_ECMP_HASH_IPV4, false, false, true, true,
      "Switch ECMP IPv4 hash OID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4, false, false, true, true,
      "Switch ECMP IPinIP hash OID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_LAG_HASH_IPV4, false, false, true, true,
      "Switch LAG IPv4 hash OID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4, false, false, true, true,
      "Switch LAG IPinIP hash OID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_SWITCH_ATTR_TOTAL_BUFFER_SIZE, false, false, false, true,
      "Total buffer size", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_INGRESS_BUFFER_POOL_NUM, false, false, false, true,
      "Number of ingress pools", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_EGRESS_BUFFER_POOL_NUM, false, false, false, true,
      "Number of egress pools", SAI_ATTR_VAL_TYPE_U32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t switch_vendor_attribs[] = {
    { SAI_SWITCH_ATTR_PORT_NUMBER,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_port_number_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_PORT_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_port_list_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_PORT_MAX_MTU,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_mtu_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CPU_PORT,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_cpu_port_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_vr_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_TABLE_SIZE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ON_LINK_ROUTE_SUPPORTED,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_on_link_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_OPER_STATUS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_oper_status_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_TEMP,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_temp_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ACL_TABLE_MINIMUM_PRIORITY,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_acl_table_min_prio_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ACL_TABLE_MAXIMUM_PRIORITY,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_acl_table_max_prio_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_acl_entry_min_prio_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_acl_entry_max_prio_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_PORT_USER_META_DATA_RANGE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_VLAN_USER_META_DATA_RANGE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ACL_USER_META_DATA_RANGE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ACL_USER_TRAP_ID_RANGE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_acl_trap_range_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_DEFAULT_STP_INST_ID,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_LAG_MEMBERS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_lag_members_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_NUMBER_OF_LAGS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_lag_number_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_SWITCHING_MODE,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_mode_get, NULL,
      mlnx_switch_mode_set, NULL },
    { SAI_SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_SRC_MAC_ADDRESS,
      { false, false, false, true },
      { false, false, true, true },
      mlnx_switch_src_mac_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_LEARNED_ADDRESSES,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_AGING_TIME,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_aging_time_get, NULL,
      mlnx_switch_aging_time_set, NULL },
    { SAI_SWITCH_ATTR_FDB_UNICAST_MISS_ACTION,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_ACTION,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_ACTION,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_lag_hash_seed_get, NULL,
      mlnx_switch_lag_hash_seed_set, NULL },
    { SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_lag_hash_algo_get, NULL,
      mlnx_switch_lag_hash_algo_set, NULL },
    { SAI_SWITCH_ATTR_LAG_DEFAULT_SYMMETRIC_HASH,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_hash_param_get, (void*)SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED,
      mlnx_switch_ecmp_hash_param_set, (void*)SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED },
    { SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_hash_param_get, (void*)SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM,
      mlnx_switch_ecmp_hash_param_set, (void*)SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM },
    { SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_hash_param_get, (void*)SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH,
      mlnx_switch_ecmp_hash_param_set, (void*)SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH },
    { SAI_SWITCH_ATTR_ECMP_MEMBERS,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_max_paths_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_counter_refresh_get, NULL,
      mlnx_switch_counter_refresh_set, NULL },
    { SAI_SWITCH_ATTR_QOS_DEFAULT_TC,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_default_tc_get, NULL,
      mlnx_switch_default_tc_set, NULL },
    { SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_qos_map_id_get, (void*)SAI_QOS_MAP_DOT1P_TO_TC,
      mlnx_switch_qos_map_id_set, (void*)SAI_QOS_MAP_DOT1P_TO_TC },
    { SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_qos_map_id_get, (void*)SAI_QOS_MAP_DOT1P_TO_COLOR,
      mlnx_switch_qos_map_id_set, (void*)SAI_QOS_MAP_DOT1P_TO_COLOR },
    { SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_qos_map_id_get, (void*)SAI_QOS_MAP_DSCP_TO_TC,
      mlnx_switch_qos_map_id_set, (void*)SAI_QOS_MAP_DSCP_TO_TC },
    { SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_qos_map_id_get, (void*)SAI_QOS_MAP_DSCP_TO_COLOR,
      mlnx_switch_qos_map_id_set, (void*)SAI_QOS_MAP_DSCP_TO_COLOR },
    { SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_qos_map_id_get, (void*)SAI_QOS_MAP_TC_TO_QUEUE,
      mlnx_switch_qos_map_id_set, (void*)SAI_QOS_MAP_TC_TO_QUEUE },
    { SAI_SWITCH_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_qos_map_id_get, (void*)SAI_QOS_MAP_TC_AND_COLOR_TO_DOT1P,
      mlnx_switch_qos_map_id_set, (void*)SAI_QOS_MAP_TC_AND_COLOR_TO_DOT1P },
    { SAI_SWITCH_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_qos_map_id_get, (void*)SAI_QOS_MAP_TC_AND_COLOR_TO_DSCP,
      mlnx_switch_qos_map_id_set, (void*)SAI_QOS_MAP_TC_AND_COLOR_TO_DSCP },
    { SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_default_trap_group_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_PORT_BREAKOUT,
      { false, false, false, false },
      { false, false, true, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_default_vrid_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUP_HIERARCHY_LEVELS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_sched_group_levels_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUPS_PER_HIERARCHY_LEVEL,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_sched_groups_count_per_level_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_CHILDS_PER_SCHEDULER_GROUP,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_sched_max_child_groups_count_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_queue_num_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES,
      NULL, NULL },
    { SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_queue_num_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES,
      NULL, NULL },
    { SAI_SWITCH_ATTR_NUMBER_OF_QUEUES,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_queue_num_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_QUEUES,
      NULL, NULL },
    { SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ECMP_HASH,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_hash_object_get, (void*)SAI_SWITCH_ATTR_ECMP_HASH,
      NULL, NULL },
    { SAI_SWITCH_ATTR_LAG_HASH,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_hash_object_get, (void*)SAI_SWITCH_ATTR_LAG_HASH,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ECMP_HASH_IPV4,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_hash_object_get, (void*)SAI_SWITCH_ATTR_ECMP_HASH_IPV4,
      mlnx_switch_hash_object_set, (void*)SAI_SWITCH_ATTR_ECMP_HASH_IPV4 },
    { SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_hash_object_get, (void*)SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4,
      mlnx_switch_hash_object_set, (void*)SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4 },
    { SAI_SWITCH_ATTR_LAG_HASH_IPV4,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_hash_object_get, (void*)SAI_SWITCH_ATTR_LAG_HASH_IPV4,
      mlnx_switch_hash_object_set, (void*)SAI_SWITCH_ATTR_LAG_HASH_IPV4 },
    { SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_hash_object_get, (void*)SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4,
      mlnx_switch_hash_object_set, (void*)SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4 },
    { SAI_SWITCH_ATTR_TOTAL_BUFFER_SIZE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_total_pool_buffer_size_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_INGRESS_BUFFER_POOL_NUM,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_ingress_pool_num_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_EGRESS_BUFFER_POOL_NUM,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_egress_pool_num_get, NULL,
      NULL, NULL },
};

#define RDQ_ETH_DEFAULT_SIZE 4200
/* the needed value is 10000 but added more for align */
#define RDQ_ETH_LARGE_SIZE                 10240
#define RDQ_DEFAULT_NUMBER_OF_ENTRIES      128
#define RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT 10
#define SAI_PATH                           "/sai_db"
#define SAI_QOS_PATH                       "/sai_qos_db"
#define SAI_BUFFER_PATH                    "/sai_buffer_db"
#define SWID_NUM                           1

static struct sx_pci_profile pci_profile_single_eth_spectrum = {
    /*profile enum*/
    .pci_profile = PCI_PROFILE_EN_SINGLE_SWID,
    /*tx_prof: <swid,etclass> -> <stclass,sdq> */
    .tx_prof = {
        {
            {0, 2}, /*-0-best effort*/
            {1, 2}, /*-1-low prio*/
            {2, 2}, /*-2-medium prio*/
            {3, 2}, /*-3-*/
            {4, 2}, /*-4-*/
            {5, 1}, /*-5-high prio*/
            {6, 1}, /*-6-critical prio*/
            {6, 1} /*-7-*/
        }
    },
    /* emad_tx_prof */
    .emad_tx_prof = {
        0, 0
    },
    /* swid_type */
    .swid_type = {
        SX_KU_L2_TYPE_ETH,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE
    },
    /* rdq_count */
    .rdq_count = {
        33,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    },
    /* rdq */
    .rdq = {
        {
            /* swid 0 - ETH */
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32
        },
    },
    /* emad_rdq */
    .emad_rdq = 33,
    /* rdq_properties */
    .rdq_properties = {
        /* SWID 0 */
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-0-best effort priority*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT},   /*-1-low priority*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-2-medium priority*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT},   /*-3-high priority*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-4-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-5-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-6-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-7-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-8-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-9-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-10-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-11-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-12-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-13-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-14-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-15-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-16-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-17-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-18-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-19-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-20-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-21-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-22-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-23-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-24-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-25-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-26-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-27-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-28-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-29-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-30-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-31-*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-32-mirror agent*/
        {RDQ_DEFAULT_NUMBER_OF_ENTRIES, RDQ_ETH_LARGE_SIZE, RDQ_ETH_SINGLE_SWID_DEFAULT_WEIGHT}, /*-33-emad*/
    },
    /* cpu_egress_tclass */
    .cpu_egress_tclass = {
        2, /*-0-critical prio*/
        1, /*-1-high ptio*/
        0, /*-2-all other prios*/
        0, /*-3-*/
        0, /*-4-*/
        0, /*-5-*/
        0, /*-6-*/
        0, /*-7-*/
        4, /*-8-EMADs*/
        0, /*-9-*/
        0, /*-10-*/
        0, /*-11-*/
        0, /*-12-*/
        0, /*-13-*/
        0, /*-14-*/
        0, /*-15-*/
        0, /*-16-*/
        0, /*-17-*/
        0, /*-18-*/
        0, /*-19-*/
        0, /*-20-*/
        0, /*-21-*/
        0, /*-22-*/
        0 /*-23-55*/
    }
};

/* device profile */
static struct ku_profile single_part_eth_device_profile_spectrum = {
    .set_mask_0_63              = 0x70073ff, /* bit 9 and bits 10-11 are turned off*/
    .set_mask_64_127            = 0,
    .max_vepa_channels          = 0,
    .max_lag                    = 64, /* 600,/ *TODO: PRM should define this field* / */
    .max_port_per_lag           = 32, /*TODO: PRM should define this field*/
    .max_mid                    = 7000,
    .max_pgt                    = 0,
    .max_system_port            = 64, /*TODO: PRM IS NOT UPDATED*/
    .max_active_vlans           = 127,
    .max_regions                = 400,
    .max_flood_tables           = 2,
    .max_per_vid_flood_tables   = 1,
    .flood_mode                 = 3,
    .max_ib_mc                  = 0,
    .max_pkey                   = 0,
    .ar_sec                     = 0,
    .adaptive_routing_group_cap = 0,
    .arn                        = 0,
    .kvd_linear_size            = 0x10000, /* 64K */
    .kvd_hash_single_size       = 0x20000, /* 128K */
    .kvd_hash_double_size       = 0xC000, /* 24K*2 = 48K */
    .swid0_config_type          = {
        .mask = 1,
        .type = KU_SWID_TYPE_ETHERNET
    },
    .swid1_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid2_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid3_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid4_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid5_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid6_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid7_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },

    .chip_type = SXD_CHIP_TYPE_SPECTRUM,
};


#ifndef _WIN32
void log_cb(sx_log_severity_t severity, const char *module_name, char *msg)
{
    int   level;
    char *level_str;

    if (!g_log_init) {
        openlog("SDK", 0, LOG_USER);
        g_log_init = true;
    }

    /* translate SDK log level to syslog level */
    switch (severity) {
    case SX_LOG_NOTICE:
        level     = LOG_NOTICE;
        level_str = "NOTICE";
        break;

    case SX_LOG_INFO:
        level     = LOG_INFO;
        level_str = "INFO";
        break;

    case SX_LOG_ERROR:
        level     = LOG_ERR;
        level_str = "ERR";
        break;

    case SX_LOG_WARNING:
        level     = LOG_WARNING;
        level_str = "WARNING";
        break;

    case SX_LOG_FUNCS:
    case SX_LOG_FRAMES:
    case SX_LOG_DEBUG:
    case SX_LOG_ALL:
        level     = LOG_DEBUG;
        level_str = "DEBUG";
        break;

    default:
        level     = LOG_DEBUG;
        level_str = "DEBUG";
        break;
    }

    syslog(level, "[%s.%s] %s", module_name, level_str, msg);
}
#else
void log_cb(sx_log_severity_t severity, const char *module_name, char *msg)
{
    UNREFERENCED_PARAMETER(severity);
    UNREFERENCED_PARAMETER(module_name);
    UNREFERENCED_PARAMETER(msg);
}
#endif /* ifndef _WIN32 */

static sai_status_t mlnx_port_speed_convert_bitmap_to_capability(const sx_port_speed_t       speed_bitmap,
                                                                 sx_port_speed_capability_t* speed_capability)
{
    if (NULL == speed_capability) {
        SX_LOG_ERR("NULL pointer: Port Speed Capability");
        return SAI_STATUS_FAILURE;
    }

    memset(speed_capability, 0, sizeof(*speed_capability));
    if (speed_bitmap & 1) {
        speed_capability->mode_1GB_CX_SGMII = TRUE;
    }
    if (speed_bitmap & 1 << 1) {
        speed_capability->mode_1GB_KX = TRUE;
    }
    if (speed_bitmap & 1 << 2) {
        speed_capability->mode_10GB_CX4_XAUI = TRUE;
    }
    if (speed_bitmap & 1 << 3) {
        speed_capability->mode_10GB_KX4 = TRUE;
    }
    if (speed_bitmap & 1 << 4) {
        speed_capability->mode_10GB_KR = TRUE;
    }
    if (speed_bitmap & 1 << 5) {
        speed_capability->mode_20GB_KR2 = TRUE;
    }
    if (speed_bitmap & 1 << 6) {
        speed_capability->mode_40GB_CR4 = TRUE;
    }
    if (speed_bitmap & 1 << 7) {
        speed_capability->mode_40GB_KR4 = TRUE;
    }
    if (speed_bitmap & 1 << 8) {
        speed_capability->mode_56GB_KR4 = TRUE;
    }
    if (speed_bitmap & 1 << 9) {
        speed_capability->mode_56GB_KX4 = TRUE;
    }
    if (speed_bitmap & 1 << 12) {
        speed_capability->mode_10GB_CR = TRUE;
    }
    if (speed_bitmap & 1 << 13) {
        speed_capability->mode_10GB_SR = TRUE;
    }
    if (speed_bitmap & 1 << 14) {
        speed_capability->mode_10GB_ER_LR = TRUE;
    }
    if (speed_bitmap & 1 << 15) {
        speed_capability->mode_40GB_SR4 = TRUE;
    }
    if (speed_bitmap & 1 << 16) {
        speed_capability->mode_40GB_LR4_ER4 = TRUE;
    }
    if (speed_bitmap & 1 << 20) {
        speed_capability->mode_100GB_CR4 = TRUE;
    }
    if (speed_bitmap & 1 << 21) {
        speed_capability->mode_100GB_SR4 = TRUE;
    }
    if (speed_bitmap & 1 << 22) {
        speed_capability->mode_100GB_KR4 = TRUE;
    }
    if (speed_bitmap & 1 << 23) {
        speed_capability->mode_100GB_LR4_ER4 = TRUE;
    }
    if (speed_bitmap & 1 << 27) {
        speed_capability->mode_25GB_CR = TRUE;
    }
    if (speed_bitmap & 1 << 28) {
        speed_capability->mode_25GB_KR = TRUE;
    }
    if (speed_bitmap & 1 << 29) {
        speed_capability->mode_25GB_SR = TRUE;
    }
    if (speed_bitmap & 1 << 30) {
        speed_capability->mode_50GB_CR2 = TRUE;
    }
    if (speed_bitmap & 1 << 31) {
        speed_capability->mode_50GB_KR2 = TRUE;
    }
    if (speed_bitmap == 0xFFFFFFFF) {
        speed_capability->mode_auto = TRUE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_resource_mng_stage(const char *config_file)
{
    int                       system_err;
    sxd_status_t              sxd_ret = SXD_STATUS_SUCCESS;
    sxd_ctrl_pack_t           ctrl_pack;
    struct ku_dpt_path_add    path;
    struct ku_dpt_path_modify path_modify;
    struct ku_swid_details    swid_details;
    char                      dev_name[MAX_NAME_LEN];
    char                     *dev_names[1] = { dev_name };
    uint32_t                  dev_num      = 1;
    sxd_handle                sxd_handle   = 0;
    uint32_t                  ii;
    sai_status_t              status;

    memset(&ctrl_pack, 0, sizeof(sxd_ctrl_pack_t));
    memset(&swid_details, 0, sizeof(swid_details));
    memset(&path_modify, 0, sizeof(path_modify));

    if (SAI_STATUS_SUCCESS != (status = sai_db_create())) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = sai_qos_db_create())) {
        return status;
    }

    sai_db_values_init();

    if (SAI_STATUS_SUCCESS != (status = mlnx_parse_config(config_file))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = sai_buffer_db_create())) {
        return status;
    }
    sai_buffer_db_values_init();

    system_err = system("pidof sx_sdk");
    if (0 == system_err) {
        fprintf(stderr, "SDK already running. Please terminate it before running SAI init.\n");
        return SAI_STATUS_FAILURE;
    }

    system_err = system("/etc/init.d/sxdkernel start");
    if (0 != system_err) {
        fprintf(stderr, "Failed running sxdkernel start.\n");
        return SAI_STATUS_FAILURE;
    }

    sxd_ret = sxd_dpt_init(SYS_TYPE_EN, sai_log_cb, LOG_VAR_NAME(__MODULE__));
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "Failed to init dpt - %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SAI_STATUS_FAILURE;
    }

    sxd_ret = sxd_dpt_set_access_control(SX_DEVICE_ID, READ_WRITE);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "Failed to set dpt access control - %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SAI_STATUS_FAILURE;
    }

    sxd_ret = sxd_access_reg_init(0, sai_log_cb, LOG_VAR_NAME(__MODULE__));
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "Failed to init access reg - %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SAI_STATUS_FAILURE;
    }

    /* get device list from the devices directory */
    sxd_ret = sxd_get_dev_list(dev_names, &dev_num);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "sxd_get_dev_list error %s.\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    /* open the first device */
    sxd_ret = sxd_open_device(dev_name, &sxd_handle);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "sxd_open_device error %s.\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    ctrl_pack.ctrl_cmd = CTRL_CMD_ADD_DEV_PATH;
    ctrl_pack.cmd_body = (void*)&(path);
    memset(&path, 0, sizeof(struct ku_dpt_path_add));
    path.dev_id                           = SX_DEVICE_ID;
    path.path_type                        = DPT_PATH_I2C;
    path.path_info.sx_i2c_info.sx_i2c_dev = 0x420248;
    sxd_ret                               = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "failed to add I2C dev path to DP table, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    ctrl_pack.ctrl_cmd = CTRL_CMD_ADD_DEV_PATH;
    ctrl_pack.cmd_body = (void*)&(path);
    memset(&path, 0, sizeof(struct ku_dpt_path_add));
    path.dev_id                        = SX_DEVICE_ID;
    path.path_type                     = DPT_PATH_PCI_E;
    path.path_info.sx_pcie_info.pci_id = 256;
    path.is_local                      = 1;
    sxd_ret                            = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "failed to add PCI dev path to DP table, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    ctrl_pack.ctrl_cmd    = CTRL_CMD_SET_CMD_PATH;
    ctrl_pack.cmd_body    = (void*)&(path_modify);
    path_modify.dev_id    = SX_DEVICE_ID;
    path_modify.path_type = DPT_PATH_PCI_E;
    sxd_ret               = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("failed to set cmd_ifc path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_EMAD_PATH;
    sxd_ret            = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("failed to set emad path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_MAD_PATH;
    sxd_ret            = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("failed to set mad path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_CR_ACCESS_PATH;
    sxd_ret            = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("failed to set cr access path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    ctrl_pack.ctrl_cmd = CTRL_CMD_RESET;
    ctrl_pack.cmd_body = (void*)SX_DEVICE_ID;
    sxd_ret            = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("failed to reset asic\n");
        return SAI_STATUS_FAILURE;
    }

    pci_profile_single_eth_spectrum.dev_id = SX_DEVICE_ID;
    ctrl_pack.ctrl_cmd                     = CTRL_CMD_SET_PCI_PROFILE;
    ctrl_pack.cmd_body                     = (void*)&(pci_profile_single_eth_spectrum);
    sxd_ret                                = sxd_ioctl(sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "failed to set pci profile in asic\n");
        return SAI_STATUS_FAILURE;
    }

    /* enable device's swid */
    swid_details.dev_id = SX_DEVICE_ID;
    ctrl_pack.cmd_body  = (void*)&(swid_details);
    ctrl_pack.ctrl_cmd  = CTRL_CMD_ENABLE_SWID;
    for (ii = 0; ii < SWID_NUM; ++ii) {
        swid_details.swid        = ii;
        swid_details.iptrap_synd = SXD_TRAP_ID_IPTRAP_MIN + ii;
        cl_plock_acquire(&g_sai_db_ptr->p_lock);
        swid_details.mac = SX_MAC_TO_U64(g_sai_db_ptr->base_mac_addr);
        cl_plock_release(&g_sai_db_ptr->p_lock);

        sxd_ret = sxd_ioctl(sxd_handle, &ctrl_pack);
        if (SXD_CHECK_FAIL(sxd_ret)) {
            printf("failed to enable swid %u : %s\n", ii, strerror(errno));
            return SAI_STATUS_FAILURE;
        }
    }

    sxd_ret = sxd_close_device(sxd_handle);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        fprintf(stderr, "sxd_close_device error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_chassis_mng_stage()
{
    int                  system_err;
    sx_status_t          status;
    sx_api_sx_sdk_init_t sdk_init_params;
    uint32_t             bridge_acls = 0;
    uint8_t              port_phy_bits_num;
    uint8_t              port_pth_bits_num;
    uint8_t              port_sub_bits_num;

    memset(&sdk_init_params, 0, sizeof(sdk_init_params));

#ifdef SDK_VALGRIND
    system_err = system(
        "valgrind --tool=memcheck --leak-check=full --error-exitcode=1 --undef-value-errors=no --run-libc-freeres=yes --max-stackframe=15310736 sx_sdk --logger libsai.so &");
#elif SDK_SNIFFER
    system_err = system("LD_PRELOAD=\"libsxsniffer.so\" sx_sdk --logger libsai.so &");
#elif ACS_OS
    system_err = system("sx_sdk --logger libsai.so &");
#else
    system_err = system("sx_sdk &");
#endif
    if (0 != system_err) {
        fprintf(stderr, "Failed running sx_sdk\n");
        return SAI_STATUS_FAILURE;
    }

    system_err = system("sx_acl_rm &");
    if (0 != system_err) {
        fprintf(stderr, "Failed running sx_acl_rm\n");
        return SAI_STATUS_FAILURE;
    }

#ifdef SDK_VALGRIND
    sleep(10);
#else
    sleep(1);
#endif

#ifndef _WIN32
    openlog("SAI", 0, LOG_USER);
    g_log_init = true;
#endif

    /* Open an handle */
    if (SX_STATUS_SUCCESS != (status = sx_api_open(sai_log_cb, &gh_sdk))) {
        fprintf(stderr, "Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    sdk_init_params.app_id = htonl(*((uint32_t*)"SDK1"));

    sdk_init_params.policer_params.priority_group_num = 3;

    sdk_init_params.port_params.max_dev_id = SX_DEV_ID_MAX;

    sdk_init_params.topo_params.max_num_of_tree_per_chip = 18; /* max num of trees */

    sdk_init_params.lag_params.max_ports_per_lag = 0;
    sdk_init_params.lag_params.default_lag_hash  = SX_LAG_DEFAULT_LAG_HASH;

    sdk_init_params.vlan_params.def_vid     = SX_VLAN_DEFAULT_VID;
    sdk_init_params.vlan_params.max_swid_id = SX_SWID_ID_MAX;

    sdk_init_params.fdb_params.max_mc_group = SX_FDB_MAX_MC_GROUPS;
    sdk_init_params.fdb_params.flood_mode   = FLOOD_PER_VLAN;

    sdk_init_params.mstp_params.mode = SX_MSTP_MODE_MSTP;

    sdk_init_params.router_profile_params.min_router_counters = 16;

    sdk_init_params.acl_params.max_swid_id = 0;

    sdk_init_params.flow_counter_params.flow_counter_byte_type_min_number   = 0;
    sdk_init_params.flow_counter_params.flow_counter_packet_type_min_number = 0;
    sdk_init_params.flow_counter_params.flow_counter_byte_type_max_number   = 100;
    sdk_init_params.flow_counter_params.flow_counter_packet_type_max_number = 155;

    sdk_init_params.acl_params.max_acl_ingress_groups = 95;
    sdk_init_params.acl_params.max_acl_egress_groups  = 31;

    sdk_init_params.acl_params.min_acl_rules = 16;
    sdk_init_params.acl_params.max_acl_rules = 1000;

    sdk_init_params.bridge_init_params.sdk_mode                                          = SX_MODE_802_1Q;
    sdk_init_params.bridge_init_params.sdk_mode_params.mode_1D.max_bridge_num            = 512;
    sdk_init_params.bridge_init_params.sdk_mode_params.mode_1D.max_virtual_ports_num     = 512;
    sdk_init_params.bridge_init_params.sdk_mode_params.mode_1D.multiple_vlan_bridge_mode =
        SX_BRIDGE_MULTIPLE_VLAN_MODE_HOMOGENOUS;
    /* correct the min/max acls according to bridge requirments */
    /* number for homgenous mode egress rules */
    bridge_acls = sdk_init_params.bridge_init_params.sdk_mode_params.mode_1D.max_bridge_num;
    /* number for ingress rules */
    bridge_acls += sdk_init_params.bridge_init_params.sdk_mode_params.mode_1D.max_virtual_ports_num;

    sdk_init_params.acl_params.max_acl_rules += bridge_acls;

    port_phy_bits_num = SX_PORT_UCR_ID_PHY_NUM_OF_BITS;
    port_pth_bits_num = 16;
    port_sub_bits_num = 0;

    if (sdk_init_params.port_params.port_phy_bits_num == 0) {
        sdk_init_params.port_params.port_phy_bits_num = port_phy_bits_num;
    }
    if (sdk_init_params.port_params.port_pth_bits_num == 0) {
        sdk_init_params.port_params.port_pth_bits_num = port_pth_bits_num;
    }
    if (sdk_init_params.port_params.port_sub_bits_num == 0) {
        sdk_init_params.port_params.port_sub_bits_num = port_sub_bits_num;
    }

    memcpy(&(sdk_init_params.profile), &single_part_eth_device_profile_spectrum, sizeof(struct ku_profile));
    memcpy(&(sdk_init_params.pci_profile), &pci_profile_single_eth_spectrum, sizeof(struct sx_pci_profile));
    sdk_init_params.applibs_mask = SX_API_FLOW_COUNTER | SX_API_POLICER | SX_API_HOST_IFC | SX_API_SPAN |
                                   SX_API_ETH_L2 | SX_API_ACL;
    sdk_init_params.profile.chip_type = SXD_CHIP_TYPE_SPECTRUM;

    if (SX_STATUS_SUCCESS != (status = sx_api_sdk_init_set(gh_sdk, &sdk_init_params))) {
        SX_LOG_ERR("Failed to initialize SDK (%s)\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_NTC("SDK initialized successfully\n");

    if (SX_STATUS_SUCCESS != (status = sx_api_system_log_verbosity_level_set(gh_sdk,
                                                                             SX_LOG_VERBOSITY_BOTH,
                                                                             LOG_VAR_NAME(__MODULE__),
                                                                             LOG_VAR_NAME(__MODULE__)))) {
        SX_LOG_ERR("Set system log verbosity failed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
}

#ifndef _WIN32
static sai_status_t parse_port_info(xmlDoc *doc, xmlNode * port_node)
{
    xmlChar *key;
    bool     local_found = false, width_found = false, module_found = false, breakout_found = false, speed_found =
        false;

    if (g_sai_db_ptr->ports_configured >= MAX_PORTS) {
        fprintf(stderr, "Ports configured %u bigger then max %u\n", g_sai_db_ptr->ports_configured, MAX_PORTS);
        return SAI_STATUS_FAILURE;
    }

    while (port_node != NULL) {
        if ((!xmlStrcmp(port_node->name, (const xmlChar*)"local-port"))) {
            key = xmlNodeListGetString(doc,
                                       port_node->xmlChildrenNode,
                                       1);
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].local = (uint32_t)atoi((const char*)key);
            xmlFree(key);
            local_found = true;
        } else if ((!xmlStrcmp(port_node->name, (const xmlChar*)"width"))) {
            key = xmlNodeListGetString(doc,
                                       port_node->children,
                                       1);
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].width = (uint32_t)atoi((const char*)key);
            xmlFree(key);
            width_found = true;
        } else if ((!xmlStrcmp(port_node->name, (const xmlChar*)"module"))) {
            key = xmlNodeListGetString(doc,
                                       port_node->children,
                                       1);
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].module = (uint32_t)atoi((const char*)key);
            xmlFree(key);
            module_found = true;
        } else if ((!xmlStrcmp(port_node->name, (const xmlChar*)"breakout-modes"))) {
            key = xmlNodeListGetString(doc,
                                       port_node->children,
                                       1);
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].breakout_modes = (uint32_t)atoi((const char*)key);
            xmlFree(key);
            breakout_found = true;
        } else if ((!xmlStrcmp(port_node->name, (const xmlChar*)"port-speed"))) {
            key = xmlNodeListGetString(doc,
                                       port_node->children,
                                       1);
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].port_speed = (uint32_t)atoi((const char*)key);
            xmlFree(key);
            speed_found = true;
        }

        port_node = port_node->next;
    }

    if (!local_found || !width_found || !module_found || !breakout_found || !speed_found) {
        fprintf(stderr, "missing port data %u local %u width %u module %u breakout %u speed %u\n",
                g_sai_db_ptr->ports_configured, local_found, width_found, module_found, breakout_found, speed_found);
        return SAI_STATUS_FAILURE;
    }

    fprintf(stdout, "Port %u {local=%u module=%u width=%u breakout-modes=%u, port-speed=%u}\n",
            g_sai_db_ptr->ports_configured,
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].local,
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].module,
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].width,
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].breakout_modes,
            g_sai_db_ptr->ports_db[g_sai_db_ptr->ports_configured].port_speed);
    g_sai_db_ptr->ports_configured++;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t parse_elements(xmlDoc *doc, xmlNode * a_node)
{
    xmlNode       *cur_node, *ports_node;
    xmlChar       *key;
    sai_status_t   status;
    sx_mac_addr_t *base_mac_addr;
    const char    *profile_mac_address;

    /* parse all siblings of current element */
    for (cur_node = a_node; cur_node != NULL; cur_node = cur_node->next) {
        if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"device-mac-address"))) {
            profile_mac_address = g_mlnx_services.profile_get_value(g_profile_id, KV_DEVICE_MAC_ADDRESS);
            if (NULL == profile_mac_address) {
                key = xmlNodeListGetString(doc, cur_node->children, 1);
                fprintf(stdout, "mac: %s\n", key);
                base_mac_addr = ether_aton_r((const char*)key, &g_sai_db_ptr->base_mac_addr);
                strncpy(g_sai_db_ptr->dev_mac, (const char*)key, sizeof(g_sai_db_ptr->dev_mac));
                g_sai_db_ptr->dev_mac[sizeof(g_sai_db_ptr->dev_mac) - 1] = 0;
                xmlFree(key);
            } else {
                fprintf(stdout, "mac k/v: %s\n", profile_mac_address);
                base_mac_addr = ether_aton_r(profile_mac_address, &g_sai_db_ptr->base_mac_addr);
                strncpy(g_sai_db_ptr->dev_mac, profile_mac_address, sizeof(g_sai_db_ptr->dev_mac));
                g_sai_db_ptr->dev_mac[sizeof(g_sai_db_ptr->dev_mac) - 1] = 0;
            }
            if (base_mac_addr == NULL) {
                fprintf(stderr, "Error parsing device mac address\n");
                return SAI_STATUS_FAILURE;
            }
            if (base_mac_addr->ether_addr_octet[5] & (~PORT_MAC_BITMASK)) {
                fprintf(stderr,
                        "Device mac address must be aligned by %u %02x\n",
                        (~PORT_MAC_BITMASK) + 1,
                        base_mac_addr->ether_addr_octet[5]);
                return SAI_STATUS_FAILURE;
            }
        } else if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"number-of-physical-ports"))) {
            key                        = xmlNodeListGetString(doc, cur_node->children, 1);
            g_sai_db_ptr->ports_number = (uint32_t)atoi((const char*)key);
            fprintf(stdout, "ports num: %u\n", g_sai_db_ptr->ports_number);
            xmlFree(key);
            if (g_sai_db_ptr->ports_number > MAX_PORTS) {
                fprintf(stderr, "Ports number %u bigger then max %u\n", g_sai_db_ptr->ports_number, MAX_PORTS);
                return SAI_STATUS_FAILURE;
            }
        } else if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"ports-list"))) {
            for (ports_node = cur_node->children; ports_node != NULL; ports_node = ports_node->next) {
                if ((!xmlStrcmp(ports_node->name, (const xmlChar*)"port-info"))) {
                    if (SAI_STATUS_SUCCESS != (status = parse_port_info(doc, ports_node->children))) {
                        return status;
                    }
                }
            }
        } else {
            /* parse all children of current element */
            if (SAI_STATUS_SUCCESS != (status = parse_elements(doc, cur_node->children))) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_parse_config(const char *config_file)
{
    xmlDoc      *doc          = NULL;
    xmlNode     *root_element = NULL;
    sai_status_t status;

    LIBXML_TEST_VERSION;

    doc = xmlReadFile(config_file, NULL, 0);

    if (doc == NULL) {
        fprintf(stderr, "could not parse config file %s\n", config_file);
        return SAI_STATUS_FAILURE;
    }

    root_element = xmlDocGetRootElement(doc);

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    status = parse_elements(doc, root_element);

    if (g_sai_db_ptr->ports_configured != g_sai_db_ptr->ports_number) {
        fprintf(stderr, "mismatch of port number and configuration %u %u\n",
                g_sai_db_ptr->ports_configured, g_sai_db_ptr->ports_number);
        status = SAI_STATUS_FAILURE;
    }

    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return status;
}
#else /* ifndef _WIN32 */
static sai_status_t mlnx_parse_config(const char *config_file)
{
    UNUSED_PARAM(config_file);
    return SAI_STATUS_SUCCESS;
}
#endif /* ifndef _WIN32 */

static void sai_db_policer_entries_init()
{
    uint32_t ii = 0, policers_cnt = MLNX_SAI_ARRAY_LEN(g_sai_db_ptr->policers_db);

    for (ii = 0; ii < policers_cnt; ii++) {
        db_reset_policer_entry(ii);
    }
}

static void sai_db_values_init()
{
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    memset(&g_sai_db_ptr->base_mac_addr, 0, sizeof(g_sai_db_ptr->base_mac_addr));
    memset(g_sai_db_ptr->dev_mac, 0, sizeof(g_sai_db_ptr->dev_mac));
    g_sai_db_ptr->ports_configured = 0;
    g_sai_db_ptr->ports_number     = 0;
    memset(g_sai_db_ptr->ports_db, 0, sizeof(g_sai_db_ptr->ports_db));
    memset(g_sai_db_ptr->fd_db, 0, sizeof(g_sai_db_ptr->fd_db));
    g_sai_db_ptr->default_trap_group = SAI_NULL_OBJECT_ID;
    g_sai_db_ptr->default_vrid       = SAI_NULL_OBJECT_ID;
    memset(&g_sai_db_ptr->callback_channel, 0, sizeof(g_sai_db_ptr->callback_channel));
    memset(g_sai_db_ptr->traps_db, 0, sizeof(g_sai_db_ptr->traps_db));
    memset(g_sai_db_ptr->qos_maps_db, 0, sizeof(g_sai_db_ptr->qos_maps_db));
    g_sai_db_ptr->switch_default_tc = 0;
    memset(g_sai_db_ptr->ports_default_tc, 0, sizeof(g_sai_db_ptr->ports_default_tc));
    memset(g_sai_db_ptr->policers_db, 0, sizeof(g_sai_db_ptr->policers_db));
    memset(g_sai_db_ptr->mlnx_samplepacket_session, 0, sizeof(g_sai_db_ptr->mlnx_samplepacket_session));
    memset(g_sai_db_ptr->trap_group_valid, 0, sizeof(g_sai_db_ptr->trap_group_valid));

    sai_db_policer_entries_init();

    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    sai_qos_db_init();
    memset(g_sai_qos_db_ptr->wred_db, 0, sizeof(mlnx_wred_profile_t) * g_resource_limits.cos_redecn_profiles_max);
    memset(g_sai_qos_db_ptr->queue_db, 0,
           sizeof(mlnx_qos_queue_config_t) * (g_resource_limits.cos_port_ets_traffic_class_max + 1) * MAX_PORTS);
    memset(g_sai_qos_db_ptr->sched_db, 0, sizeof(mlnx_sched_profile_t) * MAX_SCHED);

    sai_qos_db_sync();

    cl_plock_release(&g_sai_db_ptr->p_lock);
}

static sai_status_t sai_db_unload(boolean_t erase_db)
{
    int          err    = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (erase_db == TRUE) {
        cl_shm_destroy(SAI_PATH);
        if (g_sai_db_ptr != NULL) {
            cl_plock_destroy(&g_sai_db_ptr->p_lock);
        }
    }

    if (g_sai_db_ptr != NULL) {
        err = munmap(g_sai_db_ptr, sizeof(*g_sai_db_ptr));
        if (err == -1) {
            SX_LOG_ERR("Failed to unmap the shared memory of the SAI DB\n");
            status = SAI_STATUS_FAILURE;
        }

        g_sai_db_ptr = NULL;
    }

    return status;
}

static sai_status_t sai_db_create()
{
    int         shmid;
    cl_status_t cl_err;

    cl_err = cl_shm_create(SAI_PATH, &shmid);
    if (cl_err) {
        if (errno == EEXIST) { /* one retry is allowed */
            fprintf(stderr, "Shared memory of the SAI already exists, destroying it and re-creating\n");
            cl_shm_destroy(SAI_PATH);
            cl_err = cl_shm_create(SAI_PATH, &shmid);
        }

        if (cl_err) {
            fprintf(stderr, "Failed to create shared memory for SAI DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }
    }

    if (ftruncate(shmid, sizeof(*g_sai_db_ptr)) == -1) {
        fprintf(stderr, "Failed to set shared memory size for the SAI DB\n");
        cl_shm_destroy(SAI_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    g_sai_db_ptr = mmap(NULL, sizeof(*g_sai_db_ptr), PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
    if (g_sai_db_ptr == MAP_FAILED) {
        fprintf(stderr, "Failed to map the shared memory of the SAI DB\n");
        g_sai_db_ptr = NULL;
        cl_shm_destroy(SAI_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    cl_err = cl_plock_init_pshared(&g_sai_db_ptr->p_lock);
    if (cl_err) {
        fprintf(stderr, "Failed to initialize the SAI DB rwlock\n");
        munmap(g_sai_db_ptr, sizeof(*g_sai_db_ptr));
        g_sai_db_ptr = NULL;
        cl_shm_destroy(SAI_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_dvs_mng_stage()
{
    sai_status_t                              status;
    int                                       system_err;
    char                                      cmd[200];
    sx_port_attributes_t                     *port_attributes_p = NULL;
    uint32_t                                  ii, jj;
    sx_topolib_dev_info_t                     dev_info;
    struct                        ku_pmlp_reg pmlp_reg;
    sxd_reg_meta_t                            reg_meta;
    sxd_status_t                              sxd_status;
    sx_port_speed_capability_t                admin_speed;
    sx_vlan_ports_t                           vlan_port;
    sai_port_event_notification_t             event_data;
    mlnx_qos_port_config_t                   *qos_port;
    uint32_t                                  tc;

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    if (SX_STATUS_SUCCESS != (status = sx_api_port_swid_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID))) {
        SX_LOG_ERR("Port swid set failed - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    /* Set MAC address */
    snprintf(cmd, sizeof(cmd), "ip link set address %s dev swid0_eth > /dev/null 2>&1", g_sai_db_ptr->dev_mac);
    system_err = system(cmd);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", cmd);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    /* Take swid netdev up */
    snprintf(cmd, sizeof(cmd), "ip -4 addr flush dev swid0_eth");
    system_err = system(cmd);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", cmd);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    port_attributes_p = (sx_port_attributes_t*)malloc(sizeof(*port_attributes_p) * g_sai_db_ptr->ports_number);
    if (NULL == port_attributes_p) {
        SX_LOG_ERR("Can't allocate port attributes\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    memset(port_attributes_p, 0, sizeof(*port_attributes_p) * g_sai_db_ptr->ports_number);

    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        port_attributes_p[ii].port_mode                 = SX_PORT_MODE_EXTERNAL;
        port_attributes_p[ii].port_mapping.config_hw    = false;
        port_attributes_p[ii].port_mapping.lane_bmap    = 0xf;
        port_attributes_p[ii].port_mapping.local_port   = g_sai_db_ptr->ports_db[ii].local;
        port_attributes_p[ii].port_mapping.mapping_mode = SX_PORT_MAPPING_MODE_ENABLE;
        port_attributes_p[ii].port_mapping.module_port  = g_sai_db_ptr->ports_db[ii].module;
        port_attributes_p[ii].port_mapping.width        = g_sai_db_ptr->ports_db[ii].width;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_port_device_set(gh_sdk, SX_ACCESS_CMD_ADD, SX_DEVICE_ID, &g_sai_db_ptr->base_mac_addr,
                                         port_attributes_p, g_sai_db_ptr->ports_number))) {
        SX_LOG_ERR("Port device set failed - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        g_sai_db_ptr->ports_db[ii].logical = port_attributes_p[ii].log_port;
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, g_sai_db_ptr->ports_db[ii].logical, NULL,
                                         &g_sai_db_ptr->ports_db[ii].saiport))) {
            goto out;
        }
    }

    dev_info.dev_id          = SX_DEVICE_ID;
    dev_info.node_type       = SX_DEV_NODE_TYPE_LEAF_LOCAL;
    dev_info.unicast_arr_len = 0;
    /* TODO : fill switch_mac_addr */

    if (SX_STATUS_SUCCESS != (status = sx_api_topo_device_set(gh_sdk, SX_ACCESS_CMD_ADD, &dev_info))) {
        SX_LOG_ERR("topo device add failed - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_topo_device_set(gh_sdk, SX_ACCESS_CMD_READY, &dev_info))) {
        SX_LOG_ERR("topo device set ready failed - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (g_notification_callbacks.on_switch_state_change) {
        g_notification_callbacks.on_switch_state_change(SAI_SWITCH_OPER_STATUS_UP);
    }

    memset(&pmlp_reg, 0, sizeof(struct ku_pmlp_reg));
    memset(&reg_meta, 0, sizeof(reg_meta));
    reg_meta.swid       = DEFAULT_ETH_SWID;
    reg_meta.dev_id     = SX_DEVICE_ID;
    reg_meta.access_cmd = SXD_ACCESS_CMD_SET;
    pmlp_reg.width      = 0;

    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        pmlp_reg.local_port = g_sai_db_ptr->ports_db[ii].local;

        sxd_status = sxd_access_reg_pmlp(&pmlp_reg, &reg_meta, 1, NULL, NULL);
        if (SXD_CHECK_FAIL(sxd_status)) {
            SX_LOG_ERR("pmlp unbind %u failed - %s.\n", pmlp_reg.local_port, SXD_STATUS_MSG(sxd_status));
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        pmlp_reg.local_port = g_sai_db_ptr->ports_db[ii].local;
        pmlp_reg.width      = g_sai_db_ptr->ports_db[ii].width;

        for (jj = 0; jj < pmlp_reg.width; ++jj) {
            pmlp_reg.module[jj] = g_sai_db_ptr->ports_db[ii].module;
            pmlp_reg.lane[jj]   = jj;
        }

        sxd_status = sxd_access_reg_pmlp(&pmlp_reg, &reg_meta, 1, NULL, NULL);
        if (SXD_CHECK_FAIL(sxd_status)) {
            SX_LOG_ERR("pmlp bind %u failed - %s.\n", pmlp_reg.local_port, SXD_STATUS_MSG(sxd_status));
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    memset(&vlan_port, 0, sizeof(vlan_port));
    vlan_port.is_untagged = true;
    event_data.port_event = SAI_PORT_EVENT_ADD;

    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 mlnx_port_speed_convert_bitmap_to_capability(g_sai_db_ptr->ports_db[ii].port_speed, &admin_speed))) {
            SX_LOG_ERR("failed to convert port %x speed %d\n",
                       g_sai_db_ptr->ports_db[ii].logical,
                       g_sai_db_ptr->ports_db[ii].port_speed);
            goto out;
        }

        if (SX_STATUS_SUCCESS !=
            (status = sx_api_port_swid_bind_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical, DEFAULT_ETH_SWID))) {
            SX_LOG_ERR("port swid bind %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_port_init_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical))) {
            SX_LOG_ERR("port init set %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_rstp_port_state_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical,
                                                                      SX_MSTP_INST_PORT_STATE_FORWARDING))) {
            SX_LOG_ERR("port rstp state set %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical,
                       SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_port_speed_admin_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical,
                                                                       &admin_speed))) {
            SX_LOG_ERR("port admin speed set %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical,
                       SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_port_state_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical,
                                                                 SX_PORT_ADMIN_STATUS_DOWN))) {
            SX_LOG_ERR("port state set %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_port_phys_loopback_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical,
                                                                         SX_PORT_PHYS_LOOPBACK_DISABLE))) {
            SX_LOG_ERR("port phys loopback set %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical,
                       SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                                                     g_sai_db_ptr->ports_db[ii].logical,
                                                                     DEFAULT_VLAN))) {
            SX_LOG_ERR("port pvid set %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        vlan_port.log_port = g_sai_db_ptr->ports_db[ii].logical;
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, DEFAULT_VLAN,
                                            &vlan_port, 1))) {
            SX_LOG_ERR("port add port %x to vlan %u failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical,
                       DEFAULT_VLAN, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_ingr_filter_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical,
                                                                            SX_INGR_FILTER_ENABLE))) {
            SX_LOG_ERR("port ingress filter set %x failed - %s.\n", g_sai_db_ptr->ports_db[ii].logical,
                       SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        if (!(SX_PORT_TYPE_ID_GET(g_sai_db_ptr->ports_db[ii].logical) & SX_PORT_TYPE_VPORT)) {
            status = sx_api_cos_port_trust_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical, SX_COS_TRUST_LEVEL_PORT);
            if (status != SX_STATUS_SUCCESS) {
                SX_LOG_ERR("port trust level set %x failed - %s.\n",
                           g_sai_db_ptr->ports_db[ii].logical, SX_STATUS_MSG(status));
                status = sdk_to_sai(status);
                goto out;
            }
        }

        status = sx_api_port_global_fc_enable_set(gh_sdk, g_sai_db_ptr->ports_db[ii].logical,
                                                  SX_PORT_FLOW_CTRL_MODE_TX_DIS_RX_DIS);
        if (status != SX_STATUS_SUCCESS) {
            SX_LOG_ERR("Failed to init port global flow control - %s\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        event_data.port_id = g_sai_db_ptr->ports_db[ii].saiport;
        if (g_notification_callbacks.on_port_event) {
            g_notification_callbacks.on_port_event(1, &event_data);
        }
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_init())) {
        goto out;
    }

    jj = 0;
    qos_port_foreach(qos_port, ii) {
        qos_port->wred_id            = SAI_NULL_OBJECT_ID;
        qos_port->scheduler_id       = SAI_NULL_OBJECT_ID;
        qos_port->log_port_id        = g_sai_db_ptr->ports_db[ii].logical;
        qos_port->start_queues_index = jj;

        for (tc = 0; tc <= MAX_ETS_TC; tc++, jj++) {
            g_sai_qos_db_ptr->queue_db[jj].wred_id                = SAI_NULL_OBJECT_ID;
            g_sai_qos_db_ptr->queue_db[jj].sched_obj.scheduler_id = SAI_NULL_OBJECT_ID;
        }

        if (SX_PORT_TYPE_ID_GET(qos_port->log_port_id) & SX_PORT_TYPE_VPORT) {
            continue;
        }

        status = mlnx_sched_group_port_init(qos_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed initialize SAI scheduler groups for log port 0x%x\n",
                       g_sai_db_ptr->ports_db[ii].logical);

            goto out;
        }
    }
    sai_qos_db_sync();

out:
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    if (NULL != port_attributes_p) {
        free(port_attributes_p);
    }
    return status;
}

static sai_status_t mlnx_switch_parse_fdb_event(uint8_t                           *p_packet,
                                                sx_receive_info_t                 *receive_info,
                                                sai_fdb_event_notification_data_t *fdb_events,
                                                uint32_t                          *event_count,
                                                sai_attribute_t                   *attr_list)
{
    uint32_t                    ii       = 0;
    sx_fdb_notify_data_t       *packet   = (sx_fdb_notify_data_t*)p_packet;
    sai_attribute_t            *attr_ptr = attr_list;
    sai_status_t                status   = SAI_STATUS_SUCCESS;
    sx_fdb_uc_mac_addr_params_t mac_entry;
    uint32_t                    entries_count = 1;
    sai_object_id_t             port_id       = SAI_NULL_OBJECT_ID;
    uint16_t                    vlan_id       = 0;
    sai_mac_t                   mac_addr;
    sx_access_cmd_t             cmd = SX_ACCESS_CMD_ADD;

    memset(&mac_entry, 0, sizeof(mac_entry));

    for (ii = 0; ii < packet->records_num; ii++) {
        SX_LOG_INF("FDB event received [%u] vlan: %4u ; mac: %x:%x:%x:%x:%x:%x ; log_port: (0x%08X) ; type: %s(%d)\n",
                   ii,
                   packet->records_arr[ii].fid,
                   packet->records_arr[ii].mac_addr.ether_addr_octet[0],
                   packet->records_arr[ii].mac_addr.ether_addr_octet[1],
                   packet->records_arr[ii].mac_addr.ether_addr_octet[2],
                   packet->records_arr[ii].mac_addr.ether_addr_octet[3],
                   packet->records_arr[ii].mac_addr.ether_addr_octet[4],
                   packet->records_arr[ii].mac_addr.ether_addr_octet[5],
                   packet->records_arr[ii].log_port,
                   SX_FDB_NOTIFY_TYPE_STR(packet->records_arr[ii].type),
                   packet->records_arr[ii].type);

        port_id = SAI_NULL_OBJECT_ID;
        vlan_id = 0;
        memset(mac_addr, 0, sizeof(mac_addr));

        switch (packet->records_arr[ii].type) {
        case SX_FDB_NOTIFY_TYPE_NEW_MAC_LAG:
        case SX_FDB_NOTIFY_TYPE_NEW_MAC_PORT:
            fdb_events[ii].event_type = SAI_FDB_EVENT_LEARNED;
            memcpy(&mac_addr, packet->records_arr[ii].mac_addr.ether_addr_octet, sizeof(mac_addr));
            vlan_id = packet->records_arr[ii].fid;
            status  = mlnx_create_object(
                (packet->records_arr[ii].type == SX_FDB_NOTIFY_TYPE_NEW_MAC_PORT) ? SAI_OBJECT_TYPE_PORT : SAI_OBJECT_TYPE_LAG,
                packet->records_arr[ii].log_port,
                NULL,
                &port_id);
            if (SAI_STATUS_SUCCESS != status) {
                return status;
            }
            cmd = SX_ACCESS_CMD_ADD;
            break;

        case SX_FDB_NOTIFY_TYPE_AGED_MAC_LAG:
        case SX_FDB_NOTIFY_TYPE_AGED_MAC_PORT:
            fdb_events[ii].event_type = SAI_FDB_EVENT_AGED;
            memcpy(&mac_addr, packet->records_arr[ii].mac_addr.ether_addr_octet, sizeof(mac_addr));
            vlan_id = packet->records_arr[ii].fid;
            status  = mlnx_create_object(
                (packet->records_arr[ii].type == SX_FDB_NOTIFY_TYPE_AGED_MAC_PORT) ? SAI_OBJECT_TYPE_PORT : SAI_OBJECT_TYPE_LAG,
                packet->records_arr[ii].log_port,
                NULL,
                &port_id);
            if (SAI_STATUS_SUCCESS != status) {
                return status;
            }
            cmd = SX_ACCESS_CMD_DELETE;
            break;

        case SX_FDB_NOTIFY_TYPE_FLUSH_ALL:
            fdb_events[ii].event_type = SAI_FDB_EVENT_FLUSHED;
            break;

        case SX_FDB_NOTIFY_TYPE_FLUSH_LAG:
        case SX_FDB_NOTIFY_TYPE_FLUSH_PORT:
            fdb_events[ii].event_type = SAI_FDB_EVENT_FLUSHED;
            status                    =
                mlnx_create_object(
                    (packet->records_arr[ii].type == SX_FDB_NOTIFY_TYPE_FLUSH_PORT) ? SAI_OBJECT_TYPE_PORT : SAI_OBJECT_TYPE_LAG,
                    packet->records_arr[ii].log_port,
                    NULL,
                    &port_id);
            if (SAI_STATUS_SUCCESS != status) {
                return status;
            }
            break;

        case SX_FDB_NOTIFY_TYPE_FLUSH_FID:
            fdb_events[ii].event_type = SAI_FDB_EVENT_FLUSHED;
            vlan_id                   = packet->records_arr[ii].fid;
            break;

        case SX_FDB_NOTIFY_TYPE_FLUSH_LAG_FID:
        case SX_FDB_NOTIFY_TYPE_FLUSH_PORT_FID:
            fdb_events[ii].event_type = SAI_FDB_EVENT_FLUSHED;
            status                    =
                mlnx_create_object(
                    (packet->records_arr[ii].type == SX_FDB_NOTIFY_TYPE_FLUSH_PORT_FID) ? SAI_OBJECT_TYPE_PORT : SAI_OBJECT_TYPE_LAG,
                    packet->records_arr[ii].log_port,
                    NULL,
                    &port_id);
            if (SAI_STATUS_SUCCESS != status) {
                return status;
            }
            vlan_id = packet->records_arr[ii].fid;
            break;

        default:
            return SAI_STATUS_FAILURE;
        }

        memcpy(&fdb_events[ii].fdb_entry.mac_address, mac_addr,
               sizeof(fdb_events[ii].fdb_entry.mac_address));
        fdb_events[ii].fdb_entry.vlan_id = vlan_id;

        fdb_events[ii].attr       = attr_ptr;
        fdb_events[ii].attr_count = FDB_NOTIF_ATTRIBS_NUM;

        attr_ptr->id        = SAI_FDB_ENTRY_ATTR_PORT_ID;
        attr_ptr->value.oid = port_id;
        ++attr_ptr;

        attr_ptr->id        = SAI_FDB_ENTRY_ATTR_TYPE;
        attr_ptr->value.s32 = SAI_FDB_ENTRY_DYNAMIC;
        ++attr_ptr;

        attr_ptr->id        = SAI_FDB_ENTRY_ATTR_PACKET_ACTION;
        attr_ptr->value.s32 = SAI_PACKET_ACTION_FORWARD;
        ++attr_ptr;

        if (fdb_events[ii].event_type != SAI_FDB_EVENT_FLUSHED) {
            /* learn or age event */
            mac_entry.fid_vid  = packet->records_arr[ii].fid;
            mac_entry.log_port = packet->records_arr[ii].log_port;
            memcpy(&mac_entry.mac_addr, fdb_events[ii].fdb_entry.mac_address, sizeof(mac_entry.mac_addr));
            mac_entry.entry_type = SX_FDB_UC_AGEABLE;
            mac_entry.action     = SX_FDB_ACTION_FORWARD;

            status = sx_api_fdb_uc_mac_addr_set(gh_sdk, cmd, DEFAULT_ETH_SWID, &mac_entry, &entries_count);
            if (SX_STATUS_SUCCESS != status) {
                SX_LOG_ERR("Failed to %s fdb entry - %s.\n",
                           (cmd == SX_ACCESS_CMD_ADD) ? "add" : "remove",
                           SX_STATUS_MSG(status));
                return sdk_to_sai(status);
            }
        }
    }
    *event_count = packet->records_num;
    return SAI_STATUS_SUCCESS;
}

static void event_thread_func(void *context)
{
    sx_status_t       status;
    sx_api_handle_t   api_handle;
    sx_user_channel_t port_channel, callback_channel;
    fd_set            descr_set;
    int               ret_val;

    #define MAX_PACKET_SIZE 10240
    uint8_t                            *p_packet    = NULL;
    uint32_t                            packet_size = MAX_PACKET_SIZE;
    sx_receive_info_t                   receive_info;
    sai_port_oper_status_notification_t port_data;
    struct timeval                      timeout;
    sai_attribute_t                     callback_data[RECV_ATTRIBS_NUM];
    sai_hostif_trap_id_t                trap_id;
    const char                         *trap_name;
    sai_fdb_event_notification_data_t  *fdb_events  = NULL;
    sai_attribute_t                    *attr_list   = NULL;
    uint32_t                            event_count = 0;

    memset(&port_channel, 0, sizeof(port_channel));
    memset(&callback_channel, 0, sizeof(callback_channel));

    callback_data[0].id = SAI_HOSTIF_PACKET_ATTR_TRAP_ID;
    callback_data[1].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT;
    callback_data[2].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG;

    if (SX_STATUS_SUCCESS != (status = sx_api_open(sai_log_cb, &api_handle))) {
        fprintf(stderr, "Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
        if (g_notification_callbacks.on_switch_shutdown_request) {
            g_notification_callbacks.on_switch_shutdown_request();
        }
        return;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_open(api_handle, &port_channel.channel.fd))) {
        SX_LOG_ERR("host ifc open port fd failed - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    p_packet = (uint8_t*)malloc(sizeof(*p_packet) * MAX_PACKET_SIZE);
    if (NULL == p_packet) {
        SX_LOG_ERR("Can't allocate packet memory\n");
        status = SX_STATUS_ERROR;
        goto out;
    }

    fdb_events = calloc(SX_FDB_NOTIFY_SIZE_MAX, sizeof(sai_fdb_event_notification_data_t));
    if (NULL == fdb_events) {
        SX_LOG_ERR("Can't allocate memory for fdb events\n");
        status = SX_STATUS_ERROR;
        goto out;
    }

    attr_list = calloc(SX_FDB_NOTIFY_SIZE_MAX * FDB_NOTIF_ATTRIBS_NUM, sizeof(sai_attribute_t));
    if (NULL == attr_list) {
        SX_LOG_ERR("Can't allocate memory for attribute list\n");
        status = SX_STATUS_ERROR;
        goto out;
    }

    port_channel.type = SX_USER_CHANNEL_TYPE_FD;
    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_register_set(api_handle, SX_ACCESS_CMD_REGISTER,
                                                                            DEFAULT_ETH_SWID, SX_TRAP_ID_PUDE,
                                                                            &port_channel))) {
        SX_LOG_ERR("host ifc trap register PUDE failed - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    memcpy(&callback_channel, &g_sai_db_ptr->callback_channel, sizeof(callback_channel));
    cl_plock_release(&g_sai_db_ptr->p_lock);

    while (!event_thread_asked_to_stop) {
        FD_ZERO(&descr_set);
        FD_SET(port_channel.channel.fd.fd, &descr_set);
        FD_SET(callback_channel.channel.fd.fd, &descr_set);

        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        ret_val = select(FD_SETSIZE, &descr_set, NULL, NULL, &timeout);

        if (-1 == ret_val) {
            SX_LOG_ERR("select ended with error/interrupt %s\n", strerror(errno));
            status = SX_STATUS_ERROR;
            goto out;
        }

        packet_size = MAX_PACKET_SIZE;

        if (ret_val > 0) {
            if (FD_ISSET(port_channel.channel.fd.fd, &descr_set)) {
                if (SX_STATUS_SUCCESS !=
                    (status = sx_lib_host_ifc_recv(&port_channel.channel.fd, p_packet, &packet_size, &receive_info))) {
                    SX_LOG_ERR("sx_api_host_ifc_recv on port fd failed with error %s\n", SX_STATUS_MSG(status));
                    goto out;
                }

                if (SX_INVALID_PORT == receive_info.source_log_port) {
                    SX_LOG_WRN("sx_api_host_ifc_recv on port fd returned unknown port, waiting for next packet\n");
                    continue;
                }

                if (SAI_STATUS_SUCCESS !=
                    (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, receive_info.event_info.pude.log_port, NULL,
                                                 &port_data.port_id))) {
                    goto out;
                }

                if (SX_PORT_OPER_STATUS_UP == receive_info.event_info.pude.oper_state) {
                    port_data.port_state = SAI_PORT_OPER_STATUS_UP;
                } else {
                    port_data.port_state = SAI_PORT_OPER_STATUS_DOWN;
                }
                SX_LOG_NTC("Port %x changed state to %s\n", receive_info.event_info.pude.log_port,
                           (SX_PORT_OPER_STATUS_UP == receive_info.event_info.pude.oper_state) ? "up" : "down");

                if (g_notification_callbacks.on_port_state_change) {
                    g_notification_callbacks.on_port_state_change(1, &port_data);
                }
            }

            if (FD_ISSET(callback_channel.channel.fd.fd, &descr_set)) {
                if (SX_STATUS_SUCCESS !=
                    (status =
                         sx_lib_host_ifc_recv(&callback_channel.channel.fd, p_packet, &packet_size, &receive_info))) {
                    SX_LOG_ERR("sx_api_host_ifc_recv on callback fd failed with error %s\n", SX_STATUS_MSG(status));
                    goto out;
                }

                if (SAI_STATUS_SUCCESS !=
                    (status = mlnx_translate_sdk_trap_to_sai(receive_info.trap_id, &trap_id, &trap_name))) {
                    SX_LOG_WRN("unknown sdk trap %u, waiting for next packet\n", receive_info.trap_id);
                    continue;
                }

                if (SX_TRAP_ID_FDB_EVENT == receive_info.trap_id) {
                    SX_LOG_INF("Received trap %s sdk %u\n", trap_name, receive_info.trap_id);

                    if (SAI_STATUS_SUCCESS != (status = mlnx_switch_parse_fdb_event(p_packet, &receive_info,
                                                                                    fdb_events, &event_count,
                                                                                    attr_list))) {
                        goto out;
                    }

                    if (g_notification_callbacks.on_fdb_event) {
                        g_notification_callbacks.on_fdb_event(event_count, fdb_events);
                    }

                    continue;
                }

                if (SX_INVALID_PORT == receive_info.source_log_port) {
                    SX_LOG_WRN("sx_api_host_ifc_recv on callback fd returned unknown port, waiting for next packet\n");
                    continue;
                }

                callback_data[0].value.s32 = trap_id;

                if (SAI_STATUS_SUCCESS !=
                    (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, receive_info.source_log_port, NULL,
                                                 &callback_data[1].value.oid))) {
                    goto out;
                }

                if (receive_info.is_lag) {
                    if (SAI_STATUS_SUCCESS !=
                        (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, receive_info.source_lag_port, NULL,
                                                     &callback_data[2].value.oid))) {
                        goto out;
                    }
                } else {
                    callback_data[2].value.oid = SAI_NULL_OBJECT_ID;
                }

                SX_LOG_INF("Received trap %s sdk %u port %x is lag %u %x\n", trap_name, receive_info.trap_id,
                           receive_info.source_log_port, receive_info.is_lag, receive_info.source_lag_port);

                if (g_notification_callbacks.on_packet_event) {
                    g_notification_callbacks.on_packet_event(p_packet, packet_size, RECV_ATTRIBS_NUM, callback_data);
                }
            }
        }
    }

out:
    SX_LOG_NTC("Closing event thread - %s.\n", SX_STATUS_MSG(status));

    if (SX_STATUS_SUCCESS != status) {
        if (g_notification_callbacks.on_switch_shutdown_request) {
            g_notification_callbacks.on_switch_shutdown_request();
        }
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_close(api_handle, &port_channel.channel.fd))) {
        SX_LOG_ERR("host ifc close port fd failed - %s.\n", SX_STATUS_MSG(status));
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_close(api_handle, &callback_channel.channel.fd))) {
        SX_LOG_ERR("host ifc close callback fd failed - %s.\n", SX_STATUS_MSG(status));
    }
    memset(&g_sai_db_ptr->callback_channel, 0, sizeof(g_sai_db_ptr->callback_channel));
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);

    if (NULL != p_packet) {
        free(p_packet);
    }

    if (NULL != fdb_events) {
        free(fdb_events);
    }

    if (NULL != attr_list) {
        free(attr_list);
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&api_handle))) {
        SX_LOG_ERR("API close failed.\n");
    }
}

/* Arrange memory for QoS DB.
 *  *wred_db
 *  *sched_db
 *  *qos_port_db
 *  array for all wred profiles
 *  array of port qos config
 *  array of all queues for all ports
 */
static void sai_qos_db_init()
{
    g_sai_qos_db_ptr->wred_db = (mlnx_wred_profile_t*)(((uint8_t*)g_sai_qos_db_ptr->db_base_ptr));

    g_sai_qos_db_ptr->sched_db = (mlnx_sched_profile_t*)((uint8_t*)g_sai_qos_db_ptr->wred_db +
                                                         (sizeof(mlnx_wred_profile_t) *
                                                          g_resource_limits.cos_redecn_profiles_max));

    g_sai_qos_db_ptr->qos_port_db = (mlnx_qos_port_config_t*)((uint8_t*)g_sai_qos_db_ptr->sched_db +
                                                              sizeof(mlnx_sched_profile_t) * MAX_SCHED);

    g_sai_qos_db_ptr->queue_db = (mlnx_qos_queue_config_t*)((uint8_t*)g_sai_qos_db_ptr->qos_port_db +
                                                            (sizeof(mlnx_qos_port_config_t) * MAX_PORTS));
}

static sai_status_t sai_qos_db_unload(boolean_t erase_db)
{
    int          err    = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (erase_db == TRUE) {
        cl_shm_destroy(SAI_QOS_PATH);
    }

    if (g_sai_qos_db_ptr == NULL) {
        return status;
    }

    if (g_sai_qos_db_ptr->db_base_ptr != NULL) {
        err = munmap(g_sai_qos_db_ptr->db_base_ptr, g_sai_qos_db_size);
        if (err == -1) {
            SX_LOG_ERR("Failed to unmap the shared memory of the SAI QOS DB\n");
            status = SAI_STATUS_FAILURE;
        }
    }

    free(g_sai_qos_db_ptr);
    g_sai_qos_db_ptr = NULL;

    return status;
}

static uint32_t sai_qos_db_size_get()
{
    return ((sizeof(mlnx_wred_profile_t) * g_resource_limits.cos_redecn_profiles_max) +
            (((sizeof(mlnx_qos_queue_config_t) * (g_resource_limits.cos_port_ets_traffic_class_max + 1)) +
              sizeof(mlnx_qos_port_config_t)) * MAX_PORTS) +
            sizeof(mlnx_sched_profile_t) * MAX_SCHED);
}

/* g_resource_limits must be initialized before we call create,
 * we need it to calculate size of shared memory */
static sai_status_t sai_qos_db_create()
{
    int         shmid;
    cl_status_t cl_err;

    cl_err = cl_shm_create(SAI_QOS_PATH, &shmid);
    if (cl_err) {
        if (errno == EEXIST) { /* one retry is allowed */
            SX_LOG_WRN("Shared memory of the SAI QOS already exists, destroying it and re-creating\n");
            cl_shm_destroy(SAI_QOS_PATH);
            cl_err = cl_shm_create(SAI_QOS_PATH, &shmid);
        }

        if (cl_err) {
            SX_LOG_ERR("Failed to create shared memory for SAI QOS DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }
    }

    g_sai_qos_db_size = sai_qos_db_size_get();

    if (ftruncate(shmid, g_sai_qos_db_size) == -1) {
        SX_LOG_ERR("Failed to set shared memory size for the SAI QOS DB\n");
        cl_shm_destroy(SAI_QOS_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    g_sai_qos_db_ptr = malloc(sizeof(*g_sai_qos_db_ptr));
    if (g_sai_qos_db_ptr == NULL) {
        SX_LOG_ERR("Failed to allocate SAI QoS DB structure\n");
        return SAI_STATUS_NO_MEMORY;
    }

    g_sai_qos_db_ptr->db_base_ptr = mmap(NULL, g_sai_qos_db_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
    if (g_sai_qos_db_ptr->db_base_ptr == MAP_FAILED) {
        SX_LOG_ERR("Failed to map the shared memory of the SAI QOS DB\n");
        g_sai_qos_db_ptr->db_base_ptr = NULL;
        cl_shm_destroy(SAI_QOS_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    return SAI_STATUS_SUCCESS;
}

/* NOTE:  g_sai_db_ptr->ports_number must be initializes before calling this method*/
static void sai_buffer_db_values_init()
{
    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    assert(g_sai_db_ptr->ports_number != 0);
    sai_buffer_db_pointers_init();
#ifdef SAI_BUFFER_SELF_CHECK
    sai_buffer_db_data_reset();
    assert(true == self_check_buffer_db());
#endif /* SAI_BUFFER_SELF_CHECK */
    sai_buffer_db_data_reset();
    cl_plock_release(&g_sai_db_ptr->p_lock);
}

static sai_status_t sai_buffer_db_switch_connect_init(int shmid)
{
    init_buffer_resource_limits();
    g_sai_buffer_db_size = sai_buffer_db_size_get();
    g_sai_buffer_db_ptr  = malloc(sizeof(*g_sai_buffer_db_ptr));
    if (g_sai_buffer_db_ptr == NULL) {
        SX_LOG_ERR("Failed to allocate SAI buffer DB structure\n");
        return SAI_STATUS_NO_MEMORY;
    }

    g_sai_buffer_db_ptr->db_base_ptr = mmap(NULL, g_sai_buffer_db_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
    if (g_sai_buffer_db_ptr->db_base_ptr == MAP_FAILED) {
        SX_LOG_ERR("Failed to map the shared memory of the SAI buffer DB\n");
        g_sai_buffer_db_ptr->db_base_ptr = NULL;
        return SAI_STATUS_NO_MEMORY;
    }
    sai_buffer_db_pointers_init();
    msync(g_sai_buffer_db_ptr, g_sai_buffer_db_size, MS_SYNC);
    return SAI_STATUS_SUCCESS;
}

static void sai_buffer_db_data_reset()
{
    if (0 == g_sai_buffer_db_size) {
        g_sai_buffer_db_size = sai_buffer_db_size_get();
    }
    memset(g_sai_buffer_db_ptr->db_base_ptr, 0, g_sai_buffer_db_size);
}

static void sai_buffer_db_pointers_init()
{
    assert(g_sai_db_ptr->ports_number != 0);
    g_sai_buffer_db_ptr->buffer_profiles  = (mlnx_sai_db_buffer_profile_entry_t*)(g_sai_buffer_db_ptr->db_base_ptr);
    g_sai_buffer_db_ptr->port_buffer_data =
        (uint32_t*)
        (
            g_sai_buffer_db_ptr->buffer_profiles +
            (1 + (g_sai_db_ptr->ports_number * mlnx_sai_get_buffer_resource_limits()->max_buffers_per_port))
        );
    g_sai_buffer_db_ptr->pool_allocation = (bool*)
                                           (g_sai_buffer_db_ptr->port_buffer_data +
                                            BUFFER_DB_PER_PORT_PROFILE_INDEX_ARRAY_SIZE * g_sai_db_ptr->ports_number);
}

static sai_status_t sai_buffer_db_unload(boolean_t erase_db)
{
    int          err    = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (erase_db == TRUE) {
        cl_shm_destroy(SAI_BUFFER_PATH);
    }

    if (g_sai_buffer_db_ptr == NULL) {
        return status;
    }

    if (g_sai_buffer_db_ptr->db_base_ptr != NULL) {
        err = munmap(g_sai_buffer_db_ptr->db_base_ptr, g_sai_buffer_db_size);
        if (err == -1) {
            SX_LOG_ERR("Failed to unmap the shared memory of the SAI buffer DB\n");
            status = SAI_STATUS_FAILURE;
        }
    }
    free(g_sai_buffer_db_ptr);
    g_sai_buffer_db_ptr = NULL;
    return status;
}

static uint32_t sai_buffer_db_size_get()
{
    if (0 == g_sai_db_ptr->ports_number) {
        SX_LOG_ERR("g_sai_db_ptr->ports_number NOT CONFIGURED\n");
        return SAI_STATUS_FAILURE;
    }

    return (
        /*
         *  buffer profiles
         */
        sizeof(mlnx_sai_db_buffer_profile_entry_t) *
        (1 + (g_sai_db_ptr->ports_number * mlnx_sai_get_buffer_resource_limits()->max_buffers_per_port)) +

        /*
         *  for each port - 3 arrays holding references to buffer profiles, see comments on sai_buffer_db_t.port_buffer_data
         */
        sizeof(uint32_t) * BUFFER_DB_PER_PORT_PROFILE_INDEX_ARRAY_SIZE * g_sai_db_ptr->ports_number +
        sizeof(bool) * (1 + BUFFER_DB_POOL_FLAG_ARRAY_SIZE)
        );
}

static sai_status_t sai_buffer_db_create()
{
    int         shmid;
    cl_status_t cl_err;

    init_buffer_resource_limits();

    cl_err = cl_shm_create(SAI_BUFFER_PATH, &shmid);
    if (cl_err) {
        if (errno == EEXIST) { /* one retry is allowed */
            SX_LOG_WRN("Shared memory of the SAI buffer already exists, destroying it and re-creating\n");
            cl_shm_destroy(SAI_BUFFER_PATH);
            cl_err = cl_shm_create(SAI_BUFFER_PATH, &shmid);
        }

        if (cl_err) {
            SX_LOG_ERR("Failed to create shared memory for SAI buffer DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }
    }

    g_sai_buffer_db_size = sai_buffer_db_size_get();

    if (ftruncate(shmid, g_sai_buffer_db_size) == -1) {
        SX_LOG_ERR("Failed to set shared memory size for the SAI buffer DB\n");
        cl_shm_destroy(SAI_BUFFER_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    g_sai_buffer_db_ptr = malloc(sizeof(sai_buffer_db_t));
    if (g_sai_buffer_db_ptr == NULL) {
        SX_LOG_ERR("Failed to allocate SAI buffer DB structure\n");
        return SAI_STATUS_NO_MEMORY;
    }

    g_sai_buffer_db_ptr->db_base_ptr = mmap(NULL, g_sai_buffer_db_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
    if (g_sai_buffer_db_ptr->db_base_ptr == MAP_FAILED) {
        SX_LOG_ERR("Failed to map the shared memory of the SAI buffer DB\n");
        g_sai_buffer_db_ptr->db_base_ptr = NULL;
        cl_shm_destroy(SAI_BUFFER_PATH);
        return SAI_STATUS_NO_MEMORY;
    }
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *   SDK initialization. After the call the capability attributes should be
 *   ready for retrieval via sai_get_switch_attribute().
 *
 * Arguments:
 *   [in] profile_id - Handle for the switch profile.
 *   [in] switch_hardware_id - Switch hardware ID to open
 *   [in/opt] firmware_path_name - Vendor specific path name of the firmware
 *                                     to load
 *   [in] switch_notifications - switch notification table
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
static sai_status_t mlnx_initialize_switch(_In_ sai_switch_profile_id_t                           profile_id,
                                           _In_reads_z_(SAI_MAX_HARDWARE_ID_LEN) char           * switch_hardware_id,
                                           _In_reads_opt_z_(SAI_MAX_FIRMWARE_PATH_NAME_LEN) char* firmware_path_name,
                                           _In_ sai_switch_notification_t                       * switch_notifications)
{
    sx_router_general_param_t   general_param;
    sx_router_resources_param_t resources_param;
    sx_status_t                 status;
    const char                 *config_file, *route_table_size, *neighbor_table_size;
    uint32_t                    routes_num    = 0;
    uint32_t                    neighbors_num = 0;

#ifndef ACS_OS
    const char *initial_fan_speed;
    uint8_t     fan_percent;
#endif

    cl_status_t            cl_err;
    sx_router_attributes_t router_attr;
    sx_router_id_t         vrid;
    sx_span_init_params_t  span_init_params;

    memset(&span_init_params, 0, sizeof(sx_span_init_params_t));

    if (NULL == switch_hardware_id) {
        fprintf(stderr, "NULL switch hardware ID passed to SAI switch initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == switch_notifications) {
        fprintf(stderr, "NULL switch notifications passed to SAI switch initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    config_file = g_mlnx_services.profile_get_value(profile_id, SAI_KEY_INIT_CONFIG_FILE);
    if (NULL == config_file) {
        fprintf(stderr, "NULL config file for profile %u\n", profile_id);

        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* Get resource limits before shared memory creation as we need it for memory allocation. */
    if (SX_STATUS_SUCCESS !=
        (status = rm_chip_limits_get(SX_CHIP_TYPE_SPECTRUM, &g_resource_limits))) {
        fprintf(stderr, "Failed to get chip resources - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    memcpy(&g_notification_callbacks, switch_notifications, sizeof(g_notification_callbacks));
    g_profile_id = profile_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_resource_mng_stage(config_file))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_chassis_mng_stage())) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_dvs_mng_stage())) {
        return status;
    }

#ifndef ACS_OS
    initial_fan_speed = g_mlnx_services.profile_get_value(profile_id, KV_INITIAL_FAN_SPEED);
    if (NULL != initial_fan_speed) {
        fan_percent = (uint8_t)atoi(initial_fan_speed);
        if ((fan_percent > MAX_FAN_PERCENT) || (fan_percent < MIN_FAN_PERCENT)) {
            SX_LOG_ERR("Initial fan speed must be in range [%u,%u] - %u\n",
                       MIN_FAN_PERCENT,
                       MAX_FAN_PERCENT,
                       fan_percent);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        SX_LOG_NTC("Setting initial fan speed %u%%\n", fan_percent);
        if (SAI_STATUS_SUCCESS != (status = mlnx_switch_fan_set(fan_percent))) {
            return status;
        }
    }
#endif

    if (SAI_STATUS_SUCCESS != (status = switch_open_traps())) {
        return status;
    }

    cl_err = cl_thread_init(&event_thread, event_thread_func, NULL, NULL);
    if (cl_err) {
        SX_LOG_ERR("Failed to create event thread\n");
        return SAI_STATUS_FAILURE;
    }

    /* init router model, T1 config */
    /* TODO : in the future, get some/all of these params dynamically from the profile */
    memset(&resources_param, 0, sizeof(resources_param));
    memset(&general_param, 0, sizeof(general_param));

    route_table_size    = g_mlnx_services.profile_get_value(profile_id, SAI_KEY_L3_ROUTE_TABLE_SIZE);
    neighbor_table_size = g_mlnx_services.profile_get_value(profile_id, SAI_KEY_L3_NEIGHBOR_TABLE_SIZE);
    if (NULL != route_table_size) {
        routes_num = (uint32_t)atoi(route_table_size);
        SX_LOG_NTC("Setting initial route table size %u\n", routes_num);
    }
    if (NULL != neighbor_table_size) {
        neighbors_num = (uint32_t)atoi(neighbor_table_size);
        SX_LOG_NTC("Setting initial neighbor table size %u\n", neighbors_num);
    }

    resources_param.max_virtual_routers_num    = g_resource_limits.router_vrid_max;
    resources_param.max_vlan_router_interfaces = 64;
    resources_param.max_port_router_interfaces = 64;
    resources_param.max_router_interfaces      = g_resource_limits.router_rifs_max;

    resources_param.min_ipv4_uc_route_entries = routes_num;
    resources_param.min_ipv6_uc_route_entries = routes_num;
    resources_param.max_ipv4_uc_route_entries = routes_num;
    resources_param.max_ipv6_uc_route_entries = routes_num;

    resources_param.min_ipv4_neighbor_entries = neighbors_num;
    resources_param.min_ipv6_neighbor_entries = neighbors_num;
    resources_param.max_ipv4_neighbor_entries = neighbors_num;
    resources_param.max_ipv6_neighbor_entries = neighbors_num;

    resources_param.min_ipv4_mc_route_entries = 0;
    resources_param.min_ipv6_mc_route_entries = 0;
    resources_param.max_ipv4_mc_route_entries = 0;
    resources_param.max_ipv6_mc_route_entries = 0;

    general_param.ipv4_enable    = 1;
    general_param.ipv6_enable    = 1;
    general_param.ipv4_mc_enable = 0;
    general_param.ipv6_mc_enable = 0;
    general_param.rpf_enable     = 0;

    memset(&router_attr, 0, sizeof(router_attr));

    router_attr.ipv4_enable            = 1;
    router_attr.ipv6_enable            = 1;
    router_attr.ipv4_mc_enable         = 0;
    router_attr.ipv6_mc_enable         = 0;
    router_attr.uc_default_rule_action = SX_ROUTER_ACTION_DROP;
    router_attr.mc_default_rule_action = SX_ROUTER_ACTION_DROP;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_init_set(gh_sdk, &general_param, &resources_param))) {
        SX_LOG_ERR("Router init failed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_set(gh_sdk, SX_ACCESS_CMD_ADD, &router_attr, &vrid))) {
        SX_LOG_ERR("Failed to add default router - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    status = mlnx_create_object(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, vrid, NULL, &g_sai_db_ptr->default_vrid);
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != status) {
        return status;
    }

    /* Set default aging time - 0 (disabled) */
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_age_time_set(gh_sdk, DEFAULT_ETH_SWID, SX_FDB_AGE_TIME_MAX))) {
        SX_LOG_ERR("Failed to set fdb age time - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_hash_initialize())) {
        return status;
    }

    if (SAI_STATUS_SUCCESS != (status = acl_db_init())) {
        SX_LOG_ERR("Failed to init acl DB\n");
        return sdk_to_sai(status);
    }

    span_init_params.version = SX_SPAN_MIRROR_HEADER_VERSION_1;

    if (SAI_STATUS_SUCCESS !=
        (status = sdk_to_sai(sx_api_span_init_set(gh_sdk, &span_init_params)))) {
        SX_LOG_ERR("Failed to init SPAN\n");
        return status;
    }

    status = mlnx_sai_buffer_load_current_config();
    return status;
}

static sai_status_t switch_open_traps(void)
{
    uint32_t                   ii;
    sx_trap_group_attributes_t trap_group_attributes;
    sai_status_t               status;

    memset(&trap_group_attributes, 0, sizeof(trap_group_attributes));
    trap_group_attributes.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
    trap_group_attributes.truncate_size = 0;
    trap_group_attributes.prio          = DEFAULT_TRAP_GROUP_PRIO;

    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_group_set(gh_sdk, DEFAULT_ETH_SWID,
                                                                       DEFAULT_TRAP_GROUP_ID,
                                                                       &trap_group_attributes))) {
        SX_LOG_ERR("Failed to sx_api_host_ifc_trap_group_set %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    g_sai_db_ptr->trap_group_valid[DEFAULT_TRAP_GROUP_ID] = true;

    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_TRAP_GROUP, DEFAULT_TRAP_GROUP_ID, NULL,
                                                           &g_sai_db_ptr->default_trap_group))) {
        goto out;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_open(gh_sdk, &g_sai_db_ptr->callback_channel.channel.fd))) {
        SX_LOG_ERR("host ifc open callback fd failed - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }
    g_sai_db_ptr->callback_channel.type = SX_USER_CHANNEL_TYPE_FD;

    for (ii = 0; END_TRAP_INFO_ID != mlnx_traps_info[ii].trap_id; ii++) {
        g_sai_db_ptr->traps_db[ii].action     = mlnx_traps_info[ii].action;
        g_sai_db_ptr->traps_db[ii].trap_group = g_sai_db_ptr->default_trap_group;
#ifdef ACS_OS
        g_sai_db_ptr->traps_db[ii].trap_channel = SAI_HOSTIF_TRAP_CHANNEL_NETDEV;
#else
        g_sai_db_ptr->traps_db[ii].trap_channel = SAI_HOSTIF_TRAP_CHANNEL_CB;
#endif
        g_sai_db_ptr->traps_db[ii].fd = SAI_NULL_OBJECT_ID;

        if (0 == mlnx_traps_info[ii].sdk_traps_num) {
            continue;
        }

        if (SAI_STATUS_SUCCESS != (status = mlnx_trap_set(ii, mlnx_traps_info[ii].action,
                                                          g_sai_db_ptr->default_trap_group))) {
            goto out;
        }

        cl_plock_release(&g_sai_db_ptr->p_lock);
        if (SAI_STATUS_SUCCESS != (status = mlnx_register_trap(SX_ACCESS_CMD_REGISTER, ii))) {
            return status;
        }
        cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    }

#ifdef ACS_OS
    /* TODO : intermediate solution to drop traffic to unresolved neighbors, replace in long term*/
    if (SAI_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_set(gh_sdk, DEFAULT_ETH_SWID,
                                                                    SX_TRAP_ID_HOST_MISS_IPV4, DEFAULT_TRAP_GROUP_ID,
                                                                    SX_TRAP_ACTION_DISCARD))) {
        SX_LOG_ERR("Failed to set trap host miss, error is %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }
#endif

out:
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);
    return status;
}

static sai_status_t switch_close_traps(void)
{
    uint32_t ii;

    for (ii = 0; END_TRAP_INFO_ID != mlnx_traps_info[ii].trap_id; ii++) {
        if (0 == mlnx_traps_info[ii].sdk_traps_num) {
            continue;
        }

        mlnx_register_trap(SX_ACCESS_CMD_DEREGISTER, ii);
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Release all resources associated with currently opened switch
 *
 * Arguments:
 *   [in] warm_restart_hint - hint that indicates controlled warm restart.
 *                            Since warm restart can be caused by crash
 *                            (therefore there are no guarantees for this call),
 *                            this hint is really a performance optimization.
 *
 * Return Values:
 *   None
 */
static void mlnx_shutdown_switch(_In_ bool warm_restart_hint)
{
    sx_status_t    status;
    sxd_status_t   sxd_status;
    int            system_err;
    sx_router_id_t vrid;
    uint32_t       data;

    SX_LOG_ENTER();

    SX_LOG_NTC("Shutdown switch\n");

    if (SX_STATUS_SUCCESS != (status = switch_close_traps())) {
        SX_LOG_ERR("Close traps failed\n");
    }

    event_thread_asked_to_stop = true;

#ifndef _WIN32
    pthread_join(event_thread.osd.id, NULL);
#endif

    if (SAI_STATUS_SUCCESS ==
        mlnx_object_to_type(g_sai_db_ptr->default_vrid, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &data, NULL)) {
        vrid = (sx_router_id_t)data;

        if (SX_STATUS_SUCCESS != (status = sx_api_router_set(gh_sdk, SX_ACCESS_CMD_DELETE, NULL, &vrid))) {
            SX_LOG_ERR("Failed to delete default router - %s.\n", SX_STATUS_MSG(status));
        }
    }

    if (SAI_STATUS_SUCCESS != (status = acl_db_deinit())) {
        SX_LOG_ERR("ACL DB deinit failed.\n");
    }

    sai_qos_db_unload(true);
    sai_buffer_db_unload(true);
    sai_db_unload(true);

    if (SX_STATUS_SUCCESS != (status = sx_api_router_deinit_set(gh_sdk))) {
        SX_LOG_ERR("Router deinit failed.\n");
    }

    if (SXD_STATUS_SUCCESS != (sxd_status = sxd_access_reg_deinit())) {
        SX_LOG_ERR("Access reg deinit failed.\n");
    }

    if (SXD_STATUS_SUCCESS != (sxd_status = sxd_dpt_deinit())) {
        SX_LOG_ERR("DPT deinit failed.\n");
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));

    system_err = system("killall -w sx_sdk sx_acl_rm");
    if (0 != system_err) {
        fprintf(stderr, "killall -w sx_sdk sx_acl_rm failed.\n");
    }

    system_err = system("/etc/init.d/sxdkernel stop");
    if (0 != system_err) {
        fprintf(stderr, "Failed running sxdkernel stop.\n");
    }

    SX_LOG_EXIT();
}

/*
 * Routine Description:
 *   SDK connect. This API connects library to the initialized SDK.
 *   After the call the capability attributes should be ready for retrieval
 *   via sai_get_switch_attribute().
 *
 * Arguments:
 *   [in] profile_id - Handle for the switch profile.
 *   [in] switch_hardware_id - Switch hardware ID to open
 *   [in] switch_notifications - switch notification table
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
static sai_status_t mlnx_connect_switch(_In_ sai_switch_profile_id_t                profile_id,
                                        _In_reads_z_(SAI_MAX_HARDWARE_ID_LEN) char* switch_hardware_id,
                                        _In_ sai_switch_notification_t            * switch_notifications)
{
    sx_status_t status;
    int         err, shmid;

    UNUSED_PARAM(profile_id);

    if (NULL == switch_hardware_id) {
        fprintf(stderr, "NULL switch hardware ID passed to SAI switch connect\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == switch_notifications) {
        fprintf(stderr, "NULL switch notifications passed to SAI switch connect\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    memcpy(&g_notification_callbacks, switch_notifications, sizeof(g_notification_callbacks));
    g_profile_id = profile_id;

    /* Open an handle if not done already on init for init agent */
    if (0 == gh_sdk) {
#ifndef _WIN32
        openlog("SAI", 0, LOG_USER);
        g_log_init = true;
#endif

        if (SX_STATUS_SUCCESS != (status = sx_api_open(sai_log_cb, &gh_sdk))) {
            fprintf(stderr, "Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_system_log_verbosity_level_set(gh_sdk,
                                                                                 SX_LOG_VERBOSITY_TARGET_API,
                                                                                 LOG_VAR_NAME(__MODULE__),
                                                                                 LOG_VAR_NAME(__MODULE__)))) {
            SX_LOG_ERR("Set system log verbosity failed - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SX_STATUS_SUCCESS !=
            (status = rm_chip_limits_get(SX_CHIP_TYPE_SPECTRUM, &g_resource_limits))) {
            SX_LOG_ERR("Failed to get chip resources - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        err = cl_shm_open(SAI_PATH, &shmid);
        if (err) {
            SX_LOG_ERR("Failed to open shared memory of SAI DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }

        g_sai_db_ptr = mmap(NULL, sizeof(*g_sai_db_ptr), PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
        if (g_sai_db_ptr == MAP_FAILED) {
            SX_LOG_ERR("Failed to map the shared memory of the SAI DB\n");
            g_sai_db_ptr = NULL;
            return SAI_STATUS_NO_MEMORY;
        }

        err = cl_shm_open(SAI_QOS_PATH, &shmid);
        if (err) {
            SX_LOG_ERR("Failed to open shared memory of SAI QOS DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }

        g_sai_qos_db_size = sai_qos_db_size_get();
        g_sai_qos_db_ptr  = malloc(sizeof(*g_sai_qos_db_ptr));
        if (g_sai_qos_db_ptr == NULL) {
            SX_LOG_ERR("Failed to allocate SAI QoS DB structure\n");
            return SAI_STATUS_NO_MEMORY;
        }

        g_sai_qos_db_ptr->db_base_ptr = mmap(NULL, g_sai_qos_db_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
        if (g_sai_qos_db_ptr->db_base_ptr == MAP_FAILED) {
            SX_LOG_ERR("Failed to map the shared memory of the SAI QOS DB\n");
            g_sai_qos_db_ptr->db_base_ptr = NULL;
            return SAI_STATUS_NO_MEMORY;
        }

        sai_qos_db_init();

        err = cl_shm_open(SAI_BUFFER_PATH, &shmid);
        if (err) {
            SX_LOG_ERR("Failed to open shared memory of SAI Buffers DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }

        status = sai_buffer_db_switch_connect_init(shmid);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to map SAI buffer db on switch connect\n");
            return status;
        }
    }

    SX_LOG_NTC("Connect switch\n");

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Disconnect this SAI library from the SDK.
 *
 * Arguments:
 *   None
 * Return Values:
 *   None
 */
static void mlnx_disconnect_switch(void)
{
    sx_status_t status;

    SX_LOG_NTC("Disconnect switch\n");

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));

    if (g_sai_qos_db_ptr != NULL) {
        free(g_sai_qos_db_ptr);
    }
    g_sai_qos_db_ptr = NULL;
}

/*
 * Routine Description:
 *    Set switch attribute value
 *
 * Arguments:
 *    [in] attr - switch attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_switch_attribute(_In_ const sai_attribute_t *attr)
{
    SX_LOG_ENTER();

    return sai_set_attribute(NULL, "switch", switch_attribs, switch_vendor_attribs, attr);
}

/* Switching mode [sai_switch_switching_mode_t]
 *  (default to SAI_SWITCHING_MODE_STORE_AND_FORWARD) */
static sai_status_t mlnx_switch_mode_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg)
{
    SX_LOG_ENTER();

    switch (value->s32) {
    case SAI_SWITCHING_MODE_CUT_THROUGH:
        break;

    /* Note Mellanox implementation does not support store and forward.
    * The default is cut through, different then SAI defined default */
    case SAI_SWITCHING_MODE_STORE_AND_FORWARD:
        SX_LOG_ERR("Switching mode store and forward not supported\n");
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;

    default:
        SX_LOG_ERR("Invalid switching mode value %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Dynamic FDB entry aging time in seconds [uint32_t]
 *   Zero means aging is disabled.
 *  (default to zero)
 */
static sai_status_t mlnx_switch_aging_time_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sai_status_t      status;
    sx_fdb_age_time_t time;

    SX_LOG_ENTER();

    if (0 == value->u32) {
        time = SX_FDB_AGE_TIME_MAX;
    } else if (SX_FDB_AGE_TIME_MIN > value->u32) {
        time = SX_FDB_AGE_TIME_MIN;
    } else if (SX_FDB_AGE_TIME_MAX < value->u32) {
        time = SX_FDB_AGE_TIME_MAX;
    } else {
        time = value->u32;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_age_time_set(gh_sdk, DEFAULT_ETH_SWID, time))) {
        SX_LOG_ERR("Failed to set fdb age time - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing seed  [uint32_t] */
/* Hash algorithm for all ECMP in the switch[sai_switch_hash_algo_t] */
static sai_status_t mlnx_switch_ecmp_hash_param_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    sx_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = mlnx_hash_ecmp_attr_apply((long)arg, value))) {
        SX_LOG_ERR("Failed to set ECMP hash params.\n");
    }

    SX_LOG_EXIT();
    return status;
}

/* The SDK can
 * 1 - Read the counters directly from HW (or)
 * 2 - Cache the counters in SW. Caching is typically done if
 * retrieval of counters directly from HW for each counter
 * read is CPU intensive
 * This setting can be used to
 * 1 - Move from HW based to SW based or Vice versa
 * 2 - Configure the SW counter cache refresh rate
 * Setting a value of 0 enables direct HW based counter read. A
 * non zero value enables the SW cache based and the counter
 * refresh rate.
 * A NPU may support both or one of the option. It would return
 * error for unsupported options. [uint32_t]
 */
static sai_status_t mlnx_switch_counter_refresh_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    SX_LOG_ENTER();

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* Set LAG hashing seed  [uint32_t] */
static sai_status_t mlnx_switch_lag_hash_seed_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    sx_lag_hash_param_t hash_param;
    sx_status_t         status;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_get(gh_sdk, &hash_param))) {
        SX_LOG_ERR("Failed to get LAG hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    hash_param.lag_seed = value->u32;

    if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_set(gh_sdk, &hash_param))) {
        SX_LOG_ERR("Failed to set LAG hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Hash algorithm for all LAGs in the switch[sai_switch_hash_algo_t] */
static sai_status_t mlnx_switch_lag_hash_algo_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    sx_lag_hash_param_t hash_param;
    sx_status_t         status = SAI_STATUS_SUCCESS;

    memset(&hash_param, 0, sizeof(hash_param));

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_get(gh_sdk, &hash_param))) {
        SX_LOG_ERR("Failed to get LAG hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    switch (value->s32) {
    case SAI_HASH_ALGORITHM_XOR:
        hash_param.lag_hash_type = SX_LAG_HASH_TYPE_XOR;
        break;

    case SAI_HASH_ALGORITHM_CRC:
        hash_param.lag_hash_type = SX_LAG_HASH_TYPE_CRC;
        break;

    case SAI_HASH_ALGORITHM_RANDOM:
        return SAI_STATUS_NOT_SUPPORTED;

    default:
        SX_LOG_ERR("Invalid hash type value %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }
    if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_set(gh_sdk, &hash_param))) {
        SX_LOG_ERR("Failed to set LAG hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Get switch attribute value
 *
 * Arguments:
 *    [in] attr_count - number of switch attributes
 *    [inout] attr_list - array of switch attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_switch_attribute(_In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_get_attributes(NULL, "switch", switch_attribs, switch_vendor_attribs, attr_count, attr_list);
    SX_LOG_EXIT();
    return status;
}

/* The number of ports on the switch [uint32_t] */
static sai_status_t mlnx_switch_port_number_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    SX_LOG_ENTER();

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    value->u32 = g_sai_db_ptr->ports_number;
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get the port list [sai_object_list_t] */
static sai_status_t mlnx_switch_port_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_object_id_t ports[MAX_PORTS];
    uint32_t        ii;
    sai_status_t    status;

    SX_LOG_ENTER();

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        ports[ii] = g_sai_db_ptr->ports_db[ii].saiport;
    }

    status = mlnx_fill_objlist(ports, g_sai_db_ptr->ports_number, &value->objlist);

    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return status;
}

/* Get the Max MTU in bytes, Supported by the switch [uint32_t] */
static sai_status_t mlnx_switch_max_mtu_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = g_resource_limits.port_mtu_max;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get the CPU Port [sai_object_id_t] */
static sai_status_t mlnx_switch_cpu_port_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, CPU_PORT, NULL, &value->oid))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Max number of virtual routers supported [uint32_t] */
static sai_status_t mlnx_switch_max_vr_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = SWITCH_MAX_VR;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *   Local subnet routing supported [bool]
 *   Routes with next hop set to "on-link"
 */
static sai_status_t mlnx_switch_on_link_get(_In_ const sai_object_key_t   *key,
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

/* Oper state [sai_switch_oper_status_t] */
static sai_status_t mlnx_switch_oper_status_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_SWITCH_OPER_STATUS_UP;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* The current value of the maximum temperature
 * retrieved from the switch sensors, in Celsius [int32_t] */
static sai_status_t mlnx_switch_max_temp_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    struct ku_mtmp_reg tmp_reg;
    sxd_reg_meta_t     reg_meta;
    int16_t            tmp = 0;
    sxd_status_t       sxd_status;

    #define TEMP_MASUREMENT_UNIT 0.125

    SX_LOG_ENTER();

    memset(&tmp_reg, 0, sizeof(tmp_reg));
    memset(&reg_meta, 0, sizeof(reg_meta));
    tmp_reg.sensor_index = 0;
    reg_meta.access_cmd  = SXD_ACCESS_CMD_GET;
    reg_meta.dev_id      = SX_DEVICE_ID;
    reg_meta.swid        = DEFAULT_ETH_SWID;

    sxd_status = sxd_access_reg_mtmp(&tmp_reg, &reg_meta, 1, NULL, NULL);
    if (sxd_status) {
        SX_LOG_ERR("Access_mtmp_reg failed with status (%s:%d)\n", SXD_STATUS_MSG(sxd_status), sxd_status);
        return SAI_STATUS_FAILURE;
    }
    if (((int16_t)tmp_reg.temperature) < 0) {
        tmp = (0xFFFF + ((int16_t)tmp_reg.temperature) + 1);
    } else {
        tmp = (int16_t)tmp_reg.temperature;
    }
    value->s32 = (int32_t)(tmp * TEMP_MASUREMENT_UNIT);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** QoS Map Id [sai_object_id_t] */
static sai_status_t mlnx_switch_qos_map_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_qos_map_type_t qos_map_type = (sai_qos_map_type_t)arg;
    uint32_t           qos_map_id;

    assert(qos_map_type < MLNX_QOS_MAP_TYPES_MAX);

    sai_db_read_lock();

    qos_map_id = g_sai_db_ptr->switch_qos_maps[qos_map_type];

    if (!qos_map_id) {
        value->oid = SAI_NULL_OBJECT_ID;
        sai_db_unlock();
        return SAI_STATUS_SUCCESS;
    }

    sai_db_unlock();
    return mlnx_create_object(SAI_OBJECT_TYPE_QOS_MAPS, qos_map_id, NULL, &value->oid);
}

/** QoS Map Id [sai_object_id_t] */
static sai_status_t mlnx_switch_qos_map_id_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sai_qos_map_type_t  qos_map_type = (sai_qos_map_type_t)arg;
    sai_status_t        status       = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port;
    uint32_t            qos_map_id;
    uint32_t            port_idx;

    assert(qos_map_type < MLNX_QOS_MAP_TYPES_MAX);

    if (value->oid == SAI_NULL_OBJECT_ID) {
        qos_map_id = 0;
    } else {
        status = mlnx_object_to_type(value->oid, SAI_OBJECT_TYPE_QOS_MAPS, &qos_map_id, NULL);
        if (status != SAI_STATUS_SUCCESS) {
            return status;
        }
    }

    sai_db_write_lock();

    mlnx_port_foreach(port, port_idx) {
        if (port->qos_maps[qos_map_type]) {
            continue;
        }

        status = mlnx_port_qos_map_apply(port->saiport, value->oid, qos_map_type);
        if (status != SAI_STATUS_SUCCESS) {
            SX_LOG_ERR("Failed to update port %" PRIx64 " with QoS map %" PRIx64 "\n",
                       port->saiport, value->oid);
            break;
        }

        SX_LOG_NTC("Port %" PRIx64 " was updated with new QoS map %" PRIx64 "\n",
                   port->saiport, value->oid);
    }

    g_sai_db_ptr->switch_qos_maps[qos_map_type] = qos_map_id;

    sai_db_sync();
    sai_db_unlock();
    return status;
}

/** Default Traffic class Mapping [sai_uint8_t], Default TC=0*/
static sai_status_t mlnx_switch_default_tc_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    SX_LOG_ENTER();

    sai_db_read_lock();
    value->u8 = g_sai_db_ptr->switch_default_tc;
    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** Default Traffic class Mapping [sai_uint8_t], Default TC=0*/
static sai_status_t mlnx_switch_default_tc_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    mlnx_port_config_t *port;
    uint32_t            port_idx;
    sai_status_t        status;

    SX_LOG_ENTER();

    if (!SX_CHECK_MAX(value->u8, SXD_COS_PORT_PRIO_MAX)) {
        SX_LOG_ERR("Invalid tc(%u)\n", value->u8);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_write_lock();
    g_sai_db_ptr->switch_default_tc = value->u8;
    sai_db_unlock();

    mlnx_port_foreach(port, port_idx) {
        if (g_sai_db_ptr->ports_default_tc[port_idx]) {
            continue;
        }

        status = mlnx_port_tc_set(port->saiport, value->u8);
        if (status != SAI_STATUS_SUCCESS) {
            SX_LOG_ERR("Failed to update port %" PRIx64 " with tc(%u)\n", port->saiport, value->u8);
            break;
        }

        SX_LOG_NTC("Port %" PRIx64 " was updated with tc(%u)\n", port->saiport, value->u8);
    }

    SX_LOG_EXIT();
    return status;
}

#ifndef ACS_OS
static sai_status_t mlnx_switch_fan_set(uint8_t power_percent)
{
    struct ku_mfsc_reg mfsc_reg;
    sxd_reg_meta_t     reg_meta;
    sxd_status_t       sxd_status;

    SX_LOG_ENTER();

    memset(&(mfsc_reg), 0, sizeof(mfsc_reg));
    memset(&reg_meta, 0, sizeof(reg_meta));
    mfsc_reg.pwm            = 0;
    mfsc_reg.pwm_duty_cycle = (u_int8_t)((uint16_t)(power_percent * 0xff) / 100);
    reg_meta.access_cmd     = SXD_ACCESS_CMD_SET;
    reg_meta.dev_id         = SX_DEVICE_ID;
    reg_meta.swid           = DEFAULT_ETH_SWID;

    sxd_status = sxd_access_reg_mfsc(&mfsc_reg, &reg_meta, 1, NULL, NULL);
    if (sxd_status) {
        SX_LOG_ERR("Access_mfsc_reg failed with status (%s:%d)\n", SXD_STATUS_MSG(sxd_status), sxd_status);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}
#endif

/* minimum priority for ACL table [sai_uint32_t] */
static sai_status_t mlnx_switch_acl_table_min_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    SX_LOG_ENTER();

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* maximum priority for ACL table [sai_uint32_t] */
static sai_status_t mlnx_switch_acl_table_max_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    SX_LOG_ENTER();

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* minimum priority for ACL entry [sai_uint32_t] */
static sai_status_t mlnx_switch_acl_entry_min_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    SX_LOG_ENTER();

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* maximum priority for ACL entry [sai_uint32_t] */
static sai_status_t mlnx_switch_acl_entry_max_prio_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    SX_LOG_ENTER();

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* ACL user-based trap id range [sai_u32_range_t] */
static sai_status_t mlnx_switch_acl_trap_range_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    SX_LOG_ENTER();

    value->u32range.min = SX_TRAP_ID_ACL_MIN;
    value->u32range.max = SX_TRAP_ID_ACL_MAX;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Maximum number of ports that can be part of a LAG [uint32_t] */
static sai_status_t mlnx_switch_max_lag_members_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = g_resource_limits.lag_port_members_max;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Maximum number of LAGs that can be created per switch [uint32_t] */
static sai_status_t mlnx_switch_max_lag_number_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = g_resource_limits.lag_num_max;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Switching mode [sai_switch_switching_mode_t]
 *  (default to SAI_SWITCHING_MODE_STORE_AND_FORWARD) */
static sai_status_t mlnx_switch_mode_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_SWITCHING_MODE_CUT_THROUGH;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default switch MAC Address [sai_mac_t] */
static sai_status_t mlnx_switch_src_mac_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t  status;
    sx_mac_addr_t mac;

    SX_LOG_ENTER();

    /* Use switch first port, and zero down lower 6 bits port part (64 ports) */
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_port_phys_addr_get(gh_sdk, FIRST_PORT, &mac))) {
        SX_LOG_ERR("Failed to get port address - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    mac.ether_addr_octet[5] &= PORT_MAC_BITMASK;

    memcpy(value->mac, &mac,  sizeof(value->mac));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Dynamic FDB entry aging time in seconds [uint32_t]
 *   Zero means aging is disabled.
 *  (default to zero)
 */
static sai_status_t mlnx_switch_aging_time_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t      status;
    sx_fdb_age_time_t age_time;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_age_time_get(gh_sdk, DEFAULT_ETH_SWID, &age_time))) {
        SX_LOG_ERR("Failed to get fdb age time - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u32 = age_time;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_convert_ecmp_sx_param_to_sai(sx_router_ecmp_port_hash_params_t* hash_param,
                                                           sai_attribute_value_t             *value)
{
    switch (hash_param->ecmp_hash_type) {
    case SX_ROUTER_ECMP_HASH_TYPE_XOR:
        value->s32 = SAI_HASH_ALGORITHM_XOR;
        break;

    case SX_ROUTER_ECMP_HASH_TYPE_CRC:
        value->s32 = SAI_HASH_ALGORITHM_CRC;
        break;

    case SX_ROUTER_ECMP_HASH_TYPE_RANDOM:
        value->s32 = SAI_HASH_ALGORITHM_RANDOM;
        break;

    default:
        SX_LOG_ERR("Unexpected ECMP hash type %u\n", hash_param->ecmp_hash_type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing seed  [uint32_t] */
/* Hash algorithm for all ECMP in the switch[sai_switch_hash_algo_t] */
static sai_status_t mlnx_switch_ecmp_hash_param_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    sx_router_ecmp_port_hash_params_t  port_hash_param;
    sx_router_ecmp_hash_field_enable_t hash_enable_list[FIELDS_ENABLES_NUM];
    uint32_t                           enable_count = FIELDS_ENABLES_NUM;
    sx_router_ecmp_hash_field_t        hash_field_list[FIELDS_NUM];
    uint32_t                           field_count = FIELDS_NUM;
    sai_status_t                       status      = SAI_STATUS_SUCCESS;

    memset(&port_hash_param, 0, sizeof(port_hash_param));
    memset(hash_enable_list, 0, sizeof(hash_enable_list));
    memset(hash_field_list, 0, sizeof(hash_field_list));

    SX_LOG_ENTER();

    /* get operational ecmp hash port config */
    status = mlnx_hash_get_oper_ecmp_fields(&port_hash_param,
                                            hash_enable_list, &enable_count,
                                            hash_field_list, &field_count);
    if (SAI_STATUS_SUCCESS != status) {
        return status;
    }

    switch ((long)arg) {
    case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED:
        value->u32 = port_hash_param.seed;
        break;

    case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM:
        status = mlnx_hash_convert_ecmp_sx_param_to_sai(&port_hash_param, value);
        break;

    case SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH:
        value->booldata = port_hash_param.symmetric_hash;
        break;
    }

    SX_LOG_EXIT();
    return status;
}


/* ECMP max number of paths per group [uint32_t]
 *  (default to 64) */
static sai_status_t mlnx_switch_ecmp_max_paths_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = ECMP_MAX_PATHS;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* The SDK can
 * 1 - Read the counters directly from HW (or)
 * 2 - Cache the counters in SW. Caching is typically done if
 * retrieval of counters directly from HW for each counter
 * read is CPU intensive
 * This setting can be used to
 * 1 - Move from HW based to SW based or Vice versa
 * 2 - Configure the SW counter cache refresh rate
 * Setting a value of 0 enables direct HW based counter read. A
 * non zero value enables the SW cache based and the counter
 * refresh rate.
 * A NPU may support both or one of the option. It would return
 * error for unsupported options. [uint32_t]
 */
static sai_status_t mlnx_switch_counter_refresh_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    SX_LOG_ENTER();

    /* TODO : implement */
    SX_LOG_EXIT();

    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* Default trap group [sai_object_id_t] */
static sai_status_t mlnx_switch_default_trap_group_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    SX_LOG_ENTER();

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    value->oid = g_sai_db_ptr->default_trap_group;
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default SAI Virtual Router ID [sai_object_id_t] */
static sai_status_t mlnx_switch_default_vrid_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    SX_LOG_ENTER();

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    value->oid = g_sai_db_ptr->default_vrid;
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** HQOS - Maximum Number of Hierarchy scheduler
 *  group levels(depth) supported [sai_uint32_t]*/
static sai_status_t mlnx_switch_sched_group_levels_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = MAX_SCHED_LEVELS;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/** HQOS - Maximum number of scheduler groups supported on
 * each Hierarchy level [sai_u32_list_t] */
static sai_status_t mlnx_switch_sched_groups_count_per_level_get(_In_ const sai_object_key_t   *key,
                                                                 _Inout_ sai_attribute_value_t *value,
                                                                 _In_ uint32_t                  attr_index,
                                                                 _Inout_ vendor_cache_t        *cache,
                                                                 void                          *arg)
{
    uint32_t    *groups_count = NULL;
    sai_status_t status;
    uint32_t     ii;

    SX_LOG_ENTER();

    groups_count = malloc(MAX_SCHED_LEVELS * sizeof(uint32_t));
    if (!groups_count) {
        SX_LOG_ERR("Failed to max groups count list per level\n");
        return SAI_STATUS_NO_MEMORY;
    }

    for (ii = 0; ii < MAX_SCHED_LEVELS; ii++) {
        if (ii == 0) {
            groups_count[ii] = 1;
        } else {
            groups_count[ii] = MAX_SCHED_CHILD_GROUPS;
        }
    }

    status = mlnx_fill_u32list(groups_count, MAX_SCHED_LEVELS, &value->u32list);

    SX_LOG_EXIT();
    free(groups_count);
    return status;
}

/** HQOS - Maximum number of childs supported per scheudler group [sai_uint32_t]*/
static sai_status_t mlnx_switch_sched_max_child_groups_count_get(_In_ const sai_object_key_t   *key,
                                                                 _Inout_ sai_attribute_value_t *value,
                                                                 _In_ uint32_t                  attr_index,
                                                                 _Inout_ vendor_cache_t        *cache,
                                                                 void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = MAX_SCHED_CHILD_GROUPS;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* The number of Unicast Queues per port [sai_uint32_t]
* The number of Multicast Queues per port [sai_uint32_t]
* The total number of Queues per port [sai_uint32_t] */
static sai_status_t mlnx_switch_queue_num_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    long attr = (long)arg;

    SX_LOG_ENTER();

    assert((SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES == attr) ||
           (SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES == attr) ||
           (SAI_SWITCH_ATTR_NUMBER_OF_QUEUES == attr));

    switch (attr) {
    case SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES:
        value->u32 = (g_resource_limits.cos_port_ets_traffic_class_max + 1) / 2;
        break;

    case SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES:
        value->u32 = (g_resource_limits.cos_port_ets_traffic_class_max + 1) / 2;
        break;

    case SAI_SWITCH_ATTR_NUMBER_OF_QUEUES:
        value->u32 = g_resource_limits.cos_port_ets_traffic_class_max + 1;
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* The ECMP hash object ID [sai_object_id_t] */
/* The LAG hash object ID [sai_object_id_t] */
static sai_status_t mlnx_switch_hash_object_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    long     attr    = (long)arg;
    uint32_t hash_id = 0;

    SX_LOG_ENTER();

    switch (attr) {
    case SAI_SWITCH_ATTR_ECMP_HASH:
        hash_id = SAI_HASH_ECMP_ID;
        break;

    case SAI_SWITCH_ATTR_ECMP_HASH_IPV4:
        hash_id = SAI_HASH_ECMP_IP4_ID;
        break;

    case SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4:
        hash_id = SAI_HASH_ECMP_IPINIP_ID;
        break;

    case SAI_SWITCH_ATTR_LAG_HASH:
        hash_id = SAI_HASH_LAG_ID;
        break;

    case SAI_SWITCH_ATTR_LAG_HASH_IPV4:
        hash_id = SAI_HASH_LAG_IP4_ID;
        break;

    case SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4:
        hash_id = SAI_HASH_LAG_IPINIP_ID;
        break;

    default:
        /* Should not reach this */
        assert(false);
        break;
    }

    sai_db_read_lock();
    value->oid = g_sai_db_ptr->oper_hash_list[hash_id];
    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* The ECMP hash object ID [sai_object_id_t] */
/* The LAG hash object ID [sai_object_id_t] */
static sai_status_t mlnx_switch_hash_object_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    long            attr         = (long)arg;
    sai_object_id_t hash_obj_id  = value->oid;
    uint32_t        hash_oper_id = 0;
    uint32_t        hash_data    = 0;
    sai_status_t    status       = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    /* validate value */
    if (hash_obj_id != SAI_NULL_OBJECT_ID) {
        if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_obj_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
            return SAI_STATUS_FAILURE;
        }
    }

    switch (attr) {
    case SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4:
        hash_oper_id = SAI_HASH_ECMP_IPINIP_ID;
        break;

    case SAI_SWITCH_ATTR_ECMP_HASH_IPV4:
        hash_oper_id = SAI_HASH_ECMP_IP4_ID;
        break;

    case SAI_SWITCH_ATTR_LAG_HASH_IPV4:
        hash_oper_id = SAI_HASH_LAG_IP4_ID;
        break;

    case SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4:
        hash_oper_id = SAI_HASH_LAG_IPINIP_ID;
        break;

    default:
        /* Should not reach this */
        assert(false);
        break;
    }

    if (g_sai_db_ptr->oper_hash_list[hash_oper_id] == hash_obj_id) {
        /* Config didn't change. Just return here. */
        SX_LOG_EXIT();
        return status;
    }

    if (hash_obj_id == SAI_NULL_OBJECT_ID) {
        /* On reset, need apply next object.
         *  So if IPinIP object is reset - try apply IP.
         *  If IP object is reset or just not set - apply default object. */
        sai_db_read_lock();
        if (hash_oper_id == SAI_HASH_LAG_IPINIP_ID) {
            hash_oper_id = SAI_HASH_LAG_IP4_ID;
        } else if (hash_oper_id == SAI_HASH_ECMP_IPINIP_ID) {
            hash_oper_id = SAI_HASH_ECMP_IP4_ID;
        }
        hash_obj_id = g_sai_db_ptr->oper_hash_list[hash_oper_id];
        if (hash_obj_id == SAI_NULL_OBJECT_ID) {
            /* We get here when we reset IP object, or
             * when we reset IPinIp and IP is not configure.
             * In such case apply native fields for default object.
             */
            if (hash_oper_id == SAI_HASH_LAG_IP4_ID) {
                hash_oper_id = SAI_HASH_LAG_ID;
            } else if (hash_oper_id == SAI_HASH_ECMP_IP4_ID) {
                hash_oper_id = SAI_HASH_ECMP_ID;
            }
            hash_obj_id = g_sai_db_ptr->oper_hash_list[hash_oper_id];
        }
        sai_db_unlock();
    }

    status = mlnx_hash_object_apply(hash_obj_id, hash_oper_id);

    if (SAI_STATUS_SUCCESS == status) {
        sai_db_write_lock();
        g_sai_db_ptr->oper_hash_list[hash_oper_id] = value->oid;
        sai_db_sync();
        sai_db_unlock();
    }

    SX_LOG_EXIT();
    return status;
}

/* LAG hashing seed  [uint32_t] */
static sai_status_t mlnx_switch_lag_hash_seed_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t        status;
    sx_lag_hash_param_t hash_param;

    memset(&hash_param, 0, sizeof(hash_param));

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_get(gh_sdk, &hash_param))) {
        SX_LOG_ERR("Failed to get LAG hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u32 = hash_param.lag_seed;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Hash algorithm for all LAGs in the switch[sai_switch_hash_algo_t] */
static sai_status_t mlnx_switch_lag_hash_algo_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t        status;
    sx_lag_hash_param_t hash_param;

    memset(&hash_param, 0, sizeof(hash_param));

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_get(gh_sdk, &hash_param))) {
        SX_LOG_ERR("Failed to get LAG hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    switch (hash_param.lag_hash_type) {
    case SX_LAG_HASH_TYPE_CRC:
        value->s32 = SAI_HASH_ALGORITHM_CRC;
        break;

    case SX_LAG_HASH_TYPE_XOR:
        value->s32 = SAI_HASH_ALGORITHM_XOR;
        break;

    default:
        SX_LOG_ERR("Unexpected ECMP hash type %u\n", hash_param.lag_hash_type);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_switch_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_total_pool_buffer_size_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg)
{
    SX_LOG_ENTER();
    if (!value) {
        SX_LOG_ERR("NULL value\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    value->u32 = g_resource_limits.total_buffer_space / 1024;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_ingress_pool_num_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    SX_LOG_ENTER();
    if (!value) {
        SX_LOG_ERR("NULL value\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    value->u32 = mlnx_sai_get_buffer_resource_limits()->num_ingress_pools;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_egress_pool_num_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    SX_LOG_ENTER();
    if (!value) {
        SX_LOG_ERR("NULL value\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    value->u32 = mlnx_sai_get_buffer_resource_limits()->num_egress_pools;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_switch_api_t mlnx_switch_api = {
    mlnx_initialize_switch,
    mlnx_shutdown_switch,
    mlnx_connect_switch,
    mlnx_disconnect_switch,
    mlnx_set_switch_attribute,
    mlnx_get_switch_attribute,
};
