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
#ifndef _WIN32
#include <mqueue.h>
#include <sys/un.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <complib/cl_thread.h>
#include <sys/types.h>

#undef  __MODULE__
#define __MODULE__ SAI_ACL

#define IP_TYPE_KEY_SIZE              3 /* TODO: Change value to 4 when is_ip_v6 key is available */
#define IP_FRAG_KEY_TYPE_SIZE         2
#define SX_FLEX_ACL_MAX_FIELDS_IN_KEY RM_API_ACL_MAX_FIELDS_IN_KEY
#define ACL_MAX_NUM_OF_ACTIONS        20
#define ACL_TABLE_SIZE_INC_PERCENT    0.2
#define ACL_TABLE_SIZE_DEC_PERCENT    0.2
#define ACL_TABLE_SIZE_MIN_DELTA      16
#define ACL_DEFAULT_ENTRY_PRIO        ACL_MIN_ENTRY_PRIO
#define ACL_INVALID_DB_INDEX          0xFFFFFFFF
#define ACL_INVALID_PBS_INDEX         {.index = ACL_INVALID_DB_INDEX}

#define ACL_DEFAULT_TABLE_SIZE       128
#define ACL_TABLE_SIZE_INCREASE_AUTO 1

#define PSORT_ALMOST_FULL_PERC_STATIC  100
#define PSORT_ALMOST_EMPTY_PERC_STATIC 33
#define PSORT_ALMOST_FULL_PERC_DYN     90
#define PSORT_ALMOST_EMPTY_PERC_DYN    33

#define ACL_QUEUE_INVALID_HANDLE -1
#define ACL_QUEUE_NAME           "/sai_acl_queue"
#define ACL_QUEUE_TIMEOUT        2
#define ACL_QUEUE_SIZE           3
#define ACL_QUEUE_MSG_SIZE       sizeof(uint32_t)
#define ACL_QUEUE_DEF_MSG_PRIO   0
#define ACL_QUEUE_EXIT_MSG_PRIO  31
#define ACL_BCKG_THREAD_EXIT_MSG 0xFFFFFFFF

#define ACL_PBS_MAP_FLOOD_INDEX 64
#define ACL_PBS_MAP_EMPTY_KEY   0

#define ACL_RPC_SV_SOCKET_ADDR "/tmp/sai_acl_rpc_socket"

#define sai_acl_db (g_sai_acl_db_ptr)

#define acl_sai_stage_to_sx_dir(stage) \
    ((stage == SAI_ACL_STAGE_INGRESS) ? \
     SX_ACL_DIRECTION_INGRESS :       \
     SX_ACL_DIRECTION_EGRESS)

#define acl_db_group_by_sai_stage(stage) \
    ((stage == SAI_ACL_STAGE_INGRESS) ?  \
     sai_acl_db->acl_ingress_group_db : \
     sai_acl_db->acl_egress_group_db)
#define acl_db_group_by_sdk_direction(stage) \
    ((stage == SX_ACL_DIRECTION_INGRESS) ? \
     sai_acl_db->acl_ingress_group_db :  \
     sai_acl_db->acl_egress_group_db)

#define acl_table_index_check_range(table_index)     ((table_index < ACL_MAX_TABLE_NUMBER) ? true : false)
#define acl_entry_index_check_range(entry_index)     ((entry_index < ACL_MAX_ENTRY_NUMBER) ? true : false)
#define acl_counter_index_check_range(counter_index) ((counter_index < ACL_MAX_COUNTER_NUM) ? true : false)

#define acl_db_table(table_index)     sai_acl_db->acl_table_db[(table_index)]
#define acl_db_entry(entry_index)     sai_acl_db->acl_entry_db[(entry_index)]
#define acl_db_entry_ptr(entry_index) & sai_acl_db->acl_entry_db[(entry_index)]
#define acl_db_pbs(pbs_index) \
    ((pbs_index.is_simple) ?                        \
     sai_acl_db->acl_pbs_map_db[(pbs_index.index)] : \
     sai_acl_db->acl_port_comb_pbs_map_db[(pbs_index.index)])

#define acl_cond_mutex sai_acl_db->acl_settings_tbl->cond_mutex
#define acl_cond_mutex_lock() \
    do { if (pthread_mutex_lock(&acl_cond_mutex) != 0) { \
             SX_LOG_ERR("Failed to lock ACL mutex\n"); } \
    } while (0)

#define acl_cond_mutex_unlock() \
    do { if (pthread_mutex_unlock(&acl_cond_mutex) != 0) { \
             SX_LOG_ERR("Failed to unlock ACL mutex\n"); } \
    } while (0)

#define acl_db_pbs_ptr(pbs_index) \
    ((pbs_index.is_simple) ?                          \
     &sai_acl_db->acl_pbs_map_db[(pbs_index.index)] : \
     &sai_acl_db->acl_port_comb_pbs_map_db[(pbs_index.index)])

#define is_pbs_index_valid(pbs_index) (pbs_index.index != ACL_INVALID_DB_INDEX)

#define ACL_FOREACH_ENTRY_IN_TABLE(table_index, entry_index)       \
    for (entry_index = acl_db_table(table_index).head_entry_index; \
         ACL_INVALID_DB_INDEX != entry_index; entry_index = acl_db_entry(entry_index).next)

#define ACL_FOREACH_ENTRY(enrty, entry_index, entry_count)              \
    for (; (entry_count > 0) && (ACL_INVALID_DB_INDEX != entry_index) && \
         (enrty = acl_db_entry_ptr(entry_index));                      \
         entry_count--, entry_index = (entry_count > 0) ? enrty->next : entry_index)

#define acl_global_lock()   cl_plock_excl_acquire(&sai_acl_db->acl_settings_tbl->lock)
#define acl_global_unlock() cl_plock_release(&sai_acl_db->acl_settings_tbl->lock)

#define acl_table_write_lock(table_id) cl_plock_excl_acquire(&acl_db_table(table_id).lock)
#define acl_table_read_lock(table_id)  cl_plock_acquire(&acl_db_table(table_id).lock)
#define acl_table_unlock(table_id)     cl_plock_release(&acl_db_table(table_id).lock)

typedef enum acl_psort_rpc_type {
    ACL_RPC_TERMINATE_THREAD,
    ACL_RPC_PSORT_TABLE_INIT,
    ACL_RPC_PSORT_TABLE_DELETE,
    ACL_RPC_PSORT_ENTRY_CREATE,
    ACL_RPC_PSORT_ENTRY_DELETE
} acl_rpc_type_t;
typedef struct acl_psort_rpc_args {
    bool                 table_is_dynamic;
    uint32_t             table_id;
    uint32_t             size;
    uint32_t             entry_id;
    uint32_t             entry_prio;
    sx_acl_rule_offset_t entry_offset;
} acl_rpc_args_t;
typedef struct acl_psort_rpc_call_info {
    acl_rpc_type_t type;
    acl_rpc_args_t args;
    sai_status_t   status;
} acl_rpc_info_t;

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static cl_thread_t psort_thread;
static cl_thread_t rpc_thread;
#ifndef _WIN32
static pthread_key_t      pthread_key;
static mqd_t              fg_mq = ACL_QUEUE_INVALID_HANDLE;
static struct sockaddr_un rpc_sv_sockaddr;
#endif
static sx_api_handle_t psort_sx_api    = SX_API_INVALID_HANDLE, rpc_sx_api = SX_API_INVALID_HANDLE;
static int             rpc_cl_socket   = -1;
static bool            is_init_process = false;

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
static sai_status_t mlnx_acl_entry_vlan_tags_set(_In_ const sai_object_key_t      *key,
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
static sai_status_t fetch_flex_acl_rule_params_to_get(_In_ uint32_t                    acl_table_index,
                                                      _In_ uint32_t                    acl_entry_index,
                                                      _Inout_ sx_flex_acl_flex_rule_t *flex_acl_rule_p);
static sai_status_t fetch_flex_acl_rule_params_to_set(_In_ uint32_t                     acl_table_index,
                                                      _In_ uint32_t                     acl_entry_index,
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
static void mlnx_acl_flex_rule_key_del(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t key_index);
static void mlnx_acl_flex_rule_action_del(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t action_index);
static void mlnx_acl_flex_rule_copy(_Out_ sx_flex_acl_flex_rule_t      *dst_rule,
                                    _In_ const sx_flex_acl_flex_rule_t *src_rule);
static int sai_cmp_flex_acl_rules_offsets(const void *a, const void *b);
static sai_status_t mlnx_acl_flex_rules_get_helper(_In_ const sx_acl_key_type_t     key_type,
                                                   _In_ const sx_acl_region_id_t    region_id,
                                                   _In_ const sx_acl_rule_offset_t *offsets_list_p,
                                                   _Inout_ sx_flex_acl_flex_rule_t *rules_list_p,
                                                   _In_ uint32_t                    rules_count);
static sai_status_t mlnx_acl_flex_rules_set_helper(_In_ sx_access_cmd_t          cmd,
                                                   _In_ const sx_acl_key_type_t  key_type,
                                                   _In_ const sx_acl_region_id_t region_id,
                                                   _In_ sx_acl_rule_offset_t    *offsets_list_p,
                                                   _In_ sx_flex_acl_flex_rule_t *rules_list_p,
                                                   _In_ uint32_t                 rules_count);
static sai_status_t mlnx_delete_acl_entry_data(_In_ uint32_t table_index,
                                               _In_ uint32_t entry_index,
                                               _In_ uint32_t entry_count);
static sx_utils_status_t psort_notification_func(_In_ psort_notification_type_e notif_type,
                                                 _In_ void                     *data,
                                                 _In_ void                     *cookie);
static sai_status_t init_psort_table(_In_ uint32_t table_id, _In_ bool is_table_dynamic, _In_ uint32_t size);
static sai_status_t __init_psort_table(_In_ uint32_t table_id, _In_ bool is_table_dynamic, _In_ uint32_t size);
static sai_status_t get_new_psort_offset(_In_ uint32_t                 table_id,
                                         _In_ uint32_t                 entry_id,
                                         _In_ uint32_t                 priority,
                                         _Inout_ sx_acl_rule_offset_t *offset,
                                         _In_ uint32_t                 request_num);
static sai_status_t __get_new_psort_offset(_In_ uint32_t                 table_id,
                                           _In_ uint32_t                 entry_id,
                                           _In_ uint32_t                 priority,
                                           _Inout_ sx_acl_rule_offset_t *offset,
                                           _In_ uint32_t                 requested_num);
static sai_status_t release_psort_offset(_In_ uint32_t             table_id,
                                         _In_ uint32_t             priority,
                                         _In_ sx_acl_rule_offset_t offset);
static sai_status_t __release_psort_offset(_In_ uint32_t             table_id,
                                           _In_ uint32_t             priority,
                                           _In_ sx_acl_rule_offset_t offset);
static sai_status_t delete_psort_table(_In_ uint32_t table_id);
static sai_status_t __delete_psort_table(_In_ uint32_t table_id);
static sai_status_t create_rpc_server(_Inout_ int *s);
static sai_status_t create_rpc_client(_Inout_ int *s, _Inout_ struct sockaddr_un *sv_sockaddr);
static sai_status_t create_rpc_socket(_Inout_ int *s, _Inout_opt_ struct sockaddr_un *sockaddr, _In_ bool is_server);
static sai_status_t acl_psort_rpc_call(_Inout_ acl_rpc_info_t *rpc_info);
static sai_status_t update_rules_offsets(_In_ const psort_shift_param_t *shift_param, _In_ uint32_t acl_table_index);
static uint32_t acl_calculate_delta(_In_ uint32_t acl_table_index);
static sai_status_t acl_table_size_increase(_In_ uint32_t table_index, _In_ uint32_t size);
static sai_status_t acl_table_size_decrease(_In_ uint32_t table_index);
static void acl_psort_optimize_table(_In_ uint32_t table_index);
static sai_status_t acl_enqueue_table(_In_ uint32_t table_index);
static sai_status_t acl_db_find_entry_free_index(_Out_ uint32_t *free_index);
static sai_status_t acl_db_find_table_free_index(_Out_ uint32_t *free_index);
static sai_status_t acl_db_insert_entries(_In_ uint32_t table_index,
                                          _In_ uint32_t entry_index,
                                          _In_ uint32_t entry_count);
static void acl_db_add_entry_to_table(_In_ uint32_t table_index, _In_ uint32_t new_entry_index);
static void acl_db_remove_entry_from_table(_In_ uint32_t table_index,
                                           _In_ uint32_t entry_index,
                                           _In_ uint32_t entry_count);
static sai_status_t extract_acl_table_index_and_entry_index(_In_ sai_object_id_t entry_object_id,
                                                            _Out_ uint32_t      *acl_table_index,
                                                            _Out_ uint32_t      *acl_entry_index);
static sai_status_t extract_acl_table_index(_In_ sai_object_id_t table_object_id,
                                            _Out_ uint32_t      *acl_table_index);
static sai_status_t extract_acl_counter_index(_In_ sai_object_id_t counter_object_id,
                                              _Out_ uint32_t      *acl_counter_index);
static sai_status_t acl_create_entry_object_id(_Out_ sai_object_id_t *entry_oid,
                                               _In_ uint32_t          entry_index,
                                               _In_ uint16_t          table_index);
static sai_status_t acl_get_entries_offsets(_In_ uint32_t                 entry_index,
                                            _In_ uint32_t                 entry_number,
                                            _Inout_ sx_acl_rule_offset_t *offsets_list);
static sai_status_t mlnx_acl_pbs_get_simple_map_index(_In_ const sx_port_id_t *ports,
                                                      _In_ uint32_t            ports_number,
                                                      _Inout_ pbs_index_t     *pbs_index);

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_acl_pbs_get_map_index_and_key(_In_ const sx_port_id_t *ports,
                                                       _In_ uint32_t            ports_number,
                                                       _Out_ pbs_index_t       *pbs_index,
                                                       _Out_ acl_pbs_map_key_t *pbs_key);
static sai_status_t mlnx_acl_pbs_entry_create_or_get(_In_ sx_port_id_t       *ports,
                                                     _In_ uint32_t            ports_number,
                                                     _Inout_ sx_acl_pbs_id_t *pbs_id,
                                                     _Inout_ pbs_index_t     *pbs_index);
static sai_status_t mlnx_acl_pbs_entry_delete(pbs_index_t pbs_index);
static sai_status_t mlnx_acl_pbs_map_port_to_index(_In_ sx_port_id_t port, _Out_ uint32_t *index);
static sai_status_t mlnx_acl_pbs_map_ports_to_key(_In_ const sx_port_id_t   *ports,
                                                  _In_ uint32_t              port_number,
                                                  _Inout_ acl_pbs_map_key_t *pbs_map_key);
static sai_status_t mlnx_acl_pbs_map_get_ports(_In_ pbs_index_t      pbs_index,
                                               _Inout_ sx_port_id_t *ports,
                                               _Inout_ uint32_t     *port_number);
static uint32_t mlnx_acl_pbs_map_key_to_index(_In_ acl_pbs_map_key_t key, uint32_t step);
static sai_status_t acl_resources_init();
static sai_status_t acl_background_threads_close();
static sai_status_t acl_psort_background_close();
static sai_status_t acl_psort_rpc_thread_close();
static void mlnx_acl_psort_deinit();
static void mlnx_acl_table_locks_deinit();
static void psort_background_thread(void *arg);
static void psort_rpc_thread(void *arg);

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
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_VLAN_TAGS,
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
      { true, false, false, true },
      { true, false, true, true },
      mlnx_acl_entry_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS,
      mlnx_acl_entry_vlan_tags_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS },
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
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST },
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

sai_status_t mlnx_acl_deinit()
{
    sai_status_t status;

    SX_LOG_ENTER();

    status = acl_background_threads_close();
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to close ACL background threads\n");
    }

    mlnx_acl_foreground_ipc_deinit();
    mlnx_acl_psort_deinit();
    mlnx_acl_table_locks_deinit();

#ifndef _WIN32
    if (0 != pthread_key_delete(pthread_key)) {
        SX_LOG_ERR("Failed to delete pthread_key\n");
    }
#endif

    SX_LOG_EXIT();
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

sai_status_t mlnx_acl_init()
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    is_init_process = true;

    sai_acl_db->acl_settings_tbl->initialized                  = false;
    sai_acl_db->acl_settings_tbl->bg_stop                      = false;
    sai_acl_db->acl_settings_tbl->background_thread_start_flag = false;
    sai_acl_db->acl_settings_tbl->rpc_thread_start_flag        = false;

#ifndef _WIN32
    pthread_condattr_t  cond_attr;
    pthread_mutexattr_t mutex_attr;

    if (0 != pthread_condattr_init(&cond_attr)) {
        SX_LOG_ERR("Failed to init contition variable attribute for ACL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_NO_MEMORY;
    }

    if (0 != pthread_mutexattr_init(&mutex_attr)) {
        SX_LOG_ERR("Failed to init contition variable attribute for ACL\n");
        status = SAI_STATUS_NO_MEMORY;
        goto err_cond_attr;
    }

    if (0 != pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED)) {
        SX_LOG_ERR("Failed to set contition variable attribute for ACL - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (0 != pthread_cond_init(&sai_acl_db->acl_settings_tbl->background_thread_init_cond, &cond_attr)) {
        SX_LOG_ERR("Failed to init contition variable for ACL - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (0 != pthread_cond_init(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond, &cond_attr)) {
        SX_LOG_ERR("Failed to init contition variable for ACL - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (0 != pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED)) {
        SX_LOG_ERR("Failed to set contition variable attribute for ACL - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (0 != pthread_mutex_init(&acl_cond_mutex, &mutex_attr)) {
        SX_LOG_ERR("Failed to init mutex for ACL - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (CL_SUCCESS != cl_plock_init_pshared(&sai_acl_db->acl_settings_tbl->lock)) {
        SX_LOG_ERR("Failed to init cl_plock for ACL\n");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    if (0 != pthread_key_create(&pthread_key, NULL)) {
        SX_LOG_ERR("Failed to init pthread_key for ACL\n");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    if (0 != pthread_setspecific(pthread_key, &gh_sdk)) {
        SX_LOG_ERR("Failed to call pthread_setspecific\n");
        goto out;
    }

    if (CL_SUCCESS != cl_thread_init(&psort_thread, psort_background_thread, NULL, NULL)) {
        SX_LOG_ERR("Failed to init acl bg thread\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (CL_SUCCESS != cl_thread_init(&rpc_thread, psort_rpc_thread, NULL, NULL)) {
        SX_LOG_ERR("Failed to init acl req thread\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    if (0 != pthread_mutexattr_destroy(&mutex_attr)) {
        SX_LOG_ERR("Failed to destory mutex attribute for ACL\n");
        status = SAI_STATUS_FAILURE;
    }

err_cond_attr:
    if (0 != pthread_condattr_destroy(&cond_attr)) {
        SX_LOG_ERR("Failed to destory contition variable attribute for ACL\n");
        status = SAI_STATUS_FAILURE;
    }
#endif /* ifndef _WIN32 */

    SX_LOG_EXIT();
    return status;
}

/*
 *   Routine Description:
 *       Unitialize ACL Respurces
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */

sai_status_t acl_resources_init()
{
    sx_status_t  sx_status;
    sai_status_t status = SAI_STATUS_SUCCESS;
    sx_acl_id_t  ingress_acl_group_id;
    sx_acl_id_t  egress_acl_group_id;

#ifndef _WIN32
    struct mq_attr mq_attributes;
#endif

    SX_LOG_ENTER();

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, SX_ACL_DIRECTION_INGRESS, NULL, 0,
                                     &ingress_acl_group_id);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Unable to create ingress acl group - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    acl_db_group_by_sai_stage(SAI_ACL_STAGE_INGRESS)->acl_table_count = 0;
    acl_db_group_by_sai_stage(SAI_ACL_STAGE_INGRESS)->group_id        = ingress_acl_group_id;
    SX_LOG_NTC("Ingress ACl Group created with group id[%d] \n", ingress_acl_group_id);

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, SX_ACL_DIRECTION_EGRESS, NULL, 0,
                                     &egress_acl_group_id);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Unable to create egress acl group - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    acl_db_group_by_sai_stage(SAI_ACL_STAGE_EGRESS)->acl_table_count = 0;
    acl_db_group_by_sai_stage(SAI_ACL_STAGE_EGRESS)->group_id        = egress_acl_group_id;
    SX_LOG_NTC("Egress ACl Group created with group id[%d] \n", egress_acl_group_id);

#ifndef _WIN32
    mq_attributes.mq_flags   = 0;
    mq_attributes.mq_maxmsg  = ACL_QUEUE_SIZE;
    mq_attributes.mq_msgsize = ACL_QUEUE_MSG_SIZE;
    mq_attributes.mq_curmsgs = 0;

    mq_unlink(ACL_QUEUE_NAME);

    fg_mq = mq_open(ACL_QUEUE_NAME, O_CREAT | O_WRONLY | O_NONBLOCK, (S_IRWXU | S_IRWXG | S_IRWXO), &mq_attributes);
    if (ACL_QUEUE_INVALID_HANDLE == fg_mq) {
        SX_LOG_ERR("Failed to open acl fg_mq - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    /* trigger background thread */
    acl_cond_mutex_lock();
    sai_acl_db->acl_settings_tbl->background_thread_start_flag = true;
    if (0 != pthread_cond_signal(&sai_acl_db->acl_settings_tbl->background_thread_init_cond)) {
        SX_LOG_ERR("Failed to signal condition variable to wake up ACL background thread\n");
        status = SAI_STATUS_FAILURE;
        acl_cond_mutex_unlock();
        goto out;
    }
    acl_cond_mutex_unlock();
#endif

    sai_acl_db->acl_settings_tbl->initialized = true;

out:
    SX_LOG_EXIT();
    return status;
}

/*
 *   Routine Description:
 *       Close ACL background threads
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */

static sai_status_t acl_background_threads_close()
{
    sai_status_t status;

    status = acl_psort_background_close();
    status = acl_psort_rpc_thread_close();

#ifndef _WIN32
    if (0 != pthread_mutex_destroy(&sai_acl_db->acl_settings_tbl->cond_mutex)) {
        SX_LOG_ERR("Failed to destroy cond variable\n");
        status = SAI_STATUS_FAILURE;
    }
#endif

    return status;
}

/*
 *   Routine Description:
 *       Close ACL pSort background thread
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */

static sai_status_t acl_psort_background_close()
{
#ifndef _WIN32
    uint32_t msg = ACL_BCKG_THREAD_EXIT_MSG;

    if (false == sai_acl_db->acl_settings_tbl->initialized) {
        sai_acl_db->acl_settings_tbl->bg_stop = true;

        acl_cond_mutex_lock();
        sai_acl_db->acl_settings_tbl->background_thread_start_flag = true;
        if (0 != pthread_cond_signal(&sai_acl_db->acl_settings_tbl->background_thread_init_cond)) {
            SX_LOG_ERR("Failed to signal condition var to wake up ACL background thread\n");
            acl_cond_mutex_unlock();
            return SAI_STATUS_FAILURE;
        }
        acl_cond_mutex_unlock();
    } else {
        if (ACL_QUEUE_INVALID_HANDLE == fg_mq) {
            fg_mq = mq_open(ACL_QUEUE_NAME, O_WRONLY);
            if (ACL_QUEUE_INVALID_HANDLE == fg_mq) {
                SX_LOG_ERR("Failed to open mq - %s\n", strerror(errno));
                return SAI_STATUS_FAILURE;
            }
        }

        if (-1 == mq_send(fg_mq, (const char*)&msg, sizeof(msg), ACL_QUEUE_EXIT_MSG_PRIO)) {
            SX_LOG_ERR("Failed to send exit msg to background thread - %s\n", strerror(errno));
            return SAI_STATUS_FAILURE;
        }
    }

    cl_thread_destroy(&psort_thread);

    if (0 != pthread_cond_destroy(&sai_acl_db->acl_settings_tbl->background_thread_init_cond)) {
        SX_LOG_ERR("Failed to destroy cond variable\n");
        return SAI_STATUS_FAILURE;
    }
#endif

    return SAI_STATUS_SUCCESS;
}

/*
 *   Routine Description:
 *       Close ACL RPC thread
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */

static sai_status_t acl_psort_rpc_thread_close()
{
    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    acl_rpc_info_t rpc_info;

    if (false == sai_acl_db->acl_settings_tbl->rpc_thread_start_flag) {
        sai_acl_db->acl_settings_tbl->bg_stop = true;
        acl_cond_mutex_lock();
        sai_acl_db->acl_settings_tbl->rpc_thread_start_flag = true;
        if (0 != pthread_cond_signal(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond)) {
            SX_LOG_ERR("Failed to signal condition var to wake up RPC thread\n");
            status = SAI_STATUS_FAILURE;
        }
        acl_cond_mutex_unlock();
    } else {
        rpc_info.type = ACL_RPC_TERMINATE_THREAD;
        status        = acl_psort_rpc_call(&rpc_info);
    }

    cl_thread_destroy(&rpc_thread);

    if (0 != pthread_cond_destroy(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond)) {
        SX_LOG_ERR("Failed to destroy cond variable\n");
        status = SAI_STATUS_FAILURE;
    }
#endif

    return status;
}

/*
 *   Routine Description:
 *       Deinitialize ACL IPC
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             None
 */

void mlnx_acl_foreground_ipc_deinit()
{
#ifndef _WIN32
    if (ACL_QUEUE_INVALID_HANDLE != fg_mq) {
        if (0 != mq_close(fg_mq)) {
            SX_LOG_ERR("Failed to close ACL mq\n");
        }
    }

    if (-1 != rpc_cl_socket) {
        close(rpc_cl_socket);
    }
#endif
}

/*
 *   Routine Description:
 *       Deinitialize pSort recourses
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             None
 */

static void mlnx_acl_psort_deinit()
{
    uint32_t ingress_table_count, egress_table_count;
    uint32_t ii, table_index;

    ingress_table_count = sai_acl_db->acl_ingress_group_db->acl_table_count;
    egress_table_count  = sai_acl_db->acl_egress_group_db->acl_table_count;

    for (ii = 0; ii < ingress_table_count; ii++) {
        table_index = sai_acl_db->acl_ingress_group_db->table_indexes[ii];
        __delete_psort_table(table_index);
    }

    for (ii = 0; ii < egress_table_count; ii++) {
        table_index = sai_acl_db->acl_egress_group_db->table_indexes[ii];
        __delete_psort_table(table_index);
    }
}


/*
 *   Routine Description:
 *       Deinitialize table locks
 *
 *      Arguments:
 *          None
 *
 *         Return Values:
 *             None
 */

static void mlnx_acl_table_locks_deinit()
{
    uint32_t ii;

    for (ii = 0; ii < ACL_MAX_TABLE_NUMBER; ii++) {
        if (acl_db_table(ii).is_lock_inited) {
            cl_plock_destroy(&acl_db_table(ii).lock);
        }
    }
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
    sai_status_t status;
    uint32_t     acl_table_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_TABLE_ATTR_STAGE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_PRIORITY == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_SIZE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_GROUP_ID == (int64_t)arg));

    status = extract_acl_table_index(key->object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_ATTR_STAGE:
        value->s32 = acl_db_table(acl_table_index).stage;
        break;

    case SAI_ACL_TABLE_ATTR_PRIORITY:
        value->u32 = acl_db_table(acl_table_index).priority;
        break;

    case SAI_ACL_TABLE_ATTR_SIZE:
        value->u32 = acl_db_table(acl_table_index).table_size;
        break;

    case SAI_ACL_TABLE_ATTR_GROUP_ID:
        status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP,
                                    acl_db_group_by_sai_stage(acl_db_table(acl_table_index).stage)->group_id,
                                    NULL,
                                    &value->oid);
        break;
    }

    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
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
    sx_status_t       sx_status;
    sai_status_t      status;
    sx_acl_key_t      keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    uint32_t          key_count = 0, key_id = 0;
    sx_acl_key_type_t key_handle;
    uint32_t          key_desc_index;
    uint32_t          acl_table_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_TABLE_ATTR_FIELD_START < (int64_t)arg) && ((int64_t)arg < SAI_ACL_TABLE_ATTR_FIELD_END));

    status = extract_acl_table_index(key->object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    key_handle = acl_db_table(acl_table_index).key_type;

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6:
        key_id = FLEX_ACL_KEY_SIPV6;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6:
        key_id = FLEX_ACL_KEY_DIPV6;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_DEI;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_INNER_DEI;
        break;

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
/*
 *   case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID:
 *       key_id = FLEX_ACL_KEY_INNER_VLAN_ID;
 *       break;
 */

    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_INNER_PCP;
        break;

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

    case SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META:
        key_id = FLEX_ACL_KEY_USER_TOKEN;
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_VLAN_TAGS:
        key_id = FLEX_ACL_KEY_VLAN_TAGGED;
        break;

    default:
        SX_LOG_ERR(" Invalid attribute to get\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    sx_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, keys, &key_count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(" Failed to get flex acl key in SDK - %s \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
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
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_ip_and_tos_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sx_status_t       sx_status;
    sai_status_t      status;
    sx_acl_key_t      keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    uint32_t          key_count = 0, index = 0;
    sx_acl_key_type_t key_handle;
    uint32_t          key_desc_index;
    uint32_t          acl_table_index;
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

    status = extract_acl_table_index(key->object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    key_handle = acl_db_table(acl_table_index).key_type;

    sx_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, keys, &key_count);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(" Failed to get flex acl key in SDK - %s \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
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
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

sai_status_t acl_db_find_entry_free_index(_Out_ uint32_t *free_index)
{
    sai_status_t status;
    uint32_t     ii;

    SX_LOG_ENTER();
    assert(free_index != NULL);

    for (ii = 0; ii < ACL_MAX_ENTRY_NUMBER; ii++) {
        if (false == acl_db_entry(ii).is_used) {
            *free_index              = ii;
            acl_db_entry(ii).is_used = true;
            status                   = SAI_STATUS_SUCCESS;
            break;
        }
    }

    if (ii == ACL_MAX_ENTRY_NUMBER) {
        SX_LOG_ERR("Max Limit of ACL Entries Reached\n");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    SX_LOG_EXIT();
    return status;
}

sai_status_t acl_db_find_table_free_index(_Out_ uint32_t *free_index)
{
    sai_status_t status;
    uint32_t     ii;

    SX_LOG_ENTER();
    assert(free_index != NULL);

    for (ii = 0; ii < ACL_MAX_TABLE_NUMBER; ii++) {
        if ((false == acl_db_table(ii).is_used) &&
            (0 == acl_db_table(ii).queued)) {
            *free_index              = ii;
            acl_db_table(ii).is_used = true;
            status                   = SAI_STATUS_SUCCESS;
            break;
        }
    }

    if (ii == ACL_MAX_TABLE_NUMBER) {
        SX_LOG_ERR("Max Limit of ACL Tables Reached\n");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    SX_LOG_EXIT();
    return status;
}

/*
 *     Routine Description:
 *         Get ACL Table Id and ACL Entry Index in ACL Table
 *
 *         Arguments:
 *           [in]  entry_object_id - ACL Entry Object Id
 *           [out] acl_table_index - ACL Table Index
 *           [out] acl_entry_index - ACL Entry Index
 *
 *         Return Values:
 *          SAI_STATUS_SUCCESS on success
 *          SAI_STATUS_FAILURE on error
 */

static sai_status_t extract_acl_table_index_and_entry_index(_In_ sai_object_id_t entry_object_id,
                                                            _Out_ uint32_t      *acl_table_index,
                                                            _Out_ uint32_t      *acl_entry_index)
{
    sai_status_t status;
    uint32_t     entry_data;
    uint8_t      table_data[EXTENDED_DATA_SIZE];

    SX_LOG_ENTER();

    assert((acl_table_index != NULL) && (acl_entry_index != NULL));

    status = mlnx_object_to_type(entry_object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &entry_data, table_data);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    *acl_table_index = *(uint16_t*)&table_data;
    if (!acl_table_index_check_range(*acl_table_index)) {
        SX_LOG_ERR("Got bad ACL Table index from object_id - %x\n", *acl_table_index);
        status = SAI_STATUS_FAILURE;
    }

    if (false == acl_db_table(*acl_table_index).is_used) {
        SX_LOG_ERR("Table [%d] is deleted\n", *acl_table_index);
        status = SAI_STATUS_FAILURE;
    }

    *acl_entry_index = entry_data;
    if (!acl_entry_index_check_range(*acl_entry_index)) {
        SX_LOG_ERR("Got bad ACL Entry index from object_id - %x\n", *acl_entry_index);
        status = SAI_STATUS_FAILURE;
    }

    if (false == acl_db_entry(*acl_entry_index).is_used) {
        SX_LOG_ERR("Entry [%d] is deleted\n", *acl_entry_index);
        status = SAI_STATUS_FAILURE;
    }

out:
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Unable to extract acl table index and acl entry index in acl table\n");
    }

    SX_LOG_EXIT();
    return status;
}

/*
 *     Routine Description:
 *         Get ACL Table Id
 *
 *         Arguments:
 *           [in]  table_object_id - ACL Table Object Id
 *           [out] acl_table_index - ACL Table Index
 *
 *         Return Values:
 *          SAI_STATUS_SUCCESS on success
 *          SAI_STATUS_FAILURE on error
 */
static sai_status_t extract_acl_table_index(_In_ sai_object_id_t table_object_id,
                                            _Out_ uint32_t      *acl_table_index)
{
    sai_status_t status;

    SX_LOG_ENTER();

    assert(acl_table_index != NULL);

    status = mlnx_object_to_type(table_object_id, SAI_OBJECT_TYPE_ACL_TABLE, acl_table_index, NULL);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (false == acl_table_index_check_range(*acl_table_index)) {
        SX_LOG_ERR("Got bad ACL Table index from object_id - %x\n", *acl_table_index);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (false == acl_db_table(*acl_table_index).is_used) {
        SX_LOG_ERR("Table [%d] is deleted\n", *acl_table_index);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Unable to extract acl table index\n");
    }

    SX_LOG_EXIT();
    return status;
}

/*
 *     Routine Description:
 *         Get ACL Counter Id
 *
 *         Arguments:
 *           [in]  counter_object_id - ACL Entry Object Id
 *           [out] acl_counter_index - ACL Table Index
 *
 *         Return Values:
 *          SAI_STATUS_SUCCESS on success
 *          SAI_STATUS_FAILURE on error
 */
static sai_status_t extract_acl_counter_index(_In_ sai_object_id_t counter_object_id,
                                              _Out_ uint32_t      *acl_counter_index)
{
    sai_status_t status;

    SX_LOG_ENTER();

    assert(acl_counter_index != NULL);

    status = mlnx_object_to_type(counter_object_id, SAI_OBJECT_TYPE_ACL_COUNTER, acl_counter_index, NULL);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (!acl_counter_index_check_range(*acl_counter_index)) {
        SX_LOG_ERR("Got bad ACL Counter index from object_id - %x\n", *acl_counter_index);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (false == sai_acl_db->acl_counter_db[*acl_counter_index].is_valid) {
        SX_LOG_ERR("Counter [%d] is deleted\n", *acl_counter_index);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Unable to extract acl couner index\n");
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t status;
    uint32_t     acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_TABLE_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_PRIORITY == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_TABLE_ID:
        status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, acl_table_index, NULL, &value->oid);
        break;

    case SAI_ACL_ENTRY_ATTR_PRIORITY:
        value->u32 = sai_acl_db->acl_entry_db[acl_entry_index].priority;
        break;
    }

    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t fetch_flex_acl_rule_params_to_get(_In_ uint32_t                    acl_table_index,
                                                      _In_ uint32_t                    acl_entry_index,
                                                      _Inout_ sx_flex_acl_flex_rule_t *flex_acl_rule_p)
{
    sx_status_t          sx_status;
    sai_status_t         status    = SAI_STATUS_SUCCESS;
    sx_acl_region_id_t   region_id = 0;
    sx_acl_rule_offset_t rule_offset;
    sx_acl_key_type_t    key_type;

    assert(flex_acl_rule_p != NULL);

    SX_LOG_ENTER();

    rule_offset = sai_acl_db->acl_entry_db[acl_entry_index].offset;
    region_id   = acl_db_table(acl_table_index).region_id;
    key_type    = acl_db_table(acl_table_index).key_type;

    memset(flex_acl_rule_p, 0, sizeof(sx_flex_acl_flex_rule_t));

    sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS,
                                          flex_acl_rule_p);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = mlnx_acl_flex_rules_get_helper(key_type, region_id, &rule_offset, flex_acl_rule_p, 1);
    if (SAI_STATUS_SUCCESS != status) {
        goto out_deinit;
    }

out_deinit:
    if (SAI_STATUS_SUCCESS != status) {
        sx_status = sx_lib_flex_acl_rule_deinit(flex_acl_rule_p);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
        }
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_mac_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t            status;
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                key_desc_index;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
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
            memcpy(value->aclfield.data.mac, &flex_acl_rule.key_desc_list_p[key_desc_index].key.smac,
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
            memcpy(value->aclfield.data.mac, &flex_acl_rule.key_desc_list_p[key_desc_index].key.dmac,
                   sizeof(value->mac));
            memcpy(value->aclfield.mask.mac, &flex_acl_rule.key_desc_list_p[key_desc_index].mask.dmac,
                   sizeof(value->mac));
        } else {
            SX_LOG_ERR(" Invalid Attribute to get : DST MAC \n");
        }
        break;
    }

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
    }

out:
    acl_table_unlock(acl_table_index);

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
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_acl_key_t            ip_type_keys[IP_TYPE_KEY_SIZE];
    sx_acl_key_t            ip_frag_key, ip_frag_not_first_key;
    uint32_t                key_id                 = 0, index, key_desc_index = 0;
    uint32_t                ip_frag_key_desc_index = 0, ip_frag_not_first_key_desc_index = 0;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_key_type_present    = false;
    bool                    is_ip_frag_key_present = false, is_ip_frag_not_first_key_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_FRAG == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS == (int64_t)arg));

    /* TODO: Uncomment, ip_type_keys[3], when is_ip_v6 key is available */
    ip_type_keys[0] = FLEX_ACL_KEY_IP_OK;
    ip_type_keys[1] = FLEX_ACL_KEY_IS_IP_V4;
    ip_type_keys[2] = FLEX_ACL_KEY_IS_ARP;
    /* ip_type_keys[3] = FLEX_ACL_KEY_IS_IP_V6; */

    ip_frag_key           = FLEX_ACL_KEY_IP_FRAGMENTED;
    ip_frag_not_first_key = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
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
        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == ip_frag_key) {
                is_ip_frag_key_present = true;
                ip_frag_key_desc_index = key_desc_index;
            }

            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == ip_frag_not_first_key) {
                is_ip_frag_not_first_key_present = true;
                ip_frag_not_first_key_desc_index = key_desc_index;
            }

            if (is_ip_frag_key_present && ip_frag_not_first_key_desc_index) {
                break;
            }
        }

        if (is_ip_frag_key_present) {
            if (is_ip_frag_not_first_key_present) {
                if (flex_acl_rule.key_desc_list_p[ip_frag_key_desc_index].key.ip_fragmented) {
                    if (flex_acl_rule.key_desc_list_p[ip_frag_not_first_key_desc_index].key.ip_fragment_not_first) {
                        value->aclfield.data.s32 = SAI_ACL_IP_FRAG_NON_HEAD;
                    } else {
                        value->aclfield.data.s32 = SAI_ACL_IP_FRAG_HEAD;
                    }
                }
            } else {
                if (flex_acl_rule.key_desc_list_p[ip_frag_key_desc_index].key.ip_fragmented) {
                    value->aclfield.data.s32 = SAI_ACL_IP_FRAG_ANY;
                } else {
                    value->aclfield.data.s32 = SAI_ACL_IP_FRAG_NON_FRAG;
                }
            }
        } else if (!is_ip_frag_key_present) {
            if (is_ip_frag_not_first_key_present) {
                if (!flex_acl_rule.key_desc_list_p[ip_frag_not_first_key_desc_index].key.ip_fragment_not_first) {
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

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

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
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_ip_addr_t            ipaddr_data, ipaddr_mask;
    sai_ip_address_t        ip_address_data, ip_address_mask;
    uint32_t                key_id         = 0;
    uint32_t                key_desc_index = 0;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_key_type_present = true;

    SX_LOG_ENTER();

    memset(&ipaddr_data, 0, sizeof(ipaddr_data));
    memset(&ip_address_data, 0, sizeof(ip_address_data));
    memset(&ipaddr_mask, 0, sizeof(ipaddr_mask));
    memset(&ip_address_mask, 0, sizeof(ip_address_mask));

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
        key_id = FLEX_ACL_KEY_SIPV6;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
        key_id = FLEX_ACL_KEY_DIPV6;
        break;

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
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
        if (is_key_type_present) {
            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dipv6,
                                                          &ip_address_data);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dipv6,
                                                          &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
            memcpy(&value->aclfield.data.ip6, &ip_address_data.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
            memcpy(&value->aclfield.mask.ip6, &ip_address_mask.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : SRC_IPv6 \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
        if (is_key_type_present) {
            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dipv6,
                                                          &ip_address_data);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dipv6,
                                                          &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }

            memcpy(&value->aclfield.data.ip6, &ip_address_data.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
            memcpy(&value->aclfield.mask.ip6, &ip_address_mask.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
        } else {
            SX_LOG_ERR("Invalid Attribute to Get : DST_IPv6 \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
        if (is_key_type_present) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sip,
                                                               &ip_address_data))) {
                goto out_deinit;
            }

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip,
                                                               &ip_address_mask))) {
                goto out_deinit;
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
                goto out_deinit;
            }

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip,
                                                               &ip_address_mask))) {
                goto out_deinit;
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

out_deinit:
    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

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
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_acl_key_t            key_id         = 0;
    uint8_t                 key_desc_index = 0;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
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
/*
 *   case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
 *       key_id = FLEX_ACL_KEY_INNER_VLAN_ID;
 *       break;*/

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_INNER_DEI;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_INNER_PCP;
        break;
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
/*
 *   case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
 *       if (is_key_type_present) {
 *           value->aclfield.data.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_vlan_id;
 *           value->aclfield.mask.u16 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_vlan_id;
 *       } else {
 *           SX_LOG_ERR(" Invalid Attribute to get : INNER VID \n");
 *           status = SAI_STATUS_NOT_SUPPORTED;
 *       }
 *       break;*/

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

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ports_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sx_status_t              sx_status;
    sai_status_t             status;
    sx_acl_region_id_t       region_id = 0;
    sx_acl_key_type_t        key_type;
    sx_acl_rule_offset_t    *offsets_list_p     = NULL;
    sx_flex_acl_flex_rule_t *flex_acl_rule_p    = NULL;
    sx_acl_key_t             key_id             = 0;
    uint32_t                 flex_acl_rules_num = 1, flex_rule_index;
    uint32_t                 acl_table_index, acl_entry_index;
    bool                     is_key_type_present = false;
    uint8_t                  key_desc_index      = 0;
    uint32_t                 ii                  = 0;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    region_id          = acl_db_table(acl_table_index).region_id;
    key_type           = acl_db_table(acl_table_index).key_type;
    flex_acl_rules_num = sai_acl_db->acl_entry_db[acl_entry_index].num_rules;

    if (value->aclfield.data.objlist.count < flex_acl_rules_num) {
        value->aclfield.data.objlist.count = flex_acl_rules_num;
        status                             = SAI_STATUS_BUFFER_OVERFLOW;
        SX_LOG_ERR(" Re-allocate list size as list size is not large enough \n");
        goto out;
    } else if (value->aclfield.data.objlist.count > flex_acl_rules_num) {
        value->aclfield.data.objlist.count = flex_acl_rules_num;
    }

    offsets_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for flex_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    memset(offsets_list_p, 0, sizeof(sx_acl_rule_offset_t) * flex_acl_rules_num);

    status = acl_get_entries_offsets(acl_entry_index, flex_acl_rules_num, offsets_list_p);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);
    if (flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for flex_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    memset(flex_acl_rule_p, 0, sizeof(sx_flex_acl_flex_rule_t) * flex_acl_rules_num);

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[ii]);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
            status             = sdk_to_sai(sx_status);
            flex_acl_rules_num = ii;
            goto out;
        }
    }

    status = mlnx_acl_flex_rules_get_helper(key_type, region_id, offsets_list_p, flex_acl_rule_p, flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
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
            goto out;
        }

        for (flex_rule_index = 0; flex_rule_index < flex_acl_rules_num; flex_rule_index++) {
            status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                        flex_acl_rule_p[flex_rule_index].key_desc_list_p[key_desc_index].key.src_port,
                                        NULL,
                                        &value->aclfield.data.objlist.list[flex_rule_index]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
        if (!is_key_type_present) {
            SX_LOG_ERR(" Invalid Attribute to get : OUT_PORTS \n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        for (flex_rule_index = 0; flex_rule_index < flex_acl_rules_num; flex_rule_index++) {
            status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                        flex_acl_rule_p[flex_rule_index].key_desc_list_p[key_desc_index].key.dst_port,
                                        NULL,
                                        &value->aclfield.data.objlist.list[flex_rule_index]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }
        break;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]))) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_port_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t            status;
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_acl_key_t            key_id = 0;
    uint32_t                key_desc_index;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
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
            status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                        flex_acl_rule.key_desc_list_p[key_desc_index].key.
                                        src_port, NULL, &value->aclfield.data.oid);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get :  IN PORT \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        if (is_key_type_present) {
            status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                        flex_acl_rule.key_desc_list_p[key_desc_index].key.dst_port,
                                        NULL,
                                        &value->aclfield.data.oid);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : OUT PORT \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;
    }

out_deinit:
    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

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
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                key_desc_index, key_id = 0;
    uint32_t                acl_table_index, acl_entry_index;
    uint32_t                vlan_tagged_key_desc_index = 0, inner_vlan_valid_key_desc_index = 0;
    bool                    is_key_type_present        = false;
    bool                    is_vlan_tagged             = false, is_inner_vlan_valid = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ADMIN_STATE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE:
        key_id = FLEX_ACL_KEY_ETHERTYPE;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
        key_id = FLEX_ACL_KEY_TTL;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TC:
        key_id = FLEX_ACL_KEY_SWITCH_PRIO;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
        key_id = FLEX_ACL_KEY_USER_TOKEN;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS:
        key_id = FLEX_ACL_KEY_TCP_CONTROL;
        break;
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

    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
        if (is_key_type_present) {
            value->aclfield.data.u32 = flex_acl_rule.key_desc_list_p[key_desc_index].key.user_token;
            value->aclfield.mask.u32 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.user_token;
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : ACL User Meta \n");
            status = SAI_STATUS_NOT_SUPPORTED;
        }
        break;

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

    case SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS:
        for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_VLAN_TAGGED) {
                is_vlan_tagged             = true;
                vlan_tagged_key_desc_index = key_desc_index;
            }

            if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_INNER_VLAN_VALID) {
                is_inner_vlan_valid             = true;
                inner_vlan_valid_key_desc_index = key_desc_index;
            }

            if (is_vlan_tagged && is_inner_vlan_valid) {
                break;
            }
        }

        if (is_vlan_tagged) {
            if (!flex_acl_rule.key_desc_list_p[vlan_tagged_key_desc_index].key.vlan_tagged) {
                value->aclfield.data.s32 = SAI_PACKET_VLAN_UNTAG;
            } else if (!flex_acl_rule.key_desc_list_p[inner_vlan_valid_key_desc_index].key.inner_vlan_valid) {
                value->aclfield.data.s32 = SAI_PACKET_VLAN_SINGLE_OUTER_TAG;
            } else {
                value->aclfield.data.s32 = SAI_PACKET_VLAN_DOUBLE_TAG;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : VLAN_TAGS \n");
        }
        break;
    }

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

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
    sx_status_t                  sx_status;
    sx_flex_acl_flex_rule_t      flex_acl_rule;
    uint32_t                     flex_action_index;
    uint32_t                     forward_action_index = 0, trap_action_index = 0;
    uint32_t                     action_type;
    sx_flex_acl_forward_action_t forward_action;
    sx_flex_acl_trap_action_t    trap_action;
    uint32_t                     acl_table_index, acl_entry_index;
    bool                         is_trap_action_present    = false;
    bool                         is_forward_action_present = false;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
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

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                acl_table_index, acl_entry_index, counter_id;
    bool                    is_action_type_present = false;
    sx_acl_pbs_id_t         action_id              = 0, action_index, pbs_ports_number;
    sx_port_id_t            pds_port, *pbs_ports = NULL;
    uint32_t                policer_db_entry_index;
    sai_object_id_t         sai_policer;
    sx_status_t             sx_status;
    uint32_t                ii;
    pbs_index_t             pbs_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_COUNTER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        action_id = SX_FLEX_ACL_ACTION_PBS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
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
        SX_LOG_ERR(" Invalid Attrib to get \n");
        status = SAI_STATUS_FAILURE;
        goto out_deinit;
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
            pbs_index        = acl_db_entry(acl_entry_index).pbs_index;
            pbs_ports_number = 1;

            status = mlnx_acl_pbs_map_get_ports(pbs_index, &pds_port, &pbs_ports_number);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }

            status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, pds_port, NULL, &value->aclaction.parameter.oid);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Redirect \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
        if (is_action_type_present) {
            pbs_index        = acl_db_entry(acl_entry_index).pbs_index;
            pbs_ports_number = value->aclaction.parameter.objlist.count;

            pbs_ports = (sx_port_id_t*)malloc(sizeof(sx_port_id_t) * pbs_ports_number);
            if (NULL == pbs_ports) {
                SX_LOG_ERR("ERROR: unable to allocate memory for sx_port_id_t\n");
                status = SAI_STATUS_NO_MEMORY;
                goto out_deinit;
            }

            status = mlnx_acl_pbs_map_get_ports(pbs_index, pbs_ports, &pbs_ports_number);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }

            value->aclaction.parameter.objlist.count = pbs_ports_number;

            for (ii = 0; ii < pbs_ports_number; ii++) {
                status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                            pbs_ports[ii],
                                            NULL,
                                            &value->aclaction.parameter.objlist.list[ii]);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out_deinit;
                }
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Redirect list \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_COUNTER:
        if (is_action_type_present) {
            counter_id = sai_acl_db->acl_entry_db[acl_entry_index].counter_id;
            status     = mlnx_create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_id, NULL,
                                            &value->aclaction.parameter.oid);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
        } else {
            SX_LOG_ERR(" Invalid Attribute to Get : Action Counter \n");
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
        if (is_action_type_present) {
            status = db_find_sai_policer_entry_ind(flex_acl_rule.action_list_p[action_index].fields.action_policer.
                                                   policer_id,
                                                   &policer_db_entry_index);
            if (SAI_STATUS_SUCCESS != status) {
                SX_LOG_ERR("Failed to obtain sai_policer from sx_policer:0x%" PRIx64 "for acl. err:%d.\n",
                           flex_acl_rule.action_list_p[action_index].fields.action_policer.policer_id,
                           status);
            } else {
                status = mlnx_create_object(SAI_OBJECT_TYPE_POLICER, policer_db_entry_index, NULL, &sai_policer);
                if (SAI_STATUS_SUCCESS != status) {
                    SX_LOG_ERR("Internal error while creating the policer.\n");
                }
            }

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

out_deinit:
    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

    free(pbs_ports);

out:
    acl_table_unlock(acl_table_index);

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
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                acl_table_index, acl_entry_index;
    uint8_t                 key_desc_index;
    bool                    is_key_type_present = false, is_key_id_two_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TOS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
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

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

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
    sx_status_t                    sx_status;
    sx_flex_acl_flex_rule_t        flex_acl_rule;
    sx_flex_acl_flex_action_type_t action_type       = 0;
    uint8_t                        flex_action_index = 0;
    uint32_t                       acl_table_index, acl_entry_index;
    bool                           is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI == (int64_t)arg));

    memset(&flex_acl_rule, 0, sizeof(sx_flex_acl_flex_rule_t));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
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

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

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
    sai_acl_stage_t         acl_stage = SAI_ACL_STAGE_INGRESS;
    uint32_t                acl_entry_index, acl_table_index;
    uint8_t                 flex_action_index      = 0;
    bool                    is_action_type_present = false;
    sx_status_t             sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
        acl_stage = SAI_ACL_STAGE_INGRESS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
        acl_stage = SAI_ACL_STAGE_EGRESS;
        break;
    }

    /* Only 1 session ID is returned through getter */
    if (value->aclfield.data.objlist.count > 1) {
        value->aclfield.data.objlist.count = 1;
    }

    if (acl_db_table(acl_table_index).stage != acl_stage) {
        SX_LOG_ERR(" Invalid Attribute to Get : Action Mirror \n");
        status = SAI_STATUS_FAILURE;
        goto out_deinit;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule.action_count; flex_action_index++) {
        if (flex_acl_rule.action_list_p[flex_action_index].type == SX_FLEX_ACL_ACTION_MIRROR) {
            is_action_type_present = true;
            break;
        }
    }

    if (is_action_type_present) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_MIRROR,
                                    flex_acl_rule.action_list_p[flex_action_index].fields.action_mirror.session_id,
                                    NULL,
                                    &value->aclaction.parameter.objlist.list[0]);
        if (SAI_STATUS_SUCCESS != status) {
            goto out_deinit;
        }
    } else {
        SX_LOG_ERR(" Invalid Attribute to Get :  ACTION MIRROR \n");
        status = SAI_STATUS_NOT_SUPPORTED;
    }

out_deinit:
    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

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
    sx_flex_acl_flex_action_type_t action_type = 0;
    uint32_t                       acl_table_index, acl_entry_index;
    uint8_t                        flex_action_index      = 0;
    bool                           is_action_type_present = false;
    sx_status_t                    sx_status;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
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

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t fetch_flex_acl_rule_params_to_set(_In_ uint32_t                     acl_table_index,
                                                      _In_ uint32_t                     acl_entry_index,
                                                      _Inout_ sx_flex_acl_flex_rule_t **flex_acl_rule_p,
                                                      _Inout_ sx_acl_rule_offset_t    **offsets_list_p,
                                                      _Inout_ sx_acl_region_id_t       *region_id,
                                                      _Inout_ uint32_t                 *rules_num)
{
    sai_status_t      status;
    sx_status_t       sx_status;
    sx_acl_key_type_t key_type;
    uint32_t          flex_rules_num = 0;
    uint32_t          ii             = 0;

    key_type   = acl_db_table(acl_table_index).key_type;
    *region_id = acl_db_table(acl_table_index).region_id;
    *rules_num = acl_db_entry(acl_entry_index).num_rules;

    flex_rules_num = *rules_num;

    *flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * flex_rules_num);
    if (*flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(*flex_acl_rule_p, 0, sizeof(sx_flex_acl_flex_rule_t) * flex_rules_num);

    for (ii = 0; ii < flex_rules_num; ii++) {
        sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS, (*flex_acl_rule_p) + ii);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
            status         = sdk_to_sai(sx_status);
            flex_rules_num = ii;
            goto out;
        }
    }

    *offsets_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * flex_rules_num);
    if (*offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(*offsets_list_p, 0, sizeof(sx_acl_rule_offset_t) * flex_rules_num);

    status = acl_get_entries_offsets(acl_entry_index, flex_rules_num, *offsets_list_p);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    status = mlnx_acl_flex_rules_get_helper(key_type, *region_id, *offsets_list_p, *flex_acl_rule_p, flex_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    if (SAI_STATUS_SUCCESS != status) {
        if (*flex_acl_rule_p) {
            for (ii = 0; ii < flex_rules_num; ii++) {
                if (SX_STATUS_SUCCESS != (sx_status = sx_lib_flex_acl_rule_deinit(*flex_acl_rule_p + ii))) {
                    SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
                }
            }

            free(*flex_acl_rule_p);
            *flex_acl_rule_p = NULL;
        }

        free(*offsets_list_p);
        *offsets_list_p = NULL;
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_priority_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sx_status_t          sx_status;
    sai_status_t         status;
    sx_acl_region_id_t   region_id = 0;
    sx_acl_rule_offset_t new_rule_offset, old_rule_offset;
    uint32_t             entry_rules_num;
    uint32_t             acl_entry_index, acl_table_index;
    acl_entry_db_t      *entry_ptr;

    SX_LOG_ENTER();

    if ((value->u32 <= 0) || (value->u32 > ACL_MAX_ENTRY_PRIO)) {
        SX_LOG_ERR(" priority %u out of range (%u,%u)\n", value->u32, 1, ACL_MAX_ENTRY_PRIO);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    entry_rules_num = acl_db_entry(acl_entry_index).num_rules;
    region_id       = acl_db_table(acl_table_index).region_id;

    ACL_FOREACH_ENTRY(entry_ptr, acl_entry_index, entry_rules_num) {
        old_rule_offset = entry_ptr->offset;

        status = release_psort_offset(acl_table_index, entry_ptr->priority, old_rule_offset);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        status = get_new_psort_offset(acl_table_index, acl_entry_index, value->u32, &new_rule_offset, 1);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        entry_ptr->offset = new_rule_offset;

        sx_status = sx_api_acl_rule_block_move_set(gh_sdk, region_id, old_rule_offset, 1, new_rule_offset);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to move rule block\n");
            status = sdk_to_sai(sx_status);
            goto out;
        }

        entry_ptr->priority = value->u32;
    }

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_mac_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    uint32_t                   ii, flex_acl_rules_num = 0;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    sx_acl_key_t               key_id              = 0;
    bool                       is_key_type_present = false;
    uint32_t                   acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.smac, value->aclfield.data.mac,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.smac));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.smac, value->aclfield.mask.mac,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.smac));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SMAC;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC:
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dmac, value->aclfield.data.mac,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dmac));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dmac, value->aclfield.mask.mac,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dmac));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DMAC;
            break;
        }

        if (!is_key_type_present) {
            flex_acl_rule_p[ii].key_desc_count++;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_fields_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0;
    uint32_t                   index, ii, key_desc_index;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    bool                       is_key_type_present = false;
    sx_acl_key_t               ip_type_keys[IP_TYPE_KEY_SIZE];
    uint32_t                   acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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
                    mlnx_acl_flex_rule_key_del(&flex_acl_rule_p[ii], key_desc_index);
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

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_frag_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0;
    uint32_t                   ii, key_desc_index = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p  = NULL;
    sx_acl_key_t               ip_frag_key, ip_frag_not_first_key;
    bool                       is_ip_frag_key_present = false, is_ip_frag_not_first_key_present = false;
    uint32_t                   ip_frag_key_desc_index = 0, ip_frag_not_first_key_desc_index = 0;
    uint32_t                   acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    ip_frag_key           = FLEX_ACL_KEY_IP_FRAGMENTED;
    ip_frag_not_first_key = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == ip_frag_key) {
            is_ip_frag_key_present = true;
            ip_frag_key_desc_index = key_desc_index;
        }

        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == ip_frag_not_first_key) {
            is_ip_frag_not_first_key_present = true;
            ip_frag_not_first_key_desc_index = key_desc_index;
        }

        if (is_ip_frag_key_present && ip_frag_not_first_key_desc_index) {
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        /* Remove previous frag keys from the rule */
        if (is_ip_frag_key_present) {
            mlnx_acl_flex_rule_key_del(&flex_acl_rule_p[ii], ip_frag_key_desc_index);
        }

        if (is_ip_frag_not_first_key_present) {
            mlnx_acl_flex_rule_key_del(&flex_acl_rule_p[ii], ip_frag_not_first_key_desc_index);
        }

        key_desc_index = flex_acl_rule_p[0].key_desc_count;

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

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_vlan_tags_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0;
    uint32_t                   ii, key_desc_index = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p            = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p             = NULL;
    uint32_t                   vlan_tagged_key_desc_index = 0, inner_vlan_valid_key_desc_index;
    uint32_t                   acl_table_index, acl_entry_index;
    bool                       is_vlan_tagged = false, is_inner_vlan_valid = false;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_VLAN_TAGGED) {
            is_vlan_tagged             = true;
            vlan_tagged_key_desc_index = key_desc_index;
        }

        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_INNER_VLAN_VALID) {
            is_inner_vlan_valid             = true;
            inner_vlan_valid_key_desc_index = key_desc_index;
        }

        if (is_vlan_tagged && is_inner_vlan_valid) {
            break;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (is_vlan_tagged) {
            mlnx_acl_flex_rule_key_del(&flex_acl_rule_p[0], vlan_tagged_key_desc_index);
        }

        if (is_inner_vlan_valid) {
            mlnx_acl_flex_rule_key_del(&flex_acl_rule_p[0], inner_vlan_valid_key_desc_index);
        }

        if (SAI_PACKET_VLAN_UNTAG == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.vlan_tagged  = false;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.vlan_tagged = true;
            flex_acl_rule_p[ii].key_desc_count++;
        }

        if (SAI_PACKET_VLAN_SINGLE_OUTER_TAG == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.vlan_tagged  = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.vlan_tagged = true;
            key_desc_index++;

            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id                = FLEX_ACL_KEY_INNER_VLAN_VALID;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_vlan_valid  = false;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_vlan_valid = true;

            flex_acl_rule_p[ii].key_desc_count += 2;
        }

        if (SAI_PACKET_VLAN_DOUBLE_TAG == value->aclfield.data.s32) {
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.vlan_tagged  = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.vlan_tagged = true;
            key_desc_index++;

            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id                = FLEX_ACL_KEY_INNER_VLAN_VALID;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_vlan_valid  = true;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_vlan_valid = true;

            flex_acl_rule_p[ii].key_desc_count += 2;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    uint32_t                   ii, flex_acl_rules_num = 1;
    uint8_t                    key_desc_index  = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p  = NULL;
    sx_acl_key_t               key_id          = 0;
    sx_ip_addr_t               ipaddr_data, ipaddr_mask;
    sai_ip_address_t           ip_address_data, ip_address_mask;
    bool                       is_key_type_present = false;
    uint32_t                   acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6 == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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

    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
        key_id = FLEX_ACL_KEY_SIPV6;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
        key_id = FLEX_ACL_KEY_DIPV6;
        break;
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
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip, &ipaddr_data,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.sip, &ipaddr_mask,
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
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip, &ipaddr_data,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dip, &ipaddr_mask,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dip));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIP;
            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6:
            ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_data.addr.ip6, &value->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
            ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_mask.addr.ip6, &value->aclfield.mask.ip6, sizeof(ip_address_mask.addr.ip6));

            status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sipv6, &ipaddr_data,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sipv6));

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.sipv6, &ipaddr_mask,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.sipv6));

            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIPV6;

            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6:
            ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_data.addr.ip6, &value->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
            ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(&ip_address_mask.addr.ip6, &value->aclfield.mask.ip6, sizeof(ip_address_mask.addr.ip6));

            status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dipv6, &ipaddr_data,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dipv6));
            memcpy(&flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dipv6, &ipaddr_mask,
                   sizeof(flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dipv6));
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIPV6;

            if (!is_key_type_present) {
                flex_acl_rule_p[ii].key_desc_count++;
            }
            break;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_vlan_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id           = 0;
    uint32_t                   flex_acl_rules_num  = 0, ii;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    sx_acl_key_t               key_id              = 0;
    bool                       is_key_type_present = false;
    uint32_t                   acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
        key_id = FLEX_ACL_KEY_VLAN_ID;
        break;
/*
 *   case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
 *       key_id = FLEX_ACL_KEY_INNER_VLAN_ID;
 *       break;*/

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_INNER_PCP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_INNER_DEI;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI:
        key_id = FLEX_ACL_KEY_PCP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI:
        key_id = FLEX_ACL_KEY_DEI;
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
        case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.vlan_id  = value->aclfield.data.u16 & 0x0fff;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.vlan_id = value->aclfield.mask.u16 & 0x0fff;
            break;
/*
 *       case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
 *           flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_vlan_id  = value->aclfield.data.u16 & 0x0fff;
 *           flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_vlan_id = value->aclfield.mask.u16 & 0x0fff;
 *           break;*/

        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_pcp  = value->aclfield.data.u8 & 0x07;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_pcp = value->aclfield.mask.u8 & 0x07;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.inner_dei  = value->aclfield.data.u8 & 0x01;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.inner_dei = value->aclfield.mask.u8 & 0x01;
            break;

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

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ports_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    sx_flex_acl_rule_offset_t  first_rule_offset;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p  = NULL;
    sx_acl_key_t               key_id          = 0;
    sx_acl_key_type_t          key_type;
    sx_port_log_id_t           port_log_id;
    acl_entry_db_t            *db_entry_ptr;
    uint32_t                   acl_table_index, first_entry_index, entry_index, delete_entry_index, new_entry_index;
    uint32_t                   rule_num, old_rule_num, new_rule_num;
    uint32_t                   new_port_num;
    uint8_t                    key_desc_index      = 0;
    bool                       is_key_type_present = false;
    uint32_t                   create_entries_count;
    uint32_t                   entry_prio;
    uint32_t                   ii;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &first_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    old_rule_num      = acl_db_entry(first_entry_index).num_rules;
    first_rule_offset = acl_db_entry(first_entry_index).offset;
    entry_prio        = acl_db_entry(first_entry_index).priority;
    region_id         = acl_db_table(acl_table_index).region_id;
    key_type          = acl_db_table(acl_table_index).key_type;

    if (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg) {
        if (acl_db_table(acl_table_index).stage != SAI_ACL_STAGE_EGRESS) {
            SX_LOG_ERR("Port type(OUT PORT) and stage do not match\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }
    }

    if (true == value->aclfield.enable) {
        new_port_num = value->aclfield.data.objlist.count;
        new_rule_num = (new_port_num == 0) ? 1 : new_port_num;
    } else {
        new_port_num = 0;
        new_rule_num = 1;
    }

    offsets_list_p = (sx_flex_acl_rule_offset_t*)malloc(new_rule_num * sizeof(sx_flex_acl_rule_offset_t));
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for offsets list\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(new_rule_num * sizeof(sx_flex_acl_flex_rule_t));
    if (flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (ii = 0; ii < new_rule_num; ii++) {
        sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[ii]);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
            status       = sdk_to_sai(sx_status);
            new_rule_num = ii;
            goto out;
        }
    }

    status = mlnx_acl_flex_rules_get_helper(key_type, region_id, &first_rule_offset, &flex_acl_rule_p[0], 1);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) {
        key_id = FLEX_ACL_KEY_SRC_PORT;
    } else {
        key_id = FLEX_ACL_KEY_DST_PORT;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == key_id) {
            is_key_type_present = true;
            break;
        }
    }

    if ((0 == new_port_num) || (false == value->aclfield.enable)) {
        if (false == is_key_type_present) {
            goto out;
        }

        mlnx_acl_flex_rule_key_del(&flex_acl_rule_p[0], key_desc_index);
    } else {
        if (false == is_key_type_present) {
            flex_acl_rule_p[0].key_desc_count++;
        }

        for (ii = 1; ii < new_rule_num; ii++) {
            mlnx_acl_flex_rule_copy(&flex_acl_rule_p[ii], &flex_acl_rule_p[0]);
        }

        for (ii = 0; ii < new_port_num; ii++) {
            status = mlnx_object_to_type(value->aclfield.data.objlist.list[ii], SAI_OBJECT_TYPE_PORT,
                                         &port_log_id, NULL);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            if (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) {
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.src_port  = port_log_id;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_SRC_PORT;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.src_port = true;
            } else {
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.dst_port  = port_log_id;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key_id        = FLEX_ACL_KEY_DST_PORT;
                flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.dst_port = true;
            }
        }
    }

    ii          = 0;
    entry_index = first_entry_index;
    rule_num    = MIN(new_rule_num, old_rule_num);

    ACL_FOREACH_ENTRY(db_entry_ptr, entry_index, rule_num) {
        offsets_list_p[ii] = db_entry_ptr->offset;
        ii++;
    }

    status =
        mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, key_type, region_id, offsets_list_p, flex_acl_rule_p, ii);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (ii < new_rule_num) {
        create_entries_count = new_rule_num - old_rule_num;
        status               = acl_db_insert_entries(acl_table_index, entry_index, create_entries_count);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        new_entry_index = acl_db_entry(entry_index).next;
        ACL_FOREACH_ENTRY(db_entry_ptr, new_entry_index, create_entries_count) {
            status = get_new_psort_offset(acl_table_index,
                                          new_entry_index,
                                          entry_prio,
                                          &offsets_list_p[ii],
                                          new_rule_num - ii);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            db_entry_ptr->offset   = offsets_list_p[ii];
            db_entry_ptr->priority = acl_db_entry(first_entry_index).priority;

            status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, key_type, region_id, &offsets_list_p[ii],
                                                    &flex_acl_rule_p[ii], 1);
            if (SX_STATUS_SUCCESS != status) {
                goto out;
            }

            ii++;
        }
    } else if (ii < old_rule_num) {
        /* delete starting from next entry */
        delete_entry_index = acl_db_entry(entry_index).next;

        status = mlnx_delete_acl_entry_data(acl_table_index, delete_entry_index, old_rule_num - new_rule_num);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }
    }

    acl_db_entry(first_entry_index).num_rules = new_rule_num;

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < new_rule_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_port_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0, ii;
    uint32_t                   port_data;
    uint32_t                   key_id = 0;
    uint32_t                   acl_entry_index, acl_table_index;
    uint32_t                   acl_delete_entry_index;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    bool                       is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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

    for (key_desc_index = 0; key_desc_index < flex_acl_rule_p[0].key_desc_count; key_desc_index++) {
        if (flex_acl_rule_p[0].key_desc_list_p[key_desc_index].key_id == key_id) {
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
            status = mlnx_object_to_type(value->aclfield.data.oid, SAI_OBJECT_TYPE_PORT, &port_data, NULL);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.src_port  = port_data;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.src_port = true;
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
            if (acl_db_table(acl_table_index).stage != SAI_ACL_STAGE_EGRESS) {
                SX_LOG_ERR("Port type(OUT PORT) and stage do not match\n");
                status = SAI_STATUS_NOT_SUPPORTED;
                goto out;
            }

            status = mlnx_object_to_type(value->aclfield.data.oid, SAI_OBJECT_TYPE_PORT, &port_data, NULL);
            if (SAI_STATUS_SUCCESS != status) {
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

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

    /* Delete Rules during in-port/out-por set, except the rule at the start offset, if prev number of rules > 1 */
    if (((int64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT) || ((int64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT)) {
        if (flex_acl_rules_num > 1) {
            acl_delete_entry_index = acl_db_entry(acl_entry_index).next;
            status                 = mlnx_delete_acl_entry_data(acl_table_index,
                                                                acl_delete_entry_index,
                                                                flex_acl_rules_num - 1);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }

        /* Update New Rule Count in DB */
        acl_db_entry(acl_entry_index).num_rules = 1;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_fields_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id           = 0;
    uint32_t                   flex_acl_rules_num  = 0, ii;
    uint8_t                    key_desc_index      = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p     = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p      = NULL;
    sx_acl_key_t               key_id              = 0;
    bool                       is_key_type_present = false;
    uint32_t                   acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ADMIN_STATE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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

    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
        key_id = FLEX_ACL_KEY_USER_TOKEN;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS:
        key_id = FLEX_ACL_KEY_TCP_CONTROL;
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

        case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].key.user_token  = value->aclfield.data.u32;
            flex_acl_rule_p[ii].key_desc_list_p[key_desc_index].mask.user_token = value->aclfield.mask.u32;
            break;

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

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_tos_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p    = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p     = NULL;
    uint32_t                   flex_acl_rules_num = 0;
    uint32_t                   key_desc_index, ii;
    bool                       is_key_type_present = false;
    uint32_t                   acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TOS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }
        free(flex_acl_rule_p);
    }
    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_packet_action_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sx_status_t                    sx_status;
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
    uint32_t                       acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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

        if (is_forward_action_present && is_trap_action_present) {
            break;
        }
    }

    packet_action_type = value->aclaction.parameter.s32;

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (is_forward_action_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule_p[ii], forward_action_index);
        }

        if (is_trap_action_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule_p[ii], trap_action_index);
        }

        flex_action_index = flex_acl_rule_p[ii].action_count;

        if (value->aclaction.enable == true) {
            status = mlnx_acl_packet_actions_handler(packet_action_type, trap_id, &flex_acl_rule_p[ii],
                                                     &flex_action_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            flex_acl_rule_p[ii].action_count = flex_action_index;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sx_status_t                    sx_status;
    sai_status_t                   status;
    sx_acl_region_id_t             region_id          = 0;
    uint32_t                       flex_acl_rules_num = 0;
    uint32_t                       port_counter       = 0, ii;
    uint32_t                       action_set_policer_id_data;
    uint8_t                        flex_action_index = 0;
    sx_acl_pbs_id_t                pbs_id;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_port_log_id_t              *port_arr               = NULL;
    bool                           is_action_type_present = false;
    sx_flex_acl_flex_action_type_t action_type            = 0;
    uint32_t                       acl_table_index, acl_entry_index;
    pbs_index_t                    pbs_index        = ACL_INVALID_PBS_INDEX, old_pbs_index = ACL_INVALID_PBS_INDEX;
    uint32_t                       pbs_ports_number = 0;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_FLOOD == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_COLOR == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        action_type = SX_FLEX_ACL_ACTION_PBS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
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

    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[0].action_count; flex_action_index++) {
        if (flex_acl_rule_p[0].action_list_p[flex_action_index].type == action_type) {
            is_action_type_present = true;
            break;
        }
    }
    /* Retrieve old PBS Id and create new PBS Entry */

    if (((int64_t)arg == SAI_ACL_ENTRY_ATTR_ACTION_FLOOD) ||
        ((int64_t)arg == SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT) ||
        ((int64_t)arg == SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST)) {
        port_arr = (sx_port_log_id_t*)malloc(g_sai_db_ptr->ports_number * sizeof(sx_port_log_id_t));
        if (port_arr == NULL) {
            SX_LOG_ERR("ERROR: unable to allocate memory for port_arr\n");
            status = SAI_STATUS_NO_MEMORY;
            goto out;
        }

        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
            pbs_ports_number = g_sai_db_ptr->ports_number;
            for (port_counter = 0; port_counter < pbs_ports_number; port_counter++) {
                port_arr[port_counter] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[port_counter].logical;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
            pbs_ports_number = 1;
            status           = mlnx_object_to_type(value->aclaction.parameter.oid,
                                                   SAI_OBJECT_TYPE_PORT,
                                                   &port_arr[0],
                                                   NULL);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
            pbs_ports_number = value->aclaction.parameter.objlist.count;
            for (port_counter = 0; port_counter < pbs_ports_number; port_counter++) {
                status = mlnx_object_to_type(value->aclaction.parameter.objlist.list[port_counter],
                                             SAI_OBJECT_TYPE_PORT,
                                             &port_arr[port_counter],
                                             NULL);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }
            }
            break;
        }

        /* Store the PBS IDs to delete OLD PBS entries after the ACL Entry is Set */
        if (is_action_type_present) {
            old_pbs_index = acl_db_entry(acl_entry_index).pbs_index;
        }

        if (value->aclaction.enable == true) {
            status = mlnx_acl_pbs_entry_create_or_get(port_arr, pbs_ports_number, &pbs_id, &pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            acl_db_entry(acl_entry_index).pbs_index = pbs_index;
        }
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
            if (value->aclaction.enable == true) {
                flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_id;
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
            if (value->aclaction.enable == true) {
                status = mlnx_object_to_type(value->aclaction.parameter.oid, SAI_OBJECT_TYPE_POLICER,
                                             &action_set_policer_id_data, NULL);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }

                /* cl_plock_acquire(&g_sai_db_ptr->p_lock); */
                status = mlnx_sai_get_or_create_regular_sx_policer_for_bind(
                    value->aclaction.parameter.oid,
                    false,
                    &flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.
                    action_policer.policer_id);
                if (SAI_STATUS_SUCCESS != status) {
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
                    flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_user_token.mask = 0xFFFF;
                    flex_acl_rule_p[ii].action_list_p[flex_action_index].type                              =
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
                mlnx_acl_flex_rule_action_del(&flex_acl_rule_p[ii], flex_action_index);
            }
        } else {
            if (!is_action_type_present) {
                flex_acl_rule_p[ii].action_count++;
            }
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

    if (is_pbs_index_valid(old_pbs_index)) {
        status = mlnx_acl_pbs_entry_delete(old_pbs_index);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);
    free(port_arr);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mirror_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0, ii;
    sai_acl_stage_t            acl_stage          = SAI_ACL_STAGE_INGRESS;
    uint32_t                   acl_table_index, acl_entry_index;
    uint8_t                    flex_action_index = 0;
    uint32_t                   session_id;
    sx_flex_acl_rule_offset_t *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p        = NULL;
    bool                       is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
        acl_stage = SAI_ACL_STAGE_INGRESS;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
        acl_stage = SAI_ACL_STAGE_EGRESS;
        break;
    }

    if (acl_db_table(acl_table_index).stage != acl_stage) {
        SX_LOG_ERR(" Invalid Attribute to Get : Action Mirror  \n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[0].action_count; flex_action_index++) {
        if (flex_acl_rule_p[0].action_list_p[flex_action_index].type == SX_FLEX_ACL_ACTION_MIRROR) {
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

            status = mlnx_object_to_type(value->aclaction.parameter.objlist.list[0], SAI_OBJECT_TYPE_MIRROR,
                                         &session_id, NULL);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_mirror.session_id = session_id;
            flex_acl_rule_p[ii].action_list_p[flex_action_index].type                            =
                SX_FLEX_ACL_ACTION_MIRROR;
        } else {
            if (is_action_type_present) {
                mlnx_acl_flex_rule_action_del(&flex_acl_rule_p[ii], flex_action_index);
            }
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mac_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    sx_status_t                    sx_status;
    sai_status_t                   status;
    sx_acl_region_id_t             region_id          = 0;
    uint32_t                       flex_acl_rules_num = 0, ii;
    uint8_t                        flex_action_index;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_flex_action_type_t action_type            = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
    bool                           is_action_type_present = false;
    uint32_t                       acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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

    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[0].action_count; flex_action_index++) {
        if (flex_acl_rule_p[0].action_list_p[flex_action_index].type == action_type) {
            is_action_type_present = true;
            break;
        }
    }
    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC:
            if (value->aclaction.enable == true) {
                memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_src_mac.mac,
                       value->aclaction.parameter.mac,
                       sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_src_mac.mac));
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
            }
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC:
            if (value->aclaction.enable == true) {
                memcpy(&flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_dst_mac.mac,
                       value->aclaction.parameter.mac,
                       sizeof(flex_acl_rule_p[ii].action_list_p[flex_action_index].fields.action_set_dst_mac.mac));
                flex_acl_rule_p[ii].action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_DST_MAC;
            }
            break;
        }

        if (value->aclaction.enable == false) {
            if (is_action_type_present) {
                mlnx_acl_flex_rule_action_del(&flex_acl_rule_p[ii], flex_action_index);
            }
        } else {
            if (!is_action_type_present) {
                flex_acl_rule_p[ii].action_count++;
            }
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    if (offsets_list_p) {
        free(offsets_list_p);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_vlan_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg)
{
    sx_status_t                    sx_status;
    sai_status_t                   status;
    sx_acl_region_id_t             region_id              = 0;
    uint32_t                       flex_acl_rules_num     = 0, ii;
    uint8_t                        flex_action_index      = 0;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_flex_action_type_t action_type            = 0;
    bool                           is_action_type_present = false;
    uint32_t                       acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
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
    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[0].action_count; flex_action_index++) {
        if (flex_acl_rule_p[0].action_list_p[flex_action_index].type == action_type) {
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
                mlnx_acl_flex_rule_action_del(&flex_acl_rule_p[ii], flex_action_index);
            }
        } else {
            if (!is_action_type_present) {
                flex_acl_rule_p[ii].action_count++;
            }
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_counter_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg)
{
    sx_status_t              sx_status;
    sai_status_t             status;
    sx_acl_region_id_t       region_id;
    sx_acl_rule_offset_t    *offsets_list_p  = NULL;
    sx_flex_acl_flex_rule_t *flex_acl_rule_p = NULL;
    uint32_t                 flex_acl_rules_num;
    uint32_t                 acl_table_index, acl_entry_index;
    uint32_t                 rule_counter;
    uint8_t                  flex_action_index      = 0;
    bool                     is_action_type_present = false;
    uint32_t                 counter_index;
    uint32_t                 ii = 0;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule_p[0].action_count; flex_action_index++) {
        if (flex_acl_rule_p[0].action_list_p[flex_action_index].type == SX_FLEX_ACL_ACTION_COUNTER) {
            is_action_type_present = true;
            break;
        }
    }

    if (value->aclaction.enable == false) {
        if (is_action_type_present) {
            for (rule_counter = 0; rule_counter < flex_acl_rules_num; rule_counter++) {
                mlnx_acl_flex_rule_action_del(&flex_acl_rule_p[rule_counter], flex_action_index);
            }

            acl_db_entry(acl_entry_index).counter_id = ACL_INVALID_DB_INDEX;
        }
    } else {
        status = extract_acl_counter_index(value->aclaction.parameter.oid, &counter_index);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        for (rule_counter = 0; rule_counter < flex_acl_rules_num; rule_counter++) {
            flex_acl_rule_p[rule_counter].action_list_p[flex_action_index].fields.action_counter.counter_id =
                sai_acl_db->acl_counter_db[counter_index].counter_id;
            flex_acl_rule_p[rule_counter].action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_COUNTER;
            if (!is_action_type_present) {
                flex_acl_rule_p[rule_counter].action_count++;
            }
        }

        acl_db_entry(acl_entry_index).counter_id = counter_index;
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_acl_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
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

sai_status_t mlnx_create_acl_entry(_Out_ sai_object_id_t     * acl_entry_id,
                                   _In_ uint32_t               attr_count,
                                   _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    sx_flex_acl_flex_rule_t      flex_acl_rule;
    sx_flex_acl_flex_rule_t     *flex_acl_rule_p = NULL;
    sx_acl_pbs_id_t              pbs_id          = 0;
    sx_port_log_id_t            *port_arr        = NULL;
    sx_acl_region_id_t           region_id;
    sx_acl_rule_offset_t        *offsets_list_p = NULL;
    sx_acl_key_t                 port_key_id    = 0;
    sx_ip_addr_t                 ipaddr_data, ipaddr_mask;
    sai_acl_stage_t              stage;
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
    const sai_attribute_value_t *action_set_policer, *action_set_tc, *action_redirect,
    *action_redirect_list;
    const sai_attribute_value_t                      *action_set_inner_vlan_id, *action_set_inner_vlan_pri;
    const sai_attribute_value_t                      *action_set_outer_vlan_id, *action_set_outer_vlan_pri;
    const sai_attribute_value_t                      *action_flood;
    const sai_attribute_value_t                      *admin_state;
    const sai_attribute_value_t                      *src_ipv6, *dst_ipv6;
    const sai_attribute_value_t /* *inner_vlan_id,*/ *inner_vlan_pri, *inner_vlan_cfi;
    const sai_attribute_value_t                      *user_meta, *vlan_tags;
    uint32_t /*inner_vlan_id_index,*/                 inner_vlan_pri_index, inner_vlan_cfi_index;
    uint32_t                                          src_ipv6_index, dst_ipv6_index;
    uint32_t                                          user_meta_index, vlan_tags_index;
    uint32_t                                          table_id_index, priority_index;
    uint32_t                                          src_mac_index, dst_mac_index, src_ip_index, dst_ip_index;
    uint32_t                                          in_port_index, admin_state_index, in_ports_index;
    uint32_t                                          out_port_index, out_ports_index;
    uint32_t                                          outer_vlan_id_index, outer_vlan_pri_index, outer_vlan_cfi_index;
    uint32_t                                          L4_src_port_index, L4_dst_port_index;
    uint32_t                                          ether_type_index, ip_protocol_index;
    uint32_t                                          ip_tos_index, dscp_index, ecn_index;
    uint32_t                                          ip_type_index, ip_frag_index;
    uint32_t                                          ip_flags_index, tcp_flags_index;
    uint32_t                                          tc_index, ttl_index;
    uint32_t                                          action_set_src_mac_index, action_set_dst_mac_index;
    uint32_t                                          action_set_dscp_index;
    uint32_t                                          packet_action_index, action_counter_index, action_redirect_index,
                                                      action_redirect_list_index;
    uint32_t action_set_policer_index, action_set_tc_index;
    uint32_t action_mirror_ingress_index, action_mirror_egress_index,
             egress_session_id, ingress_session_id;
    uint32_t action_set_color_index, action_set_ecn_index;
    uint32_t action_set_user_token_index, action_dec_ttl_index;
    uint32_t action_set_inner_vlan_id_index, action_set_inner_vlan_pri_index;
    uint32_t action_set_outer_vlan_id_index, action_set_outer_vlan_pri_index;
    uint32_t action_flood_index, port_key_index = 0;
    uint32_t in_port_data, out_port_data, action_set_policer_data,
             action_redirect_port;
    uint32_t port, ports_count = 0, port_counter = 0;
    uint32_t acl_table_index, acl_entry_index, counter_index =
        ACL_INVALID_DB_INDEX;
    uint32_t    num_rules         = 0, set_flex_rules_num = 0;
    uint32_t    flex_rules_num    = 0, db_indexes_num = 0, psort_offsets_num = 0;
    uint32_t    key_desc_index    = 0; /* acl_table_size = 0; */
    uint16_t    trap_id           = SX_TRAP_ID_ACL_MIN;
    uint8_t     flex_action_index = 0;
    char        list_str[MAX_LIST_VALUE_STR_LEN];
    char        key_str[MAX_KEY_STR_LEN];
    bool        is_ipv6_present            = false;
    bool        tos_attrib_present         = false; /* Value is TRUE when TOS FIELD received from user */
    bool        is_redirect_action_present = false;
    uint32_t    ii                         = 0;
    uint32_t    table_size, created_entry_count;
    bool        is_table_dynamic_sized;
    uint32_t    entry_priority;
    uint32_t    pbs_ports_number = 0;
    pbs_index_t pbs_index        = ACL_INVALID_PBS_INDEX;

    SX_LOG_ENTER();

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

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_TABLE_ID, &table_id, &table_id_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = extract_acl_table_index(table_id->oid, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);
    acl_global_lock();

    stage                  = acl_db_table(acl_table_index).stage;
    region_id              = acl_db_table(acl_table_index).region_id;
    table_size             = acl_db_table(acl_table_index).table_size;
    created_entry_count    = acl_db_table(acl_table_index).created_entry_count;
    is_table_dynamic_sized = acl_db_table(acl_table_index).is_dynamic_sized;

    if ((created_entry_count == table_size) &&
        (false == is_table_dynamic_sized)) {
        SX_LOG_ERR("Table is full\n");
        status = SAI_STATUS_TABLE_FULL;
        goto out;
    }

    status = sx_lib_flex_acl_rule_init(acl_db_table(acl_table_index).key_type,
                                       ACL_MAX_NUM_OF_ACTIONS, &flex_acl_rule);
    if (SX_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failure to create Entry - %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_PRIORITY, &priority, &priority_index))) {
        if ((priority->u32 < ACL_MIN_ENTRY_PRIO) || (ACL_MAX_ENTRY_PRIO < priority->u32)) {
            SX_LOG_ERR(" priority %u out of range (%u,%u)\n", priority->u32, ACL_MIN_ENTRY_PRIO, ACL_MAX_ENTRY_PRIO);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + priority_index;
            goto out;
        }

        entry_priority = priority->u32;
    } else {
        entry_priority = ACL_DEFAULT_ENTRY_PRIO;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ADMIN_STATE, &admin_state,
                                 &admin_state_index))) {
        flex_acl_rule.valid = admin_state->booldata;
    } else {  /* set default enabled */
        flex_acl_rule.valid = true;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPv6, &src_ipv6, &src_ipv6_index)) {
        is_ipv6_present = true;

        ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_data.addr.ip6, &src_ipv6->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
        ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_mask.addr.ip6, &src_ipv6->aclfield.mask.ip6, sizeof(ip_address_mask.addr.ip6));

        status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.sipv6, &ipaddr_data,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sipv6));

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sipv6, &ipaddr_mask,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.sipv6));

        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_SIPV6;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_DST_IPv6, &dst_ipv6, &dst_ipv6_index)) {
        is_ipv6_present = true;

        ip_address_data.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_data.addr.ip6, &dst_ipv6->aclfield.data.ip6, sizeof(ip_address_data.addr.ip6));
        ip_address_mask.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&ip_address_mask.addr.ip6, &dst_ipv6->aclfield.mask.ip6, sizeof(ip_address_mask.addr.ip6));

        status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_data, &ipaddr_data);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        status = mlnx_translate_sai_ip_address_to_sdk(&ip_address_mask, &ipaddr_mask);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].key.dipv6, &ipaddr_data,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dipv6));
        memcpy(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dipv6, &ipaddr_mask,
               sizeof(flex_acl_rule.key_desc_list_p[key_desc_index].key.dipv6));

        flex_acl_rule.key_desc_list_p[key_desc_index].key_id = FLEX_ACL_KEY_DIPV6;
        key_desc_index++;
    }

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
/*
 *   if (SAI_STATUS_SUCCESS ==
 *       find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID, &inner_vlan_id,
 *                           &inner_vlan_id_index)) {
 *       flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_vlan_id  = (inner_vlan_id->aclfield.data.u16) & 0xFFF;
 *       flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_vlan_id = (inner_vlan_id->aclfield.mask.u16) & 0xFFF;
 *       flex_acl_rule.key_desc_list_p[key_desc_index].key_id             = FLEX_ACL_KEY_VLAN_ID;
 *       key_desc_index++;
 *   }*/

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI, &inner_vlan_pri,
                            &inner_vlan_pri_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_pcp  = (inner_vlan_pri->aclfield.data.u8) & 0x07;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_pcp = (inner_vlan_pri->aclfield.mask.u8) & 0x07;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id         = FLEX_ACL_KEY_INNER_PCP;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI, &inner_vlan_cfi,
                            &inner_vlan_cfi_index)) {
        flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_dei  = (inner_vlan_cfi->aclfield.data.u8) & 0x01;
        flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_dei = (inner_vlan_cfi->aclfield.mask.u8) & 0x01;
        flex_acl_rule.key_desc_list_p[key_desc_index].key_id         = FLEX_ACL_KEY_INNER_DEI;
        key_desc_index++;
    }

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

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META, &user_meta,
                            &user_meta_index)) {
        if (((user_meta->aclfield.data.u32 >> 0x10) == 0) && ((user_meta->aclfield.mask.u32 >> 0x10) == 0)) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key.user_token  = (uint16_t)user_meta->aclfield.data.u32;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.user_token = (uint16_t)user_meta->aclfield.mask.u32;
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id          = FLEX_ACL_KEY_USER_TOKEN;
            key_desc_index++;
        } else {
            SX_LOG_ERR(" ACL user Meta values %u %u is out of range [%d, %d]\n",
                       user_meta->aclfield.data.u32, user_meta->aclfield.mask.u32,
                       ACL_USER_META_RANGE_MIN, ACL_USER_META_RANGE_MAX);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + user_meta_index;
            goto out;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_VLAN_TAGS, &vlan_tags, &vlan_tags_index)) {
        if (SAI_PACKET_VLAN_UNTAG == vlan_tags->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
            flex_acl_rule.key_desc_list_p[key_desc_index].key.vlan_tagged  = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.vlan_tagged = true;
            key_desc_index++;
        }

        if (SAI_PACKET_VLAN_SINGLE_OUTER_TAG == vlan_tags->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
            flex_acl_rule.key_desc_list_p[key_desc_index].key.vlan_tagged  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.vlan_tagged = true;
            key_desc_index++;

            flex_acl_rule.key_desc_list_p[key_desc_index].key_id                = FLEX_ACL_KEY_INNER_VLAN_VALID;
            flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_vlan_valid  = false;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_vlan_valid = true;
            key_desc_index++;
        }

        if (SAI_PACKET_VLAN_DOUBLE_TAG == vlan_tags->aclfield.data.s32) {
            flex_acl_rule.key_desc_list_p[key_desc_index].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
            flex_acl_rule.key_desc_list_p[key_desc_index].key.vlan_tagged  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.vlan_tagged = true;
            key_desc_index++;

            flex_acl_rule.key_desc_list_p[key_desc_index].key_id                = FLEX_ACL_KEY_INNER_VLAN_VALID;
            flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_vlan_valid  = true;
            flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_vlan_valid = true;
            key_desc_index++;
        }
    }

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
                                         &action_redirect_port,
                                         NULL))) {
                goto out;
            }

            status = mlnx_acl_pbs_entry_create_or_get(&action_redirect_port, 1, &pbs_id, &pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            is_redirect_action_present                                              = true;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_id;
            flex_acl_rule.action_list_p[flex_action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST, &action_redirect_list,
                            &action_redirect_list_index)) {
        if (action_redirect_list->aclaction.enable == true) {
            if (is_redirect_action_present == true) {
                SX_LOG_ERR(" Redirect Action is already present as an ACL Entry Attribute \n");
                status = SAI_STATUS_INVALID_ATTR_VALUE_0 + action_redirect_list_index;
                goto out;
            }

            pbs_ports_number = action_redirect_list->aclaction.parameter.objlist.count;
            port_arr         = (sx_port_log_id_t*)malloc(pbs_ports_number * sizeof(sx_port_log_id_t));
            if (port_arr == NULL) {
                SX_LOG_ERR(" Unable to allocate memory for port array\n");
                status = SAI_STATUS_NO_MEMORY;
                goto out;
            }

            for (ii = 0; ii < pbs_ports_number; ii++) {
                if (SAI_STATUS_SUCCESS !=
                    (status =
                         mlnx_object_to_type(action_redirect_list->aclaction.parameter.objlist.list[ii],
                                             SAI_OBJECT_TYPE_PORT,
                                             &port_arr[ii],
                                             NULL))) {
                    goto out;
                }
            }

            status = mlnx_acl_pbs_entry_create_or_get(port_arr, pbs_ports_number, &pbs_id, &pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            is_redirect_action_present                                              = true;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_id;
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

            port_arr = (sx_port_log_id_t*)malloc(g_sai_db_ptr->ports_number * sizeof(sx_port_log_id_t));
            if (port_arr == NULL) {
                SX_LOG_ERR(" Unable to allocate memory for port array\n");
                status = SAI_STATUS_NO_MEMORY;
                goto out;
            }

            for (port_counter = 0; port_counter < g_sai_db_ptr->ports_number; port_counter++) {
                port_arr[port_counter] = g_sai_db_ptr->ports_db[port_counter].logical;
            }

            status = mlnx_acl_pbs_entry_create_or_get(port_arr, g_sai_db_ptr->ports_number, &pbs_id, &pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            flex_acl_rule.action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_id;
            flex_acl_rule.action_list_p[flex_action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_COUNTER, &action_counter,
                            &action_counter_index)) {
        if (action_counter->aclaction.enable == true) {
            status = extract_acl_counter_index(action_counter->aclaction.parameter.oid, &counter_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
            flex_acl_rule.action_list_p[flex_action_index].fields.action_counter.counter_id =
                sai_acl_db->acl_counter_db[counter_index].counter_id;
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_COUNTER;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, &action_mirror_ingress,
                            &action_mirror_ingress_index)) {
        if (stage != SAI_ACL_STAGE_INGRESS) {
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
        if (stage != SAI_ACL_STAGE_EGRESS) {
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
                                           false,
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
            memcpy(&flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac,
                   action_set_src_mac->aclaction.parameter.mac,
                   sizeof(flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac));
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC, &action_set_dst_mac,
                            &action_set_dst_mac_index)) {
        if (action_set_dst_mac->aclaction.enable == true) {
            memcpy(&flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dst_mac.mac,
                   action_set_dst_mac->aclaction.parameter.mac,
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
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_user_token.mask = 0xFFFF;
                flex_acl_rule.action_list_p[flex_action_index].type                              =
                    SX_FLEX_ACL_ACTION_SET_USER_TOKEN;
                flex_action_index++;
            }
        } else {
            SX_LOG_ERR(" ACL user Meta value %u is out of range [%d, %d] \n",
                       action_set_user_token->aclaction.parameter.u32,
                       ACL_USER_META_RANGE_MIN, ACL_USER_META_RANGE_MAX);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + action_set_user_token_index;
            goto out;
        }
    }

    flex_acl_rule.key_desc_count = key_desc_index;
    flex_acl_rule.action_count   = flex_action_index;

    num_rules = (ports_count > 0) ? ports->aclfield.data.objlist.count : 1;

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
    port_counter = 0;
    for (ii = 0; ii < num_rules; ii++) {
        sx_status = sx_lib_flex_acl_rule_init(acl_db_table(acl_table_index).key_type,
                                              ACL_MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[ii]);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
            goto out;
        }

        flex_rules_num = ii + 1;

        status = acl_db_find_entry_free_index(&acl_entry_index);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        acl_db_add_entry_to_table(acl_table_index, acl_entry_index);

        db_indexes_num = ii + 1;

        status = get_new_psort_offset(acl_table_index, acl_entry_index, entry_priority,
                                      &offsets_list_p[ii], num_rules - ii);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to get offset form pSort\n");
            goto out;
        }

        psort_offsets_num = ii + 1;

        mlnx_acl_flex_rule_copy(&flex_acl_rule_p[ii], &flex_acl_rule);

        if (ports_count > 0) {
            status = mlnx_object_to_type(ports->aclfield.data.objlist.list[port_counter],
                                         SAI_OBJECT_TYPE_PORT, &port, NULL);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            if (port_key_id == FLEX_ACL_KEY_SRC_PORT) {
                flex_acl_rule_p[ii].key_desc_list_p[port_key_index].key.src_port  = port;
                flex_acl_rule_p[ii].key_desc_list_p[port_key_index].mask.src_port = true;
            } else {
                flex_acl_rule_p[ii].key_desc_list_p[port_key_index].key.dst_port  = port;
                flex_acl_rule_p[ii].key_desc_list_p[port_key_index].mask.dst_port = true;
            }

            port_counter++;
        }

        acl_db_entry(acl_entry_index).priority   = entry_priority;
        acl_db_entry(acl_entry_index).offset     = offsets_list_p[ii];
        acl_db_entry(acl_entry_index).num_rules  = num_rules;
        acl_db_entry(acl_entry_index).counter_id = counter_index;
        acl_db_entry(acl_entry_index).pbs_index  = pbs_index;

        status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id,
                                                &offsets_list_p[ii], &flex_acl_rule_p[ii], 1);
        if (SX_STATUS_SUCCESS != status) {
            goto out;
        }

        set_flex_rules_num = ii + 1;
    }

    acl_create_entry_object_id(acl_entry_id, acl_entry_index, acl_table_index);

    acl_db_table(acl_table_index).created_entry_count++;

    if (is_table_dynamic_sized && (acl_db_table(acl_table_index).created_entry_count > table_size)) {
        acl_db_table(acl_table_index).table_size = acl_db_table(acl_table_index).created_entry_count;
    }

    status = acl_enqueue_table(acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    acl_entry_key_to_str(*acl_entry_id, key_str);
    SX_LOG_NTC("Created acl entry %s\n\n", key_str);

out:
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Failed to create Entry \n");

        acl_db_remove_entry_from_table(acl_table_index, acl_entry_index, db_indexes_num);

        for (ii = 0; ii < psort_offsets_num; ii++) {
            release_psort_offset(acl_table_index, entry_priority, offsets_list_p[ii]);
        }

        mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_DELETE, acl_db_table(acl_table_index).key_type,
                                       region_id, offsets_list_p, NULL, set_flex_rules_num);

        if (is_pbs_index_valid(pbs_index)) {
            mlnx_acl_pbs_entry_delete(pbs_index);
        }
    }

    acl_table_unlock(acl_table_index);
    acl_global_unlock();

    sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

    free(port_arr);

    if (flex_acl_rule_p) {
        for (ii = 0; ii < flex_rules_num; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&flex_acl_rule_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            }
        }

        free(flex_acl_rule_p);
    }

    free(offsets_list_p);

    SX_LOG_EXIT();
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
    sx_status_t  sx_status = SX_STATUS_SUCCESS;
    sai_status_t status    = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    uint32_t port_index = 0;
    /* Check each port if it is binded to acl_id */

    for (port_index = 0; port_index < port_num; port_index++) {
        sx_status = sx_api_acl_port_bind_set(gh_sdk, cmd, port_arr[port_index], acl_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Unable to %s  port [%d] to  acl group[%d] - %s.\n ",
                       (SX_ACCESS_CMD_BIND == cmd) ? "bind" : "unbind", port_arr[port_index], acl_id,
                       SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t sort_tables_in_group(_In_ uint32_t        stage,
                                         _In_ uint32_t        new_table_index,
                                         _In_ sx_acl_id_t     new_acl_id,
                                         _Inout_ sx_acl_id_t *acl_table_ids,
                                         _In_ uint32_t        acl_count)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     index  = 0, ii;
    uint32_t    *tables;
    uint32_t     new_priority = acl_db_table(new_table_index).priority;

    SX_LOG_ENTER();

    if (NULL == acl_table_ids) {
        return SAI_STATUS_FAILURE;
    }

    tables = (uint32_t*)acl_db_group_by_sai_stage(stage)->table_indexes;

    for (index = 0; index < acl_count - 1; index++) {
        if (acl_db_table(tables[index]).priority < new_priority) {
            break;
        }
    }

    for (ii = acl_count - 1; ii > index; ii--) {
        acl_table_ids[ii] = acl_table_ids[ii - 1];
        tables[ii]        = tables[ii - 1];
    }

    acl_table_ids[index] = new_acl_id;
    tables[index]        = new_table_index;

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

sai_status_t mlnx_create_acl_table(_Out_ sai_object_id_t     * acl_table_id,
                                   _In_ uint32_t               attr_count,
                                   _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                                      status;
    sx_status_t                                       sx_status;
    sx_acl_direction_t                                sx_acl_direction;
    const sai_attribute_value_t                      *stage, *table_size, *priority, *group_id;
    const sai_attribute_value_t                      *src_mac, *dst_mac, *src_ip, *dst_ip;
    const sai_attribute_value_t                      *outer_vlan_id, *outer_vlan_pri, *outer_vlan_cfi;
    const sai_attribute_value_t                      *L4_src_port, *L4_dst_port;
    const sai_attribute_value_t                      *ether_type, *ip_protocol;
    const sai_attribute_value_t                      *dscp, *ecn;
    const sai_attribute_value_t                      *in_port, *out_port, *in_ports, *out_ports;
    const sai_attribute_value_t                      *ip_type, *ip_frag, *ip_flags, *tcp_flags;
    const sai_attribute_value_t                      *tc, *ttl, *tos;
    const sai_attribute_value_t /* *inner_vlan_id,*/ *inner_vlan_pri, *inner_vlan_cfi;
    const sai_attribute_value_t                      *user_meta, *src_ip_v6, *dst_ip_v6, *vlan_tags;
    uint32_t                                          src_ip_v6_index, dst_ip_v6_index;
    uint32_t /*inner_vlan_id_index,*/                 inner_vlan_pri_index, inner_vlan_cfi_index;
    uint32_t                                          user_meta_index, vlan_tags_index;
    uint32_t                                          stage_index, table_size_index, priority_index, group_id_index;
    uint32_t                                          src_mac_index, dst_mac_index, src_ip_index, dst_ip_index;
    uint32_t                                          outer_vlan_id_index, outer_vlan_pri_index, outer_vlan_cfi_index;
    uint32_t                                          L4_src_port_index, L4_dst_port_index;
    uint32_t                                          ether_type_index, ip_protocol_index;
    uint32_t                                          dscp_index, ecn_index;
    uint32_t                                          in_port_index, out_port_index, in_ports_index, out_ports_index;
    uint32_t                                          ip_type_index, ip_frag_index, ip_flags_index, tcp_flags_index;
    uint32_t                                          tc_index, ttl_index, tos_index;
    uint32_t                                          acl_count      = 0, key_count = 0, key_index = 0;
    uint32_t                                          acl_table_size = 0;
    uint16_t                                          ii             = 0;
    sx_acl_key_type_t                                 key_handle;
    const sx_acl_action_type_t                        action_type = SX_ACL_ACTION_TYPE_BASIC;
    const sx_acl_type_t                               acl_type    = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_region_id_t                                region_id;
    sx_acl_region_group_t                             region_group;
    sx_acl_id_t                                       acl_id;
    sx_acl_id_t                                       acl_group_id;
    sx_acl_id_t                                      *acl_table_ids = NULL;
    char                                              list_str[MAX_LIST_VALUE_STR_LEN];
    char                                              key_str[MAX_KEY_STR_LEN];
    sx_acl_key_t                                      keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    bool                                              is_dscp_present = false, is_ecn_present = false;
    uint32_t                                          port_num;
    sx_port_log_id_t                                  port_arr[MAX_PORTS];
    bool                                              is_dynamic_sized;
    uint32_t                                          acl_table_index = 0;
    bool                                              key_created     = false, region_created = false;
    bool                                              acl_created     = false, psort_table_created = false;

    SX_LOG_ENTER();

    if (NULL == acl_table_id) {
        SX_LOG_ERR("NULL acl table id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, acl_table_attribs,
                                    acl_table_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, acl_table_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Table, %s\n", list_str);

    if (SAI_STATUS_SUCCESS !=
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_STAGE, &stage, &stage_index)) {
        SX_LOG_ERR(" Missing mandatory attribute SAI_ACL_TABLE_ATTR_STAGE\n");
        status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_PRIORITY, &priority, &priority_index)) {
        SX_LOG_ERR(" Missing mandatory attribute SAI_ACL_TABLE_ATTR_PRIORITY\n");
        status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_SRC_IPv6, &src_ip_v6, &src_ip_v6_index)) {
        if (true == src_ip_v6->booldata) {
            keys[key_index] = FLEX_ACL_KEY_SIPV6;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_DST_IPv6, &dst_ip_v6, &dst_ip_v6_index)) {
        if (true == dst_ip_v6->booldata) {
            keys[key_index] = FLEX_ACL_KEY_DIPV6;
            key_index++;
        }
    }

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
/*
 *   if (SAI_STATUS_SUCCESS ==
 *       find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID, &inner_vlan_id,
 *                           &inner_vlan_id_index)) {
 *       if (true == inner_vlan_id->booldata) {
 *           keys[key_index] = FLEX_ACL_KEY_INNER_VLAN_ID;
 *           key_index++;
 *       }
 *   }*/

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

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META, &user_meta,
                            &user_meta_index)) {
        if (true == user_meta->booldata) {
            keys[key_index] = FLEX_ACL_KEY_USER_TOKEN;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_VLAN_TAGS, &vlan_tags,
                            &vlan_tags_index)) {
        if (true == user_meta->booldata) {
            keys[key_index] = FLEX_ACL_KEY_VLAN_TAGGED;
            key_index++;
            keys[key_index] = FLEX_ACL_KEY_INNER_VLAN_VALID;
            key_index++;
        }
    }

    acl_global_lock();

    if (false == sai_acl_db->acl_settings_tbl->initialized) {
        status = acl_resources_init();
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to initialize ACL resources\n");
            goto out;
        }
    }

    status = acl_db_find_table_free_index(&acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    key_count = key_index;
    sx_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_CREATE, keys, key_count, &key_handle);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(" Failed to create flex key - %s. \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    key_created = true;

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_GROUP_ID, &group_id, &group_id_index)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(group_id->oid, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &acl_group_id, NULL))) {
            goto out;
        }
        acl_group_id = acl_db_group_by_sai_stage(stage->s32)->group_id;
    } else {
        acl_group_id = acl_db_group_by_sai_stage(stage->s32)->group_id;
    }

    acl_count = acl_db_group_by_sai_stage(stage->s32)->acl_table_count;

    if (acl_count == ACL_GROUP_SIZE) {
        SX_LOG_ERR(" Max %u ACLs are allowed in a group\n", ACL_GROUP_SIZE);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    acl_table_ids = malloc(ACL_GROUP_SIZE * sizeof(sx_acl_id_t));
    if (acl_table_ids == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for acl table ids\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(acl_table_ids, 0, ACL_GROUP_SIZE * sizeof(sx_acl_id_t));

    sx_acl_direction = acl_sai_stage_to_sx_dir(stage->s32);

    sx_status = sx_api_acl_group_get(gh_sdk, acl_group_id, &sx_acl_direction, acl_table_ids, &acl_count);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get acl group - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    if (SAI_ACL_STAGE_INGRESS == stage->s32) {
        if (acl_count >= g_resource_limits.acl_ingress_tables_max) {
            SX_LOG_ERR(" Max tables for ingress stage have already been created \n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    } else if (SAI_ACL_STAGE_EGRESS == stage->s32) {
        if (acl_count >= g_resource_limits.acl_egress_tables_max) {
            SX_LOG_ERR(" Max tables for egress stage have already been created \n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }
    /* Check for max tables ends here */

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_SIZE, &table_size, &table_size_index)) {
        if (0 == table_size->u32) {
            SX_LOG_NTC("Table size received is zero. Value is set to DEFAULT TABLE SIZE \n");
            acl_table_size   = ACL_DEFAULT_TABLE_SIZE;
            is_dynamic_sized = true;
        } else {
            acl_table_size   = table_size->u32;
            is_dynamic_sized = false;
        }
    } else {   /* if table size is not present, use default */
        acl_table_size   = ACL_DEFAULT_TABLE_SIZE;
        is_dynamic_sized = true;
    }

    sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_CREATE, key_handle,
                                      action_type, acl_table_size, &region_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create region - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    region_created = true;

    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type                           = acl_type;
    region_group.regions.acl_packet_agnostic.region = region_id;

    sx_status = sx_api_acl_set(gh_sdk, SX_ACCESS_CMD_CREATE, acl_type, sx_acl_direction, &region_group, &acl_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create acl table - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    acl_created = true;

    status = init_psort_table(acl_table_index, is_dynamic_sized, acl_table_size);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }
    psort_table_created = true;

    if (false == acl_db_table(acl_table_index).is_lock_inited) {
        if (CL_SUCCESS != cl_plock_init_pshared(&acl_db_table(acl_table_index).lock)) {
            SX_LOG_ERR("Failed to init cl_plock for table \n");
            status = SAI_STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        acl_db_table(acl_table_index).is_lock_inited = true;
    }

    /* Update D.B */
    acl_db_table(acl_table_index).table_id            = acl_id;
    acl_db_table(acl_table_index).table_size          = acl_table_size;
    acl_db_table(acl_table_index).region_size         = acl_table_size;
    acl_db_table(acl_table_index).stage               = stage->s32;
    acl_db_table(acl_table_index).priority            = priority->u32;
    acl_db_table(acl_table_index).key_type            = key_handle;
    acl_db_table(acl_table_index).region_id           = region_id;
    acl_db_table(acl_table_index).is_dynamic_sized    = is_dynamic_sized;
    acl_db_table(acl_table_index).created_entry_count = 0;
    acl_db_table(acl_table_index).created_rule_count  = 0;
    acl_db_table(acl_table_index).head_entry_index    = ACL_INVALID_DB_INDEX;

    acl_table_ids[acl_count] = acl_id;
    acl_count                = acl_count + 1;

    /* sort tables in group according to priority */
    status = sort_tables_in_group(stage->s32, acl_table_index, acl_id, acl_table_ids, acl_count);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Unable to sort ACL tables in a group \n");
        goto out;
    }

    sx_status = sx_api_acl_group_set(gh_sdk,
                                     SX_ACCESS_CMD_SET,
                                     sx_acl_direction,
                                     acl_table_ids,
                                     acl_count,
                                     &acl_group_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create acl table - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    /* update table count in group */
    acl_db_group_by_sai_stage(stage->s32)->acl_table_count = acl_count;

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

        status = acl_db_port_bind_set(SX_ACCESS_CMD_BIND, sx_acl_direction, acl_group_id, port_arr, &port_num);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Unable to Bind all ports to %s acl group \n",
                       (stage->s32 == SX_ACL_DIRECTION_INGRESS) ? "Ingress" : "Egress");
            goto out;
        }
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, acl_table_index, NULL, acl_table_id);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    acl_table_key_to_str(*acl_table_id, key_str);
    SX_LOG_NTC("Created acl table %s\n", key_str);

out:
    free(acl_table_ids);

    if (status != SAI_STATUS_SUCCESS) {
        acl_db_table(acl_table_index).is_used = false;

        if (psort_table_created) {
            if (SAI_STATUS_SUCCESS != delete_psort_table(acl_table_index)) {
                SX_LOG_ERR(" Failed to delete psort table\n");
            }
        }

        if (acl_created) {
            sx_status = sx_api_acl_set(gh_sdk, SX_ACCESS_CMD_DESTROY, acl_type,
                                       sx_acl_direction, &region_group, &acl_id);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to destroy ACL - %s.\n", SX_STATUS_MSG(sx_status));
            }
        }

        if (region_created) {
            sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_DESTROY, SX_ACL_KEY_TYPE_MAC_IPV4_FULL,
                                              SX_ACL_ACTION_TYPE_BASIC, acl_table_size, &region_id);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR(" Failed to delete region ACL - %s.\n", SX_STATUS_MSG(sx_status));
            }
        }

        if (key_created) {
            sx_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_DELETE, keys, key_count, &key_handle);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR(" Failed to delete flex keys - %s. \n", SX_STATUS_MSG(sx_status));
            }
        }
    }

    acl_global_unlock();

    SX_LOG_EXIT();
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
sai_status_t mlnx_set_acl_table_attribute(_In_ sai_object_id_t acl_table_id, _In_ const sai_attribute_t *attr)
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
    sx_status_t  sx_status;
    sx_acl_id_t  sx_counter_id;
    uint32_t     acl_counter_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_COUNTER_ATTR_PACKETS == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_BYTES == (int64_t)arg));

    acl_global_lock();

    status = extract_acl_counter_index(key->object_id, &acl_counter_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (value->u64 == 0) {
        sx_counter_id = sai_acl_db->acl_counter_db[acl_counter_index].counter_id;
        if (SX_STATUS_SUCCESS != (sx_status = sx_api_flow_counter_clear_set(gh_sdk, sx_counter_id))) {
            SX_LOG_ERR("Failed to clear counter: [%d] - %s \n", sx_counter_id, SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

out:
    acl_global_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_counter_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    sx_status_t           sx_status;
    sai_status_t          status;
    sx_flow_counter_set_t counter_value;
    sx_flow_counter_id_t  counter_id;
    uint32_t              acl_counter_index;

    SX_LOG_ENTER();
    assert((SAI_ACL_COUNTER_ATTR_PACKETS == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_BYTES == (int64_t)arg));

    acl_global_lock();

    status = extract_acl_counter_index(key->object_id, &acl_counter_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    counter_id = sai_acl_db->acl_counter_db[acl_counter_index].counter_id;

    sx_status = sx_api_flow_counter_get(gh_sdk, SX_ACCESS_CMD_READ, counter_id, &counter_value);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(" Failure to get counter in SDK - %s \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
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
    acl_global_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t db_find_acl_counter_free_index(_Out_ uint32_t *free_index)
{
    uint32_t     ii;
    sai_status_t status;

    assert(free_index != NULL);

    SX_LOG_ENTER();

    for (ii = 0; ii < ACL_MAX_COUNTER_NUM; ii++) {
        if (false == sai_acl_db->acl_counter_db[ii].is_valid) {
            *free_index                             = ii;
            sai_acl_db->acl_counter_db[ii].is_valid = true;
            status                                  = SAI_STATUS_SUCCESS;
            break;
        }
    }

    if (ACL_MAX_COUNTER_NUM == ii) {
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
    uint32_t counter_index;

    assert((SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT == (int64_t)arg));

    status = extract_acl_counter_index(key->object_id, &counter_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT:
        value->booldata = sai_acl_db->acl_counter_db[counter_index].packet_counter_flag;
        break;

    case SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT:
        value->booldata = sai_acl_db->acl_counter_db[counter_index].byte_counter_flag;
        break;
    }

out:
    SX_LOG_EXIT();
    return status;
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
    sx_status_t                  sx_status;
    const sai_attribute_value_t *byte_counter_flag_attr, *packet_counter_flag_attr, *table_id;
    uint32_t                     byte_counter_flag_index, packet_counter_flag_index;
    uint32_t                     table_id_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_flow_counter_type_t       counter_type;
    sx_flow_counter_id_t         sx_counter_id = SX_FLOW_COUNTER_ID_INVALID;
    uint32_t                     acl_table_id, counter_index = ACL_INVALID_DB_INDEX;
    bool                         byte_counter_flag = false, packet_counter_flag = false;

    SX_LOG_ENTER();

    if (NULL == acl_counter_id) {
        SX_LOG_ERR("NULL acl counter id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, acl_counter_attribs,
                                    acl_counter_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, acl_counter_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Counter, %s\n", list_str);

    /* get table id from attributes */
    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_COUNTER_ATTR_TABLE_ID, &table_id, &table_id_index);
    assert(SAI_STATUS_SUCCESS == status);


    acl_global_lock();

    status = extract_acl_table_index(table_id->oid, &acl_table_id);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
                                 &byte_counter_flag_attr, &byte_counter_flag_index);
    if (SAI_STATUS_SUCCESS == status) {
        byte_counter_flag = byte_counter_flag_attr->booldata;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
                                 &packet_counter_flag_attr, &packet_counter_flag_index);
    if (SAI_STATUS_SUCCESS == status) {
        packet_counter_flag = packet_counter_flag_attr->booldata;
    }

    if ((!byte_counter_flag) && (!packet_counter_flag)) {
        SX_LOG_ERR(" Failure to create Counter as both counter types [ byte & packet] are false.\n ");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (byte_counter_flag && packet_counter_flag) {
        counter_type = SX_FLOW_COUNTER_TYPE_PACKETS_AND_BYTES;
    } else if (byte_counter_flag) {
        counter_type = SX_FLOW_COUNTER_TYPE_BYTES;
    } else {
        counter_type = SX_FLOW_COUNTER_TYPE_PACKETS;
    }

    sx_status = sx_api_flow_counter_set(gh_sdk, SX_ACCESS_CMD_CREATE, counter_type, &sx_counter_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failure to create Counter - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = db_find_acl_counter_free_index(&counter_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    sai_acl_db->acl_counter_db[counter_index].counter_id          = sx_counter_id;
    sai_acl_db->acl_counter_db[counter_index].byte_counter_flag   = byte_counter_flag;
    sai_acl_db->acl_counter_db[counter_index].packet_counter_flag = packet_counter_flag;

    status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_index, NULL, acl_counter_id);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    acl_counter_key_to_str(*acl_counter_id, key_str);
    SX_LOG_NTC("Created acl counter %s\n", key_str);

out:
    if (SAI_STATUS_SUCCESS != status) {
        if (SX_FLOW_COUNTER_ID_INVALID != sx_counter_id) {
            sx_status = sx_api_flow_counter_set(gh_sdk, SX_ACCESS_CMD_DESTROY, 0, &sx_counter_id);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed delete counter - %s.\n", SX_STATUS_MSG(sx_status));
            }
        }

        if (ACL_INVALID_DB_INDEX != counter_index) {
            sai_acl_db->acl_counter_db[counter_index].is_valid = false;
        }
    }
    acl_global_unlock();

    SX_LOG_EXIT();
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
    sai_status_t status;
    char         key_str[MAX_KEY_STR_LEN];
    uint32_t     acl_entry_index, acl_table_index, rule_num;
    pbs_index_t  acl_pbs_index;

    SX_LOG_ENTER();
    acl_entry_key_to_str(acl_entry_id, key_str);
    SX_LOG_NTC("Delete ACL Entry %s\n", key_str);

    status = extract_acl_table_index_and_entry_index(acl_entry_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Unable to extract acl table id and acl entry index in acl table\n");
        return status;
    }

    acl_table_write_lock(acl_table_index);
    acl_global_lock();

    if (false == acl_db_entry(acl_entry_index).is_used) {
        SX_LOG_ERR("Failure : ACL Entry doesn't exist\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    acl_pbs_index = acl_db_entry(acl_entry_index).pbs_index;
    rule_num      = acl_db_entry(acl_entry_index).num_rules;

    status = mlnx_delete_acl_entry_data(acl_table_index, acl_entry_index, rule_num);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (is_pbs_index_valid(acl_pbs_index)) {
        status = mlnx_acl_pbs_entry_delete(acl_pbs_index);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("failed to delete pbs entry\n");
            goto out;
        }
    }

    acl_db_table(acl_table_index).created_entry_count--;

    status = acl_enqueue_table(acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_global_unlock();
    acl_table_unlock(acl_table_index);

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
    sai_status_t          status;
    sx_status_t           sx_status;
    sx_acl_region_id_t    region_id;
    sx_acl_direction_t    acl_direction;
    sx_acl_region_group_t region_group;
    sx_acl_id_t           sx_acl_id;
    sx_acl_size_t         region_size;
    const sx_acl_type_t   acl_type      = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_id_t          *acl_table_ids = NULL;
    sx_acl_id_t           group_id      = 0;
    sx_port_log_id_t      port_arr[MAX_PORTS];
    sx_acl_key_type_t     key_handle;
    sai_acl_stage_t       stage;
    uint32_t              port_num  = 0;
    uint32_t              ii        = 0, index = 0;
    uint32_t              acl_count = 0, key_count = 0;
    uint32_t              table_index;
    sx_acl_key_t          keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    bool                  is_table_present_in_group = false;
    uint32_t             *table_indexes;

    SX_LOG_ENTER();

    acl_table_key_to_str(acl_table_id, key_str);
    SX_LOG_NTC("Delete ACL Table %s\n", key_str);


    status = extract_acl_table_index(acl_table_id, &table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(table_index);

    if (0 != acl_db_table(table_index).created_entry_count) {
        SX_LOG_ERR("Attempt to delete table with entries\n");
        acl_table_unlock(table_index);
        SX_LOG_EXIT();
        return SAI_STATUS_OBJECT_IN_USE;
    }

    acl_table_ids = malloc(ACL_GROUP_SIZE * sizeof(sx_acl_id_t));
    if (acl_table_ids == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for acl table ids\n");
        acl_table_unlock(table_index);
        SX_LOG_EXIT();
        return SAI_STATUS_NO_MEMORY;
    }
    memset(acl_table_ids, 0, ACL_GROUP_SIZE * sizeof(sx_acl_id_t));

    acl_global_lock();

    region_id     = acl_db_table(table_index).region_id;
    region_size   = acl_db_table(table_index).region_size;
    sx_acl_id     = acl_db_table(table_index).table_id;
    stage         = acl_db_table(table_index).stage;
    key_handle    = acl_db_table(table_index).key_type;
    group_id      = acl_db_group_by_sai_stage(stage)->group_id;
    acl_count     = acl_db_group_by_sai_stage(stage)->acl_table_count;
    acl_direction = acl_sai_stage_to_sx_dir(stage);

    sx_status = sx_api_acl_group_get(gh_sdk, group_id, &acl_direction, acl_table_ids, &acl_count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get acl group - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    for (index = 0; index < acl_count; index++) {
        if (acl_table_ids[index] == sx_acl_id) {
            is_table_present_in_group = true;
            break;
        }
    }

    if (false == is_table_present_in_group) {
        SX_LOG_ERR(" Failure to delete ACL Table which doesnot exist in SDK. \n");
        goto out;
    }

    table_indexes = (uint32_t*)acl_db_group_by_sai_stage(stage)->table_indexes;

    for (; index < acl_count - 1; index++) {
        acl_table_ids[index]      = acl_table_ids[index + 1];
        table_indexes[index + ii] = table_indexes[index + ii + 1];
    }

    if (1 == acl_count) {
        port_num = g_sai_db_ptr->ports_number;
        for (ii = 0; ii < port_num; ii++) {
            port_arr[ii] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[ii].logical;
        }

        /* Unbind  all ports to ACL group */
        status = acl_db_port_bind_set(SX_ACCESS_CMD_UNBIND, acl_direction, group_id, port_arr, &port_num);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Unable to unbind all ports to %s acl group \n",
                       acl_direction == SX_ACL_DIRECTION_INGRESS ? "Ingress" : "Egress");
            goto out;
        }
    }

    acl_count = acl_count - 1;

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, acl_direction, acl_table_ids, acl_count, &group_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to delete acl table [%d] from group [%d]\n - %s", table_index, group_id,
                   SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    /* destroy the ACL */
    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type                           = acl_type;
    region_group.regions.acl_packet_agnostic.region = region_id;

    sx_status = sx_api_acl_set(gh_sdk, SX_ACCESS_CMD_DESTROY, SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC,
                               acl_direction, &region_group, &sx_acl_id);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to destroy ACL - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    acl_db_group_by_sdk_direction(acl_direction)->acl_table_count = acl_count;

    sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_DESTROY, SX_ACL_KEY_TYPE_MAC_IPV4_FULL,
                                      SX_ACL_ACTION_TYPE_BASIC, region_size, &region_id);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(" Failed to delete region ACL - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sx_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, keys, &key_count);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(" Failed to get flex keys - %s. \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sx_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_DELETE, keys, key_count, &key_handle);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR(" Failed to delete flex keys - %s. \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = delete_psort_table(table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Failed to delete psort table\n");
        goto out;
    }

    acl_db_table(table_index).is_used = false;

out:
    free(acl_table_ids);

    acl_global_unlock();
    acl_table_unlock(table_index);

    SX_LOG_EXIT();
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
    sx_status_t            sx_status;
    char                   key_str[MAX_KEY_STR_LEN];
    uint32_t               counter_index, flow_counter_id;
    sai_status_t           status;
    bool                   is_byte_counter, is_packet_counter;
    sx_flow_counter_type_t counter_type;

    SX_LOG_ENTER();

    acl_counter_key_to_str(acl_counter_id, key_str);
    SX_LOG_NTC("Delete ACL Counter %s\n", key_str);

    acl_global_lock();

    status = extract_acl_counter_index(acl_counter_id, &counter_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    is_byte_counter   = sai_acl_db->acl_counter_db[counter_index].byte_counter_flag;
    is_packet_counter = sai_acl_db->acl_counter_db[counter_index].packet_counter_flag;

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

    flow_counter_id = sai_acl_db->acl_counter_db[counter_index].counter_id;

    if (SAI_STATUS_SUCCESS !=
        (sx_status = sx_api_flow_counter_set(gh_sdk, SX_ACCESS_CMD_DESTROY, counter_type, &flow_counter_id))) {
        SX_LOG_ERR("Failed delete counter - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    switch (counter_type) {
    case SX_FLOW_COUNTER_TYPE_PACKETS:
        sai_acl_db->acl_counter_db[counter_index].packet_counter_flag = false;
        break;

    case SX_FLOW_COUNTER_TYPE_BYTES:
        sai_acl_db->acl_counter_db[counter_index].byte_counter_flag = false;
        break;

    case SX_FLOW_COUNTER_TYPE_PACKETS_AND_BYTES:
        sai_acl_db->acl_counter_db[counter_index].packet_counter_flag = false;
        sai_acl_db->acl_counter_db[counter_index].byte_counter_flag   = false;
        break;

    default:
        SX_LOG_ERR("counter type not supported \n");
        goto out;
    }

    sai_acl_db->acl_counter_db[counter_index].is_valid = false;

out:
    acl_global_unlock();

    SX_LOG_EXIT();
    return status;
}

static void mlnx_acl_flex_rule_key_del(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t key_index)
{
    uint32_t key_count;

    key_count = rule->key_desc_count;

    assert((key_count != 0) && (key_index < key_count));

    if (key_count > 1) {
        rule->key_desc_list_p[key_index] = rule->key_desc_list_p[key_count - 1];
    }

    rule->key_desc_count--;
}

static void mlnx_acl_flex_rule_action_del(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t action_index)
{
    uint32_t action_count;

    action_count = rule->action_count;

    assert((action_count != 0) && (action_index < action_count));

    if (action_count > 1) {
        rule->action_list_p[action_index] = rule->action_list_p[action_count - 1];
    }

    rule->action_count--;
}

static void mlnx_acl_flex_rule_copy(_Out_ sx_flex_acl_flex_rule_t      *dst_rule,
                                    _In_ const sx_flex_acl_flex_rule_t *src_rule)
{
    dst_rule->valid          = src_rule->valid;
    dst_rule->key_desc_count = src_rule->key_desc_count;
    dst_rule->action_count   = src_rule->action_count;

    memcpy(dst_rule->key_desc_list_p, src_rule->key_desc_list_p,
           src_rule->key_desc_count * sizeof(sx_flex_acl_key_desc_t));
    memcpy(dst_rule->action_list_p, src_rule->action_list_p,
           src_rule->action_count * sizeof(sx_flex_acl_flex_action_t));
}

static int sai_cmp_flex_acl_rules_offsets(const void *a, const void *b)
{
    return (*(sx_acl_rule_offset_t*)a - *(sx_acl_rule_offset_t*)b);
}

static sai_status_t mlnx_acl_flex_rules_get_helper(_In_ const sx_acl_key_type_t     key_type,
                                                   _In_ const sx_acl_region_id_t    region_id,
                                                   _In_ const sx_acl_rule_offset_t *offsets_list_p,
                                                   _Inout_ sx_flex_acl_flex_rule_t *rules_list_p,
                                                   _In_ uint32_t                    rules_count)
{
    sai_status_t             status = SAI_STATUS_SUCCESS;
    sx_status_t              sx_status;
    sx_acl_rule_offset_t    *region_rule_offset_list_p = NULL;
    sx_flex_acl_flex_rule_t *region_rule_list_p        = NULL;
    sx_acl_rule_offset_t    *found_offset;
    uint32_t                 region_rule_count = 0, ii;
    uint32_t                 found_index;

    sx_status = sx_api_acl_flex_rules_get(gh_sdk, region_id, NULL, NULL, &region_rule_count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get rule count from region\n");
        status = sdk_to_sai(sx_status);
        goto out;
    }

    /* region should have at least one rule */
    if (0 == region_rule_count) {
        SX_LOG_ERR("Number of rules in region = 0\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    region_rule_offset_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * region_rule_count);
    if (NULL == region_rule_offset_list_p) {
        SX_LOG_ERR("No memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    region_rule_list_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * region_rule_count);
    if (NULL == region_rule_list_p) {
        SX_LOG_ERR("No memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (ii = 0; ii < region_rule_count; ii++) {
        sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS, &region_rule_list_p[ii]);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(status));
            region_rule_count = ii;
            status            = sdk_to_sai(sx_status);
            goto out;
        }
    }

    sx_status = sx_api_acl_flex_rules_get(gh_sdk,
                                          region_id,
                                          region_rule_offset_list_p,
                                          region_rule_list_p,
                                          &region_rule_count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get rules from region - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    for (ii = 0; ii < rules_count; ii++) {
        found_offset = bsearch(&offsets_list_p[ii], region_rule_offset_list_p, region_rule_count,
                               sizeof(sx_acl_rule_offset_t), sai_cmp_flex_acl_rules_offsets);
        if (NULL == found_offset) {
            SX_LOG_ERR("Rule with given offset [%u] doesn't exist in region\n", offsets_list_p[ii]);
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        found_index = (uint32_t)(found_offset - region_rule_offset_list_p);

        mlnx_acl_flex_rule_copy(&rules_list_p[ii], &region_rule_list_p[found_index]);
    }

out:
    for (ii = 0; ii < region_rule_count; ii++) {
        sx_status = sx_lib_flex_acl_rule_deinit(&region_rule_list_p[ii]);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
        }
    }

    free(region_rule_list_p);
    free(region_rule_offset_list_p);

    return status;
}

static sai_status_t mlnx_acl_flex_rules_set_helper(_In_ sx_access_cmd_t          cmd,
                                                   _In_ const sx_acl_key_type_t  key_type,
                                                   _In_ const sx_acl_region_id_t region_id,
                                                   _In_ sx_acl_rule_offset_t    *offsets_list_p,
                                                   _In_ sx_flex_acl_flex_rule_t *rules_list_p,
                                                   _In_ uint32_t                 rules_count)
{
    sx_status_t              sx_status;
    sai_status_t             status              = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t *delete_rules_list_p = NULL;
    uint32_t                 ii, set_rules_num;

    if (0 == rules_count) {
        goto out;
    }

    assert(offsets_list_p != NULL);
    assert((cmd == SX_ACCESS_CMD_DELETE) || (rules_list_p != NULL));

    if (SX_ACCESS_CMD_DELETE == cmd) {
        delete_rules_list_p = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * rules_count);
        if (delete_rules_list_p == NULL) {
            SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
            status = SAI_STATUS_NO_MEMORY;
            goto out;
        }

        memset(delete_rules_list_p, 0, sizeof(sx_flex_acl_flex_rule_t) * rules_count);

        for (ii = 0; ii < rules_count; ii++) {
            sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS, &delete_rules_list_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
                rules_count = ii;
                status      = sdk_to_sai(sx_status);
                goto out;
            }

            delete_rules_list_p[ii].valid = false;
        }

        rules_list_p = delete_rules_list_p;
    }

    ii = 0;
    while (ii < rules_count) {
        set_rules_num = MIN(g_resource_limits.acl_rules_block_max, rules_count - ii);

        sx_status = sx_api_acl_flex_rules_set(gh_sdk, cmd, region_id,
                                              &offsets_list_p[ii], &rules_list_p[ii], set_rules_num);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        ii += set_rules_num;
    }

out:
    if (delete_rules_list_p) {
        for (ii = 0; ii < rules_count; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&delete_rules_list_p[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
            }
        }

        free(delete_rules_list_p);
    }

    return status;
}

static sai_status_t mlnx_delete_acl_entry_data(_In_ uint32_t table_index,
                                               _In_ uint32_t entry_index,
                                               _In_ uint32_t entry_count)
{
    sai_status_t               status = SAI_STATUS_SUCCESS;
    sx_acl_key_type_t          key_type;
    sx_acl_region_id_t         region_id;
    sx_flex_acl_rule_offset_t *offsets_list_p = NULL;
    uint32_t                   priority, ii;

    SX_LOG_ENTER();

    assert(table_index != ACL_INVALID_DB_INDEX && entry_index != ACL_INVALID_DB_INDEX);

    key_type  = acl_db_table(table_index).key_type;
    region_id = acl_db_table(table_index).region_id;
    priority  = acl_db_entry(entry_index).priority;

    offsets_list_p = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * entry_count);
    if (offsets_list_p == NULL) {
        SX_LOG_ERR(" Unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    status = acl_get_entries_offsets(entry_index, entry_count, offsets_list_p);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    for (ii = 0; ii < entry_count; ii++) {
        status = release_psort_offset(table_index, priority, offsets_list_p[ii]);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to delete psort entry\n");
            goto out;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_DELETE,
                                            key_type,
                                            region_id,
                                            offsets_list_p,
                                            NULL,
                                            entry_count);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    acl_db_remove_entry_from_table(table_index, entry_index, entry_count);

out:
    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sx_utils_status_t psort_notification_func(_In_ psort_notification_type_e notif_type,
                                                 _In_ void                     *data,
                                                 _In_ void                     *cookie)
{
    sx_utils_status_t    status       = SX_UTILS_STATUS_SUCCESS;
    psort_shift_param_t *shift_param  = (psort_shift_param_t*)data;
    uint32_t             acl_table_id = (uint32_t)(uintptr_t)cookie;

    SX_LOG_ENTER();

    switch (notif_type) {
    case PSORT_TABLE_SHIFT_E:
        if (SAI_STATUS_SUCCESS != update_rules_offsets(shift_param, acl_table_id)) {
            status = SX_UTILS_STATUS_ERROR;
        }
        break;

    case PSORT_TABLE_ALMOST_EMPTY_E:
        if (SAI_STATUS_SUCCESS != acl_table_size_decrease(acl_table_id)) {
            status = SX_UTILS_STATUS_ERROR;
        }
        break;

    case PSORT_TABLE_ALMOST_FULL_E:
        if (SAI_STATUS_SUCCESS != acl_table_size_increase(acl_table_id, ACL_TABLE_SIZE_INCREASE_AUTO)) {
            status = SX_UTILS_STATUS_ERROR;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported type of pSort notification\n");
    }

    SX_LOG_EXIT();
    return status;
}

static uint32_t acl_calculate_delta(_In_ uint32_t acl_table_index)
{
    uint32_t delta;

    delta = (uint32_t)(acl_db_table(acl_table_index).region_size * ACL_TABLE_SIZE_INC_PERCENT);
    delta = (delta > ACL_TABLE_SIZE_MIN_DELTA) ? delta : ACL_TABLE_SIZE_MIN_DELTA;

    return delta;
}

static sai_status_t acl_table_size_increase(_In_ uint32_t table_index, _In_ uint32_t size)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_status_t        sx_status;
    sx_utils_status_t  sx_utils_status;
    sx_acl_key_type_t  key_type;
    sx_acl_region_id_t region_id;
    sx_api_handle_t   *sdk_api_handle = NULL;
    psort_handle_t     psort_handle;
    sx_acl_size_t      old_size, new_size;
    uint32_t           delta;

    SX_LOG_ENTER();

    assert(ACL_INVALID_DB_INDEX != table_index);

    psort_handle = acl_db_table(table_index).psort_handle;
    region_id    = acl_db_table(table_index).region_id;
    key_type     = acl_db_table(table_index).key_type;
    old_size     = acl_db_table(table_index).region_size;

    delta    = acl_calculate_delta(table_index);
    delta    = MAX(delta, size);
    new_size = old_size + delta;

#ifndef _WIN32
    sdk_api_handle = pthread_getspecific(pthread_key);
#endif
    if (NULL == sdk_api_handle) {
        SX_LOG_ERR("Failed to get sdk_api_handle for thread\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    sx_status = sx_api_acl_region_set(*sdk_api_handle,
                                      SX_ACCESS_CMD_EDIT,
                                      key_type,
                                      SX_ACL_ACTION_TYPE_BASIC,
                                      new_size,
                                      &region_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to resize a region[%d] %s.\n", table_index, SX_STATUS_MSG(sx_status));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    sx_utils_status = psort_table_resize(psort_handle, new_size, false, NULL);
    if (SX_UTILS_STATUS_SUCCESS != sx_utils_status) {
        SX_LOG_ERR("Failed to resize a table[%d] %s.\n", table_index, SX_UTILS_STATUS_MSG(sx_utils_status));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    acl_db_table(table_index).region_size = new_size;

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t acl_table_size_decrease(_In_ uint32_t table_index)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_status_t        sx_status;
    sx_utils_status_t  sx_utils_status;
    sx_acl_key_type_t  key_type;
    sx_acl_region_id_t region_id;
    sx_api_handle_t   *sdk_api_handle = NULL;
    psort_handle_t     psort_handle;
    sx_acl_size_t      new_size, old_size;
    uint32_t           table_size;
    uint32_t           rule_count;

    SX_LOG_ENTER();

    assert(ACL_INVALID_DB_INDEX != table_index);

    psort_handle = acl_db_table(table_index).psort_handle;
    region_id    = acl_db_table(table_index).region_id;
    key_type     = acl_db_table(table_index).key_type;
    table_size   = acl_db_table(table_index).table_size;
    old_size     = acl_db_table(table_index).region_size;
    rule_count   = acl_db_table(table_index).created_rule_count;

    if (false == acl_db_table(table_index).is_dynamic_sized) {
        new_size = rule_count + (uint32_t)(rule_count * ACL_TABLE_SIZE_DEC_PERCENT);

        /* Don't decrease static-sized table to size less then value specified by user */
        if (new_size <= table_size) {
            status = SAI_STATUS_SUCCESS;
            goto out;
        }
    } else {
        new_size = old_size / 2;
        new_size = MAX(new_size, ACL_DEFAULT_TABLE_SIZE);

        if (old_size <= new_size) {
            status = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

#ifndef _WIN32
    sdk_api_handle = pthread_getspecific(pthread_key);
#endif
    if (NULL == sdk_api_handle) {
        SX_LOG_ERR("Failed to get sdk_api_handle for thread\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    sx_utils_status = psort_table_resize(psort_handle, new_size, false, NULL);
    if (SX_UTILS_STATUS_SUCCESS != sx_utils_status) {
        SX_LOG_ERR("Failed to resize a table[%d] %s.\n", table_index, SX_UTILS_STATUS_MSG(sx_utils_status));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    sx_status = sx_api_acl_region_set(*sdk_api_handle,
                                      SX_ACCESS_CMD_EDIT,
                                      key_type,
                                      SX_ACL_ACTION_TYPE_BASIC,
                                      new_size,
                                      &region_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to resize a region[%d] %s.\n", table_index, SX_STATUS_MSG(sx_status));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t create_rpc_server(_Inout_ int *s)
{
    return create_rpc_socket(s, NULL, true);
}

static sai_status_t create_rpc_client(_Inout_ int *s, _Inout_ struct sockaddr_un *sv_sockaddr)
{
    return create_rpc_socket(s, sv_sockaddr, false);
}

static sai_status_t create_rpc_socket(_Inout_ int *s, _Inout_opt_ struct sockaddr_un *sockaddr, _In_ bool is_server)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    struct sockaddr_un cl_sockaddr;
    struct sockaddr_un sv_sockaddr;

    assert(s != NULL);
    assert(is_server || (sockaddr != NULL));

    *s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (-1 == *s) {
        SX_LOG_ERR("Failed to open socket for ACL RPC - %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    memset(&sv_sockaddr, 0, sizeof(sv_sockaddr));
    sv_sockaddr.sun_family = AF_UNIX;
    strncpy(sv_sockaddr.sun_path, ACL_RPC_SV_SOCKET_ADDR, sizeof(sv_sockaddr.sun_path) - 1);

    if (is_server) {
        unlink(ACL_RPC_SV_SOCKET_ADDR);
        if (-1 == (bind(*s, (struct sockaddr*)&sv_sockaddr, sizeof(sv_sockaddr)))) {
            SX_LOG_ERR("Failed to bind server socket for ACL RPC - %s\n", strerror(errno));
            status = SAI_STATUS_FAILURE;
            close(*s);
        }
    } else {
        memset(&cl_sockaddr, 0, sizeof(cl_sockaddr));
        cl_sockaddr.sun_family = AF_UNIX;
        if (-1 == (bind(*s, (struct sockaddr*)&cl_sockaddr, sizeof(sa_family_t)))) {
            SX_LOG_ERR("Failed to bind client socket for ACL RPC - %s\n", strerror(errno));
            status = SAI_STATUS_FAILURE;
            close(*s);
        }

        memcpy(sockaddr, &sv_sockaddr, sizeof(sv_sockaddr));
    }
#endif

    return status;
}

static sai_status_t acl_psort_rpc_call(_Inout_ acl_rpc_info_t *rpc_info)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    ssize_t   bytes;
    socklen_t sockaddr_len;

    SX_LOG_ENTER();

    if (false == sai_acl_db->acl_settings_tbl->rpc_thread_start_flag) {
        acl_cond_mutex_lock();
        sai_acl_db->acl_settings_tbl->rpc_thread_start_flag = true;
        if (0 != pthread_cond_signal(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond)) {
            SX_LOG_ERR("Failed to signal condition var to wake up RPC thread\n");
            status = SAI_STATUS_FAILURE;
            acl_cond_mutex_unlock();
            goto out;
        }
        acl_cond_mutex_unlock();
    }

    if (-1 == rpc_cl_socket) {
        status = create_rpc_client(&rpc_cl_socket, &rpc_sv_sockaddr);
        if (status != SAI_STATUS_SUCCESS) {
            goto out;
        }
    }

    sockaddr_len = sizeof(rpc_sv_sockaddr);

    bytes = sendto(rpc_cl_socket,
                   (void*)rpc_info,
                   sizeof(*rpc_info),
                   0,
                   (struct sockaddr*)&rpc_sv_sockaddr,
                   sockaddr_len);
    if (bytes != sizeof(*rpc_info)) {
        SX_LOG_ERR("Failed to send data througn the socket - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    bytes = recvfrom(rpc_cl_socket, (void*)rpc_info, sizeof(*rpc_info), 0, NULL, NULL);
    if (bytes != sizeof(*rpc_info)) {
        SX_LOG_ERR("Failed to recv data from the socket - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = rpc_info->status;

out:
#endif
    SX_LOG_EXIT();
    return status;
}

static sai_status_t init_psort_table(_In_ uint32_t table_id, _In_ bool is_table_dynamic, _In_ uint32_t size)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    if (is_init_process) {
        status = __init_psort_table(table_id, is_table_dynamic, size);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type                  = ACL_RPC_PSORT_TABLE_INIT;
        rpc_info.args.table_id         = table_id;
        rpc_info.args.table_is_dynamic = is_table_dynamic;
        rpc_info.args.size             = size;

        status = acl_psort_rpc_call(&rpc_info);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t __init_psort_table(_In_ uint32_t table_id, _In_ bool is_table_dynamic, _In_ uint32_t size)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_utils_status_t  sx_status;
    psort_init_param_t psort_init_param;

    SX_LOG_ENTER();

    if (!acl_table_index_check_range(table_id)) {
        SX_LOG_ERR("Attempt to use invalid ACL Table DB index\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    memset(&psort_init_param, 0, sizeof(psort_init_param));

    psort_init_param.table_size     = size;
    psort_init_param.cookie         = (void*)(intptr_t)table_id;
    psort_init_param.delta_size     = 1;
    psort_init_param.min_priority   = ACL_MIN_ENTRY_PRIO;
    psort_init_param.max_priority   = ACL_MAX_ENTRY_PRIO;
    psort_init_param.notif_callback = psort_notification_func;

    if (true == is_table_dynamic) {
        psort_init_param.table_almost_empty_precentage_threshold = PSORT_ALMOST_EMPTY_PERC_DYN;
        psort_init_param.table_almost_full_precentage_threshold  = PSORT_ALMOST_FULL_PERC_DYN;
    } else {
        psort_init_param.table_almost_empty_precentage_threshold = PSORT_ALMOST_EMPTY_PERC_STATIC;
        psort_init_param.table_almost_full_precentage_threshold  = PSORT_ALMOST_FULL_PERC_STATIC;
    }

    sx_status = psort_init(&acl_db_table(table_id).psort_handle, &psort_init_param);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create psort table - %s\n", SX_UTILS_STATUS_MSG(sx_status));
        status = SAI_STATUS_FAILURE;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t delete_psort_table(_In_ uint32_t table_id)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    if (is_init_process) {
        status = __delete_psort_table(table_id);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type          = ACL_RPC_PSORT_TABLE_DELETE;
        rpc_info.args.table_id = table_id;

        status = acl_psort_rpc_call(&rpc_info);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t __delete_psort_table(_In_ uint32_t table_id)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sx_utils_status_t sx_status;
    psort_handle_t    psort_handle;

    SX_LOG_ENTER();

    if (!acl_table_index_check_range(table_id)) {
        SX_LOG_ERR("Attempt to use invalid ACL Table DB index\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    psort_handle = acl_db_table(table_id).psort_handle;

    sx_status = psort_clear_table(psort_handle);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to delete psort table - %s\n", SX_UTILS_STATUS_MSG(sx_status));
        status = SAI_STATUS_FAILURE;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t get_new_psort_offset(_In_ uint32_t                 table_id,
                                         _In_ uint32_t                 entry_id,
                                         _In_ uint32_t                 priority,
                                         _Inout_ sx_acl_rule_offset_t *offset,
                                         _In_ uint32_t                 request_num)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    if (is_init_process) {
        status = __get_new_psort_offset(table_id, entry_id, priority, offset, request_num);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type            = ACL_RPC_PSORT_ENTRY_CREATE;
        rpc_info.args.table_id   = table_id;
        rpc_info.args.entry_id   = entry_id;
        rpc_info.args.entry_prio = priority;
        rpc_info.args.size       = request_num;

        status  = acl_psort_rpc_call(&rpc_info);
        *offset = rpc_info.args.entry_offset;
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t __get_new_psort_offset(_In_ uint32_t                 table_id,
                                           _In_ uint32_t                 entry_id,
                                           _In_ uint32_t                 priority,
                                           _Inout_ sx_acl_rule_offset_t *offset,
                                           _In_ uint32_t                 requested_num)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sx_utils_status_t sx_status;
    psort_handle_t    psort_handle;
    psort_entry_t     psort_entry;

    SX_LOG_ENTER();

    if ((!acl_table_index_check_range(table_id)) || (!acl_entry_index_check_range(entry_id))) {
        SX_LOG_ERR("Attempt to use invalid ACL DB index\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    psort_handle         = acl_db_table(table_id).psort_handle;
    psort_entry.key      = entry_id;
    psort_entry.priority = priority;

    if (acl_db_table(table_id).created_rule_count + requested_num > acl_db_table(table_id).region_size) {
        if (SAI_STATUS_SUCCESS != acl_table_size_increase(table_id, requested_num)) {
            SX_LOG_ERR("Failed to increase a size of psort table\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    sx_status = psort_entry_set(psort_handle, SX_UTILS_CMD_ADD, &psort_entry);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get offset form pSort - %s\n", SX_UTILS_STATUS_MSG(sx_status));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    *offset = psort_entry.index;
out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t release_psort_offset(_In_ uint32_t             table_id,
                                         _In_ uint32_t             priority,
                                         _In_ sx_acl_rule_offset_t offset)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    if (is_init_process) {
        status = __release_psort_offset(table_id, priority, offset);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type              = ACL_RPC_PSORT_ENTRY_DELETE;
        rpc_info.args.table_id     = table_id;
        rpc_info.args.entry_prio   = priority;
        rpc_info.args.entry_offset = offset;

        status = acl_psort_rpc_call(&rpc_info);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t __release_psort_offset(_In_ uint32_t             table_id,
                                           _In_ uint32_t             priority,
                                           _In_ sx_acl_rule_offset_t offset)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sx_utils_status_t sx_status;
    psort_handle_t    psort_handle;
    psort_entry_t     psort_entry;

    SX_LOG_ENTER();

    if (!acl_table_index_check_range(table_id)) {
        SX_LOG_ERR("Attempt to use invalid ACL Table DB index\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    psort_handle         = acl_db_table(table_id).psort_handle;
    psort_entry.priority = priority;
    psort_entry.index    = offset;

    sx_status = psort_entry_set(psort_handle, SX_UTILS_CMD_DELETE, &psort_entry);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to remove index from psort - %s\n", SX_UTILS_STATUS_MSG(sx_status));
        status = SAI_STATUS_FAILURE;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t update_rules_offsets(_In_ const psort_shift_param_t *shift_param, _In_ uint32_t acl_table_index)
{
    sx_status_t          sx_status;
    sx_api_handle_t     *sdk_api_handle = NULL;
    sx_acl_region_id_t   region_id;
    sx_acl_rule_offset_t old_offset;
    sx_acl_rule_offset_t new_offset;
    uint32_t             acl_entry_index;

    SX_LOG_ENTER();

    region_id       = acl_db_table(acl_table_index).region_id;
    acl_entry_index = (uint32_t)shift_param->key;
    old_offset      = shift_param->old_index;
    new_offset      = shift_param->new_index;

#ifndef _WIN32
    sdk_api_handle = pthread_getspecific(pthread_key);
#endif
    if (NULL == sdk_api_handle) {
        SX_LOG_ERR("Failed to get sdk_api_handle for thread\n");
        sx_status = SX_STATUS_ERROR;
        goto out;
    }

    if (acl_db_entry(acl_entry_index).offset != old_offset) {
        SX_LOG_ERR("ACL DB Rule offset is not equal to pSort offset\n");
        sx_status = SX_STATUS_ERROR;
        goto out;
    }

    if (acl_db_table(acl_table_index).region_size <= new_offset) {
        SX_LOG_ERR("New offset from pSort is bigger then sx_region size\n");
        sx_status = SX_STATUS_ERROR;
        goto out;
    }

    sx_status = sx_api_acl_rule_block_move_set(*sdk_api_handle, region_id, old_offset, 1, new_offset);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to move rule block\n");
        goto out;
    }

    acl_db_entry(acl_entry_index).offset = new_offset;

out:
    SX_LOG_EXIT();
    return sdk_to_sai(sx_status);
}

static void acl_psort_optimize_table(_In_ uint32_t table_index)
{
    sx_utils_status_t status;
    psort_handle_t    psort_handle;
    boolean_t         is_complete;

    SX_LOG_ENTER();

    if (false == acl_db_table(table_index).is_used) {
        SX_LOG_NTC("Attempt to use deleted ACL Table DB index - %u\n", table_index);
        SX_LOG_EXIT();
        return;
    }

    acl_table_write_lock(table_index);

    if (0 == acl_db_table(table_index).created_rule_count) {
        goto out;
    }

    psort_handle = acl_db_table(table_index).psort_handle;

    is_complete = false;
    while (!is_complete) {
        status = psort_background_worker(psort_handle, &is_complete);
        if (SX_UTILS_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to run psort bg\n");
            break;
        }
    }

out:
    acl_table_unlock(table_index);
    SX_LOG_EXIT();
}

static sai_status_t acl_enqueue_table(_In_ uint32_t table_index)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

#ifndef _WIN32
    if (ACL_QUEUE_INVALID_HANDLE == fg_mq) {
        fg_mq = mq_open(ACL_QUEUE_NAME, O_WRONLY | O_NONBLOCK);
        if (ACL_QUEUE_INVALID_HANDLE == fg_mq) {
            SX_LOG_ERR("Failed to open mq - %s\n", strerror(errno));
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    acl_db_table(table_index).queued++;

    if (-1 == mq_send(fg_mq, (const char*)&table_index,
                      sizeof(table_index), ACL_QUEUE_DEF_MSG_PRIO)) {
        if (EAGAIN == errno) {
            SX_LOG_NTC("Failed to enqueue table %d - queue is full\n", table_index);
            acl_db_table(table_index).queued--;
            status = SAI_STATUS_SUCCESS;
            goto out;
        } else {
            SX_LOG_ERR("Failed to enqueue table %d - %s\n", table_index, strerror(errno));
            acl_db_table(table_index).queued--;
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

out:
#endif
    SX_LOG_EXIT();
    return status;
}

static sai_status_t acl_db_insert_entries(_In_ uint32_t table_index,
                                          _In_ uint32_t entry_index,
                                          _In_ uint32_t entry_count)
{
    sai_status_t status           = SAI_STATUS_SUCCESS;
    uint32_t     last_entry_index = ACL_INVALID_DB_INDEX;
    uint32_t     new_entry_index;
    uint32_t     ii;

    SX_LOG_ENTER();

    assert(entry_count != 0 && entry_index != ACL_INVALID_DB_INDEX);

    if (ACL_INVALID_DB_INDEX != acl_db_entry(entry_index).next) {
        last_entry_index = acl_db_entry(entry_index).next;
    }

    for (ii = 0; ii < entry_count; ii++) {
        if (SAI_STATUS_SUCCESS != acl_db_find_entry_free_index(&new_entry_index)) {
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        acl_db_table(table_index).created_rule_count++;

        acl_db_entry(new_entry_index).prev = entry_index;
        acl_db_entry(entry_index).next     = new_entry_index;
        entry_index                        = new_entry_index;
    }

    if (ACL_INVALID_DB_INDEX != last_entry_index) {
        acl_db_entry(last_entry_index).prev = new_entry_index;
        acl_db_entry(new_entry_index).next  = last_entry_index;
    } else {
        acl_db_entry(new_entry_index).next = ACL_INVALID_DB_INDEX;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static void acl_db_add_entry_to_table(_In_ uint32_t table_index, _In_ uint32_t new_entry_index)
{
    uint32_t       *head_entry_index = &acl_db_table(table_index).head_entry_index;
    acl_table_db_t *table            = &acl_db_table(table_index);
    acl_entry_db_t *new_entry        = &acl_db_entry(new_entry_index);
    acl_entry_db_t *table_head_entry;

    SX_LOG_ENTER();

    if (ACL_INVALID_DB_INDEX == *head_entry_index) {
        *head_entry_index = new_entry_index;
        new_entry->next   = ACL_INVALID_DB_INDEX;
        new_entry->prev   = ACL_INVALID_DB_INDEX;
    } else {
        table_head_entry       = &acl_db_entry(*head_entry_index);
        new_entry->next        = *head_entry_index;
        new_entry->prev        = ACL_INVALID_DB_INDEX;
        table_head_entry->prev = new_entry_index;

        *head_entry_index = new_entry_index;
    }

    table->created_rule_count++;
    SX_LOG_EXIT();
}

static void acl_db_remove_entry_from_table(_In_ uint32_t table_index,
                                           _In_ uint32_t entry_index,
                                           _In_ uint32_t entry_count)
{
    acl_table_db_t *table;
    acl_entry_db_t *entry;
    uint32_t        prev_entry_index, ii;

    SX_LOG_ENTER();

    assert(ACL_INVALID_DB_INDEX != table_index && ACL_INVALID_DB_INDEX != entry_index);

    if (0 == entry_count) {
        goto out;
    }

    table            = &acl_db_table(table_index);
    prev_entry_index = acl_db_entry(entry_index).prev;

    for (ii = 0; ii < entry_count; ii++) {
        if (ACL_INVALID_DB_INDEX == entry_index) {
            SX_LOG_ERR("ACL DB is corrupted\n");
            goto out;
        }

        entry       = &acl_db_entry(entry_index);
        entry_index = entry->next;

        entry->is_used = false;
        entry->next    = ACL_INVALID_DB_INDEX;
        entry->prev    = ACL_INVALID_DB_INDEX;

        acl_db_table(table_index).created_rule_count--;
    }

    if (ACL_INVALID_DB_INDEX == prev_entry_index) {
        table->head_entry_index = entry_index;
    } else {
        acl_db_entry(prev_entry_index).next = entry_index;

        if (ACL_INVALID_DB_INDEX != entry_index) {
            acl_db_entry(entry_index).prev = prev_entry_index;
        }
    }

out:
    SX_LOG_EXIT();
}

static sai_status_t acl_create_entry_object_id(_Out_ sai_object_id_t *entry_oid,
                                               _In_ uint32_t          entry_index,
                                               _In_ uint16_t          table_index)
{
    sai_status_t status;
    uint8_t      table_data[EXTENDED_DATA_SIZE] = {0};

    SX_LOG_ENTER();
    assert(entry_oid != NULL);
    assert(sizeof(uint16_t) <= EXTENDED_DATA_SIZE);

    *(uint16_t*)(&table_data) = table_index;

    status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_index, table_data, entry_oid);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t acl_get_entries_offsets(_In_ uint32_t                 entry_index,
                                            _In_ uint32_t                 entry_number,
                                            _Inout_ sx_acl_rule_offset_t *offsets_list)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii;

    SX_LOG_ENTER();
    assert(offsets_list != NULL);

    for (ii = 0; ii < entry_number; ii++) {
        if (ACL_INVALID_DB_INDEX == entry_index) {
            SX_LOG_ERR("Failed to get offset list for rules from ACL Entry DB\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        offsets_list[ii] = acl_db_entry(entry_index).offset;
        entry_index      = acl_db_entry(entry_index).next;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static void psort_background_thread(void *arg)
{
#ifndef _WIN32
    sx_status_t     sx_status;
    mqd_t           bg_mq;
    struct timespec tm;
    uint32_t        mq_message;
    uint32_t        last_used_table;

    SX_LOG_ENTER();

    acl_cond_mutex_lock();
    while (false == sai_acl_db->acl_settings_tbl->background_thread_start_flag) {
        pthread_cond_wait(&sai_acl_db->acl_settings_tbl->background_thread_init_cond, &acl_cond_mutex);
    }
    acl_cond_mutex_unlock();

    /* cond is triggered from resource_deinit() */
    if (true == sai_acl_db->acl_settings_tbl->bg_stop) {
        goto out;
    }

    sx_status = sx_api_open(sai_log_cb, &psort_sx_api);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Can't open connection to SDK from pSort thread - %s.\n", SX_STATUS_MSG(sx_status));
        goto out;
    }

    if (0 != pthread_setspecific(pthread_key, &psort_sx_api)) {
        SX_LOG_ERR("Failed to call pthread_setspecific\n");
        goto out;
    }

    bg_mq = mq_open(ACL_QUEUE_NAME, O_RDONLY);
    if (ACL_QUEUE_INVALID_HANDLE == bg_mq) {
        SX_LOG_ERR("Failed to open acl bg_mq");
        goto out;
    }

    last_used_table = ACL_INVALID_DB_INDEX;

    while (false == sai_acl_db->acl_settings_tbl->bg_stop) {
        if (ACL_INVALID_DB_INDEX == last_used_table) {
            if (-1 == mq_receive(bg_mq, (char*)&mq_message, sizeof(mq_message), NULL)) {
                SX_LOG_ERR("Failed to read from mq in blocked mode\n");
            }
        } else {
            clock_gettime(CLOCK_REALTIME, &tm);
            tm.tv_sec += ACL_QUEUE_TIMEOUT;

            if (-1 == mq_timedreceive(bg_mq, (char*)&mq_message, sizeof(mq_message), NULL, &tm)) {
                if (ETIMEDOUT == errno) {
                    acl_psort_optimize_table(last_used_table);
                    last_used_table = ACL_INVALID_DB_INDEX;
                    continue;
                }
            }
        }

        if (ACL_BCKG_THREAD_EXIT_MSG == mq_message) {
            break;
        }

        if (!acl_table_index_check_range(mq_message)) {
            SX_LOG_ERR("Attempt to use invalid ACL Table DB index - %u\n", mq_message);
            continue;
        }

        assert(acl_db_table(mq_message).queued > 0);
        acl_db_table(mq_message).queued--;

        if (ACL_INVALID_DB_INDEX == last_used_table) {
            last_used_table = mq_message;
            continue;
        }

        if (mq_message != last_used_table) {
            acl_psort_optimize_table(last_used_table);
            last_used_table = mq_message;
        }
    }

    mq_close(bg_mq);
    mq_unlink(ACL_QUEUE_NAME);

out:
    if (psort_sx_api != SX_API_INVALID_HANDLE) {
        sx_status = sx_api_close(&psort_sx_api);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("API close failed.\n");
        }
    }

#endif /* ifndef _WIN32 */
    SX_LOG_EXIT();
}

static void psort_rpc_thread(void *arg)
{
#ifndef _WIN32
    sx_status_t        sx_status;
    sai_status_t       status;
    acl_rpc_info_t     rpc_info;
    int                rpc_socket;
    struct sockaddr_un cl_sockaddr;
    socklen_t          sockaddr_len;
    ssize_t            bytes;
    bool               exit_request = false;

    SX_LOG_ENTER();

    status = create_rpc_server(&rpc_socket);
    if (status != SAI_STATUS_SUCCESS) {
        return;
    }

    acl_cond_mutex_lock();
    while (false == sai_acl_db->acl_settings_tbl->rpc_thread_start_flag) {
        pthread_cond_wait(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond, &acl_cond_mutex);
    }
    acl_cond_mutex_unlock();

    /* cond is triggered from resource_deinit() */
    if (true == sai_acl_db->acl_settings_tbl->bg_stop) {
        goto out;
    }

    sx_status = sx_api_open(sai_log_cb, &rpc_sx_api);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Can't open connection to SDK from pSort thread - %s.\n", SX_STATUS_MSG(sx_status));
        goto out;
    }

    if (0 != pthread_setspecific(pthread_key, &rpc_sx_api)) {
        SX_LOG_ERR("Failed to call pthread_setspecific\n");
        goto out;
    }

    sockaddr_len = sizeof(cl_sockaddr);

    while (false == exit_request) {
        bytes = recvfrom(rpc_socket,
                         (void*)&rpc_info,
                         sizeof(rpc_info),
                         0,
                         (struct sockaddr*)&cl_sockaddr,
                         &sockaddr_len);
        if (bytes != sizeof(rpc_info)) {
            SX_LOG_ERR("Failed to recv data from the socket - %s\n", strerror(errno));
            goto out;
        }

        switch (rpc_info.type) {
        case ACL_RPC_PSORT_TABLE_INIT:
            status = __init_psort_table(rpc_info.args.table_id, rpc_info.args.table_is_dynamic, rpc_info.args.size);
            break;

        case ACL_RPC_PSORT_TABLE_DELETE:
            status = __delete_psort_table(rpc_info.args.table_id);
            break;

        case ACL_RPC_PSORT_ENTRY_CREATE:
            status = __get_new_psort_offset(
                rpc_info.args.table_id,
                rpc_info.args.entry_id,
                rpc_info.args.entry_prio,
                &rpc_info.args.entry_offset,
                rpc_info.args.size);
            break;

        case ACL_RPC_PSORT_ENTRY_DELETE:
            status = __release_psort_offset(rpc_info.args.table_id,
                                            rpc_info.args.entry_prio,
                                            rpc_info.args.entry_offset);
            break;

        case ACL_RPC_TERMINATE_THREAD:
            SX_LOG_NTC("Received exit message for rpc thread\n");
            exit_request = true;
            status       = SAI_STATUS_SUCCESS;
            break;

        default:
            SX_LOG_ERR("Attempt to make rpc with undefined type\n");
            status = SAI_STATUS_FAILURE;
        }

        rpc_info.status = status;

        bytes =
            sendto(rpc_socket, (void*)&rpc_info, sizeof(rpc_info), 0, (struct sockaddr*)&cl_sockaddr, sockaddr_len);
        if (bytes != sizeof(rpc_info)) {
            SX_LOG_ERR("Failed to send data througn the socket - %s\n", strerror(errno));
            goto out;
        }
    }

out:
    close(rpc_socket);
    unlink(ACL_RPC_SV_SOCKET_ADDR);

    if (rpc_sx_api != SX_API_INVALID_HANDLE) {
        sx_status = sx_api_close(&rpc_sx_api);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("API close failed.\n");
        }
    }

    SX_LOG_EXIT();
#endif /* ifndef _WIN32 */
}

static sai_status_t mlnx_acl_pbs_get_simple_map_index(_In_ const sx_port_id_t *ports,
                                                      _In_ uint32_t            ports_number,
                                                      _Inout_ pbs_index_t     *pbs_index)
{
    uint32_t    port_index;
    pbs_index_t pbs_map_index;

    assert(ports != NULL && pbs_index != NULL);

    if (g_sai_db_ptr->ports_number == ports_number) {
        pbs_map_index.is_simple = true;
        pbs_map_index.index     = ACL_PBS_MAP_FLOOD_INDEX;

        *pbs_index = pbs_map_index;
        return SAI_STATUS_SUCCESS;
    } else if (1 == ports_number) {
        if (SAI_STATUS_SUCCESS != mlnx_acl_pbs_map_port_to_index(ports[0], &port_index)) {
            return SAI_STATUS_FAILURE;
        }

        pbs_map_index.is_simple = true;
        pbs_map_index.index     = port_index;

        *pbs_index = pbs_map_index;
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_FAILURE;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_acl_pbs_get_map_index_and_key(_In_ const sx_port_id_t *ports,
                                                       _In_ uint32_t            ports_number,
                                                       _Out_ pbs_index_t       *pbs_index,
                                                       _Out_ acl_pbs_map_key_t *pbs_key)
{
    sai_status_t      status        = SAI_STATUS_SUCCESS;
    pbs_index_t       pbs_map_index = ACL_INVALID_PBS_INDEX, free_pbs_map_index = ACL_INVALID_PBS_INDEX;
    acl_pbs_map_key_t pbs_map_key   = ACL_PBS_MAP_EMPTY_KEY;
    uint32_t          ii;

    assert(ports != NULL && pbs_index != NULL && pbs_key != NULL);

    status = mlnx_acl_pbs_map_ports_to_key(ports, ports_number, &pbs_map_key);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    pbs_map_index.is_simple = false;

    for (ii = 0; ii < g_sai_acl_db_pbs_map_size; ii++) {
        pbs_map_index.index = mlnx_acl_pbs_map_key_to_index(pbs_map_key, ii);

        if (pbs_map_key == acl_db_pbs(pbs_map_index).key) {
            break;
        }

        if ((0 == (acl_db_pbs(pbs_map_index).ref_counter)) &&
            (false == is_pbs_index_valid(free_pbs_map_index))) {
            free_pbs_map_index = pbs_map_index;
        }

        if (ACL_PBS_MAP_EMPTY_KEY == acl_db_pbs(pbs_map_index).key) {
            if (is_pbs_index_valid(free_pbs_map_index)) {
                pbs_map_index = free_pbs_map_index;
            }

            break;
        }
    }

    if ((g_sai_acl_db_pbs_map_size == ii) &&
        (is_pbs_index_valid(free_pbs_map_index) == false)) {
        SX_LOG_ERR("ACL PBS Map is full");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    *pbs_index = pbs_map_index;
    *pbs_key   = pbs_map_key;

out:
    return status;
}

static sai_status_t mlnx_acl_pbs_entry_create_or_get(_In_ sx_port_id_t       *ports,
                                                     _In_ uint32_t            ports_number,
                                                     _Inout_ sx_acl_pbs_id_t *pbs_id,
                                                     _Inout_ pbs_index_t     *pbs_index)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_status_t        sx_status;
    sx_acl_pbs_entry_t sx_pbs_entry;
    sx_acl_pbs_id_t    sx_pbs_id;
    sx_swid_t          swid_id       = 0;
    pbs_index_t        pbs_map_index = ACL_INVALID_PBS_INDEX;
    acl_pbs_map_key_t  pbs_map_key   = ACL_PBS_MAP_EMPTY_KEY;

    SX_LOG_ENTER();

    assert(ports != NULL && pbs_id != NULL && pbs_index != NULL);

    status = mlnx_acl_pbs_get_simple_map_index(ports, ports_number, &pbs_map_index);
    if (status != SAI_STATUS_SUCCESS) {
        status = mlnx_acl_pbs_get_map_index_and_key(ports, ports_number, &pbs_map_index, &pbs_map_key);
        if (status != SAI_STATUS_SUCCESS) {
            goto out;
        }
    }

    if (0 != (acl_db_pbs(pbs_map_index).ref_counter)) {
        acl_db_pbs_ptr(pbs_map_index)->ref_counter++;
        sx_pbs_id = acl_db_pbs(pbs_map_index).pbs_id;
    } else {
        memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));
        sx_pbs_entry.entry_type =
            (ports_number == 1) ? SX_ACL_PBS_ENTRY_TYPE_UNICAST : SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
        sx_pbs_entry.port_num  = ports_number;
        sx_pbs_entry.log_ports = ports;

        sx_status =
            sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_ADD, swid_id, &sx_pbs_entry, &sx_pbs_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to create PBS %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        acl_db_pbs_ptr(pbs_map_index)->key         = pbs_map_key;
        acl_db_pbs_ptr(pbs_map_index)->pbs_id      = sx_pbs_id;
        acl_db_pbs_ptr(pbs_map_index)->ref_counter = 1;
    }

    *pbs_id    = sx_pbs_id;
    *pbs_index = pbs_map_index;

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_pbs_entry_delete(pbs_index_t pbs_index)
{
    sx_status_t     sx_status;
    sai_status_t    status = SAI_STATUS_SUCCESS;
    sx_swid_t       swid   = 0;
    sx_acl_pbs_id_t pbs_id;

    SX_LOG_ENTER();

    assert(is_pbs_index_valid(pbs_index));

    if (1 == acl_db_pbs(pbs_index).ref_counter) {
        pbs_id = acl_db_pbs(pbs_index).pbs_id;

        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_DELETE, swid, NULL, &pbs_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to delete PBS Entry  %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    acl_db_pbs_ptr(pbs_index)->ref_counter--;

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_pbs_map_port_to_index(_In_ sx_port_id_t port, _Out_ uint32_t  *index)
{
    sai_status_t status = SAI_STATUS_FAILURE;
    uint32_t     ii;

    SX_LOG_ENTER();

    assert(index != NULL);

    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        if (g_sai_db_ptr->ports_db[ii].logical == port) {
            *index = ii;
            status = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

    SX_LOG_ERR("Couldn't find port id in SAI port DB\n");

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_pbs_map_ports_to_key(_In_ const sx_port_id_t   *ports,
                                                  _In_ uint32_t              port_number,
                                                  _Inout_ acl_pbs_map_key_t *pbs_map_key)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    acl_pbs_map_key_t key;
    uint32_t          port_index;
    uint32_t          ii;

    SX_LOG_ENTER();

    assert(ports != NULL && pbs_map_key != NULL);

    key = 0;
    for (ii = 0; ii < port_number; ii++) {
        status = mlnx_acl_pbs_map_port_to_index(ports[ii], &port_index);
        if (SAI_STATUS_SUCCESS != status) {
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        key |= UINT64_C(1) << port_index;
    }

    *pbs_map_key = key;
out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_pbs_map_get_ports(_In_ pbs_index_t      pbs_index,
                                               _Inout_ sx_port_id_t *ports,
                                               _Inout_ uint32_t     *port_number)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    acl_pbs_map_key_t key;
    sx_port_id_t     *pbs_ports = NULL;
    uint32_t          pbs_port_number, port_index;

    SX_LOG_ENTER();

    assert(pbs_index.index != ACL_INVALID_DB_INDEX && ports != NULL && port_number != NULL);

    if (0 == acl_db_pbs(pbs_index).ref_counter) {
        SX_LOG_ERR("Failed to get ports from ACL PBS Entry - entry is deleted\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    pbs_ports = (sx_port_id_t*)malloc(sizeof(sx_port_id_t) * g_sai_db_ptr->ports_number);
    if (NULL == pbs_ports) {
        SX_LOG_ERR("No memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    pbs_port_number = 0;
    if (true == pbs_index.is_simple) {
        if (ACL_PBS_MAP_FLOOD_INDEX == pbs_index.index) {
            pbs_port_number = g_sai_db_ptr->ports_number;
            for (port_index = 0; port_index < g_sai_db_ptr->ports_number; port_index++) {
                pbs_ports[port_index] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[port_index].logical;
            }
        } else {
            pbs_port_number = 1;
            pbs_ports[0]    = g_sai_db_ptr->ports_db[pbs_index.index].logical;
        }
    } else {
        key        = acl_db_pbs(pbs_index).key;
        port_index = 0;
        while (key) {
            if (key & 1) {
                pbs_ports[pbs_port_number] = g_sai_db_ptr->ports_db[port_index].logical;
                pbs_port_number++;
            }

            key >>= 1;
            port_index++;
        }
    }

    if (*port_number < pbs_port_number) {
        SX_LOG_ERR("Failed to get ports from ACL PBS Entry - Ports array is to small - (%d) need - (%d)\n",
                   *port_number,
                   pbs_port_number);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    memcpy(ports, pbs_ports, sizeof(sx_port_id_t) * pbs_port_number);
    *port_number = pbs_port_number;

out:
    free(pbs_ports);
    SX_LOG_EXIT();
    return status;
}

static uint32_t mlnx_acl_pbs_map_key_to_index(_In_ acl_pbs_map_key_t key, uint32_t step)
{
    return (key + step * key) % g_sai_acl_db_pbs_map_size;
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
