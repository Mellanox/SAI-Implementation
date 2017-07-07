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

#define IP_TYPE_KEY_SIZE              4
#define IP_FRAG_KEY_TYPE_SIZE         2
#define SX_FLEX_ACL_MAX_FIELDS_IN_KEY RM_API_ACL_MAX_FIELDS_IN_KEY
#define ACL_MAX_NUM_OF_ACTIONS        20
#define ACL_TABLE_SIZE_INC_PERCENT    0.2
#define ACL_TABLE_SIZE_DEC_PERCENT    0.2
#define ACL_TABLE_SIZE_MIN_DELTA      16
#define ACL_DEFAULT_ENTRY_PRIO        ACL_MIN_ENTRY_PRIO
#define ACL_INVALID_PORT_PBS_INDEX    {.index = ACL_INVALID_DB_INDEX}
#define ACL_INVALID_LAG_PBS_INDEX     ACL_INVALID_DB_INDEX
#define ACL_INVALID_ENTRY_REDIRECT    {.redirect_type = ACL_ENTRY_REDIRECT_TYPE_EMPTY}
#define ACL_ENTRY_PORT_PBS(index) {.type = ACL_ENTRY_PBS_TYPE_PORT, .pbs_index = index}
#define ACL_ENTRY_LAG_PBS(index)  {.type = ACL_ENTRY_PBS_TYPE_LAG, .lag_pbs_index = index}

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
#define ACL_MAX_FLEX_KEY_COUNT   (SAI_ACL_ENTRY_ATTR_FIELD_END - SAI_ACL_ENTRY_ATTR_FIELD_START + 1)

#define ACL_PBS_MAP_FLOOD_INDEX 64
#define ACL_PBS_MAP_EMPTY_KEY   0

#define ACL_RANGE_INVALID_TYPE (sai_acl_range_type_t)(-1)
#define ACL_RANGE_MAX_COUNT    (RM_API_ACL_PORT_RANGES_MAX)

#define ACL_RPC_SV_SOCKET_ADDR "/tmp/sai_acl_rpc_socket"

#define ACL_INVALID_LAG_ID 0

#define ACL_IP_IDENT_FIELD_START_OFFSET 4

#define sai_acl_db (g_sai_acl_db_ptr)

#define acl_sai_stage_to_sx_dir(stage) \
    ((stage == SAI_ACL_STAGE_INGRESS) ? \
     SX_ACL_DIRECTION_INGRESS :       \
     SX_ACL_DIRECTION_EGRESS)

#define acl_table_index_check_range(table_index)     ((table_index < ACL_MAX_TABLE_NUMBER) ? true : false)
#define acl_entry_index_check_range(entry_index)     ((entry_index < ACL_MAX_ENTRY_NUMBER) ? true : false)
#define acl_counter_index_check_range(counter_index) ((counter_index < ACL_MAX_COUNTER_NUM) ? true : false)
#define acl_group_index_check_range(group_index)     ((group_index < ACL_GROUP_NUMBER) ? true : false)
#define is_acl_index_invalid(acl_index)              (ACL_INVALID_DB_INDEX == acl_index.acl_db_index)

#define acl_db_table(table_index)     sai_acl_db->acl_table_db[(table_index)]
#define acl_db_entry(entry_index)     sai_acl_db->acl_entry_db[(entry_index)]
#define acl_db_entry_ptr(entry_index) & sai_acl_db->acl_entry_db[(entry_index)]

#define acl_db_port_list(port_list_index) sai_acl_db->acl_port_list_db[(port_list_index)]
#define acl_db_pbs(pbs_index) \
    ((pbs_index.is_simple) ?                         \
     sai_acl_db->acl_pbs_map_db[(pbs_index.index)] : \
     sai_acl_db->acl_port_comb_pbs_map_db[(pbs_index.index)])
#define acl_db_lag_pbs(lag_pbs_index)          (sai_acl_db->acl_lag_pbs_db[lag_pbs_index])
#define acl_lag_pbs_index_to_sx(lag_pbs_index) (g_sai_db_ptr->ports_db[MAX_PORTS + lag_pbs_index].logical)
#define acl_flood_pbs (sai_acl_db->acl_settings_tbl->flood_pbs)
#define acl_db_vlan_group(index) (sai_acl_db->acl_vlan_groups_db[index])

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
/* #define is_entry_redirect_pbs_valid(redirect_data)     ((redirect_data).redirect_type != ACL_ENTRY_REDIRECT_TYPE_EMPTY) */
#define is_entry_redirect_pbs_type_lag(redirect_data)  ((redirect_data).pbs_type == ACL_ENTRY_PBS_TYPE_LAG)
#define is_entry_redirect_pbs_type_port(redirect_data) ((redirect_data).pbs_type == ACL_ENTRY_PBS_TYPE_PORT)

#define ACL_FOREACH_ENTRY_IN_TABLE(table_index, entry_index)       \
    for (entry_index = acl_db_table(table_index).head_entry_index; \
         ACL_INVALID_DB_INDEX != entry_index; entry_index = acl_db_entry(entry_index).next)

#define ACL_FOREACH_ENTRY(enrty, entry_index, entry_count)              \
    for (; (entry_count > 0) && (ACL_INVALID_DB_INDEX != entry_index) && \
         (enrty = acl_db_entry_ptr(entry_index));                      \
         entry_count--, entry_index = (entry_count > 0) ? enrty->next : entry_index)

#define acl_table_write_lock(table_id) cl_plock_excl_acquire(&acl_db_table(table_id).lock)
#define acl_table_read_lock(table_id)  cl_plock_acquire(&acl_db_table(table_id).lock)
#define acl_table_unlock(table_id)     cl_plock_release(&acl_db_table(table_id).lock)

#define MLNX_SAI_STRUCT_MEMBER_SIZE(type, member) sizeof(((type*)0)->member)

#define MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, type) \
    (mlnx_acl_single_key_field_info_t) \
    {.key_id     = sx_key_id, \
     .key_size   = MLNX_SAI_STRUCT_MEMBER_SIZE(sx_acl_key_fields_t, sx_key_type), \
     .field_type = type }

#define MLNX_ACL_ENTRY_KEY_LIST(...) {__VA_ARGS__}
#define MLNX_ACL_MULTI_KEY_FIELD_INFO(sx_key_count, sx_key_list, type) \
    (mlnx_acl_multi_key_field_info_t) \
    {.key_count  = sx_key_count,    \
     .key_list   = (sx_acl_key_t[sx_key_count])sx_key_list,     \
     .field_type = type }

#define MLNX_ACL_FIELD_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_EMPTY)
#define MLNX_ACL_FIELD_L2_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_EMPTY)
#define MLNX_ACL_FIELD_INNER_VLAN_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID)
#define MLNX_ACL_FIELD_IP_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_IP)
#define MLNX_ACL_FIELD_IPV4_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_IPV4)
#define MLNX_ACL_FIELD_IPV6_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_IPV6)
#define MLNX_ACL_FIELD_INNER_IPV4_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_IPV4)
#define MLNX_ACL_FIELD_INNER_IPV6_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_IPV6)
#define MLNX_ACL_FIELD_L4_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_L4)
#define MLNX_ACL_FIELD_TCP_DEFINE(sx_key_id, sx_key_type) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_TCP)

typedef enum _mlnx_acl_field_type_t {
    MLNX_ACL_FIELD_TYPE_INVALID            = 0,
    MLNX_ACL_FIELD_TYPE_EMPTY              = (1 << 0),
    MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID   = (1 << 1),
    MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID = (1 << 2),
    MLNX_ACL_FIELD_TYPE_IP                 = (1 << 3),
    MLNX_ACL_FIELD_TYPE_NON_IP             = (1 << 4),
    MLNX_ACL_FIELD_TYPE_IPV4               = (1 << 5),
    MLNX_ACL_FIELD_TYPE_NON_IPV4           = (1 << 6),
    MLNX_ACL_FIELD_TYPE_IPV6               = (1 << 7),
    MLNX_ACL_FIELD_TYPE_ARP                = (1 << 8),
    MLNX_ACL_FIELD_TYPE_INNER_IPV4         = (1 << 9),
    MLNX_ACL_FIELD_TYPE_INNER_IPV6         = (1 << 10),
    MLNX_ACL_FIELD_TYPE_L4                 = (1 << 11),
    MLNX_ACL_FIELD_TYPE_TCP                = (1 << 12),
} mlnx_acl_field_type_t;
typedef struct _mlnx_acl_sai_single_key_field_info_t {
    sx_acl_key_t          key_id;
    uint32_t              key_size;
    mlnx_acl_field_type_t field_type;
} mlnx_acl_single_key_field_info_t;
typedef struct _mlnx_acl_sai_multiple_key_field_info_t {
    uint32_t              key_count;
    sx_acl_key_t         *key_list;
    mlnx_acl_field_type_t field_type;
} mlnx_acl_multi_key_field_info_t;
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
typedef enum _acl_port_stat_type {
    ACL_PORT_REFS_SRC,
    ACL_PORT_REFS_DST,
    ACL_PORT_REFS_PBS,
    ACL_PORT_REFS_MAX = ACL_PORT_REFS_PBS
} acl_port_stat_type_t;

static const acl_bind_point_type_list_t default_bind_point_type_list =
{.count = 3,
 .types = {SAI_ACL_BIND_POINT_TYPE_PORT,
           SAI_ACL_BIND_POINT_TYPE_LAG,
           SAI_ACL_BIND_POINT_TYPE_VLAN}
};
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static cl_thread_t psort_thread;
static cl_thread_t rpc_thread;
#ifndef _WIN32
static pthread_key_t      pthread_key;
static mqd_t              fg_mq = ACL_QUEUE_INVALID_HANDLE;
static struct sockaddr_un rpc_sv_sockaddr;
#endif
static sx_api_handle_t      psort_sx_api                  = SX_API_INVALID_HANDLE, rpc_sx_api = SX_API_INVALID_HANDLE;
static int                  rpc_cl_socket                 = -1;
static bool                 is_init_process               = false;
const sai_acl_action_type_t mlnx_acl_action_list_common[] = {
    SAI_ACL_ACTION_TYPE_PACKET_ACTION,
    SAI_ACL_ACTION_TYPE_COUNTER,
    SAI_ACL_ACTION_TYPE_SET_POLICER,
    SAI_ACL_ACTION_TYPE_SET_TC,
    SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR,
    SAI_ACL_ACTION_TYPE_SET_INNER_VLAN_ID,
    SAI_ACL_ACTION_TYPE_SET_INNER_VLAN_PRI,
    SAI_ACL_ACTION_TYPE_SET_OUTER_VLAN_ID,
    SAI_ACL_ACTION_TYPE_SET_OUTER_VLAN_PRI,
    SAI_ACL_ACTION_TYPE_SET_SRC_MAC,
    SAI_ACL_ACTION_TYPE_SET_DST_MAC,
    SAI_ACL_ACTION_TYPE_SET_DSCP,
    SAI_ACL_ACTION_TYPE_SET_ECN,
    SAI_ACL_ACTION_TYPE_SET_ACL_META_DATA,
};
const sai_acl_action_type_t mlnx_acl_action_list_ingress[] = {
    SAI_ACL_ACTION_TYPE_REDIRECT,
    SAI_ACL_ACTION_TYPE_REDIRECT_LIST,
    SAI_ACL_ACTION_TYPE_FLOOD,
    SAI_ACL_ACTION_TYPE_MIRROR_INGRESS,
};
const sai_acl_action_type_t mlnx_acl_action_list_egress[] = {
    SAI_ACL_ACTION_TYPE_MIRROR_EGRESS,
};
const uint32_t              mlnx_acl_action_list_common_count  = ARRAY_SIZE(mlnx_acl_action_list_common);
const uint32_t              mlnx_acl_action_list_ingress_count = ARRAY_SIZE(mlnx_acl_action_list_ingress);
const uint32_t              mlnx_acl_action_list_egress_count  = ARRAY_SIZE(mlnx_acl_action_list_egress);

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

static sai_status_t mlnx_set_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ const sai_attribute_t *attr);
static sai_status_t mlnx_get_acl_entry_attribute(_In_ sai_object_id_t   acl_entry_id,
                                                 _In_ uint32_t          attr_count,
                                                 _Out_ sai_attribute_t *attr_list);
static sai_status_t mlnx_delete_acl_counter(_In_ sai_object_id_t acl_counter_id);
static sai_status_t mlnx_delete_acl_table(_In_ sai_object_id_t acl_table_id);
static sai_status_t mlnx_delete_acl_entry(_In_ sai_object_id_t acl_entry_id);
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
static sai_status_t mlnx_acl_table_fields_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_table_range_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_acl_entry_tos_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_acl_entry_vlan_tags_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_acl_entry_ip_ident_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_acl_entry_range_list_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_acl_entry_ip_ident_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_acl_entry_priority_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_acl_entry_field_set(_In_ const sai_object_key_t      *key,
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
static sai_status_t mlnx_acl_entry_packet_action_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_acl_counter_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
static sai_status_t mlnx_acl_entry_ports_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
static void mlnx_acl_single_field_key_to_sai(_In_ sai_acl_entry_attr_t          attr_id,
                                             _Out_ sai_attribute_value_t       *value,
                                             _In_ const sx_flex_acl_key_desc_t *sx_key,
                                             _In_ uint32_t                      key_size);
static sai_status_t mlnx_acl_entry_single_key_field_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_acl_entry_ip_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_acl_entry_ip_type_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_acl_entry_ip_frag_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_acl_entry_port_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_acl_entry_action_redirect_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_acl_entry_out_ports_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_acl_entry_in_ports_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_acl_entry_action_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_acl_entry_action_redirect_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg);
static sai_status_t mlnx_acl_entry_action_vlan_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg);
static sai_status_t fetch_flex_acl_rule_params_to_get(_In_ uint32_t                    acl_table_index,
                                                      _In_ uint32_t                    acl_entry_index,
                                                      _Inout_ sx_flex_acl_flex_rule_t *flex_acl_rule_p);
static sai_status_t fetch_flex_acl_rule_params_to_set(_In_ uint32_t                      acl_table_index,
                                                      _In_ uint32_t                      acl_entry_index,
                                                      _Inout_ sx_flex_acl_flex_rule_t  **rules,
                                                      _Inout_opt_ sx_acl_rule_offset_t **offsets,
                                                      _Inout_opt_ sx_acl_region_id_t    *region_id,
                                                      _Inout_ uint32_t                  *rule_count);
static sai_status_t mlnx_acl_packet_actions_handler(_In_ sai_packet_action_t         packet_action_type,
                                                    _In_ uint16_t                    trap_id,
                                                    _Inout_ sx_flex_acl_flex_rule_t *flex_rule,
                                                    _Inout_ uint8_t                 *flex_action_index);
static sai_status_t mlnx_acl_ip_ident_key_create_or_get(_Out_ sx_acl_key_t *keys);
static sai_status_t mlnx_acl_ip_ident_key_ref_remove();
static sai_status_t mlnx_acl_ip_ident_key_desc_create(_In_ uint16_t                   value,
                                                      _In_ uint16_t                   mask,
                                                      _Inout_ sx_flex_acl_key_desc_t *key_descs,
                                                      _Inout_ uint32_t                key_desc_count);
static sai_status_t mlnx_acl_range_attr_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_acl_group_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_group_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static void acl_table_key_to_str(_In_ sai_object_id_t acl_table_id, _Out_ char *key_str);
static void acl_entry_key_to_str(_In_ sai_object_id_t acl_entry_id, _Out_ char *key_str);
static void acl_range_key_to_str(_In_ sai_object_id_t acl_range_id, _Out_ char *key_str);
static void acl_group_key_to_str(_In_ sai_object_id_t acl_group_id, _Out_ char *key_str);
static void acl_group_member_key_to_str(_In_ sai_object_id_t acl_group_memeber_id, _Out_ char *key_str);
static void mlnx_acl_flex_rule_key_del(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t key_index);
static void mlnx_acl_flex_rule_key_del_by_key_id(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ sx_acl_key_t key_id);
static void mlnx_acl_flex_rule_action_del(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t action_index);
static void mlnx_acl_flex_rule_copy(_Out_ sx_flex_acl_flex_rule_t      *dst_rule,
                                    _In_ const sx_flex_acl_flex_rule_t *src_rule);
static sai_status_t mlnx_acl_flex_rule_free(_In_ sx_flex_acl_flex_rule_t *rule);
static sai_status_t mlnx_acl_flex_rule_list_free(_In_ sx_flex_acl_flex_rule_t *rules, _In_ uint32_t rules_count);
static sai_status_t mlnx_acl_flex_rule_list_init(_Inout_ sx_flex_acl_flex_rule_t **rules,
                                                 _In_ uint32_t                     rules_count,
                                                 _In_ sx_acl_key_type_t            key_type);
static void mlnx_acl_flex_rule_key_find(_In_ const sx_flex_acl_flex_rule_t *rule,
                                        _In_ sx_acl_key_t                   key,
                                        _Out_ uint32_t                     *key_index,
                                        _Out_ bool                         *is_key_present);
static void mlnx_acl_flex_rule_action_find(_In_ const sx_flex_acl_flex_rule_t *rule,
                                           _In_ sx_flex_acl_flex_action_type_t action_type,
                                           _Out_ uint32_t                     *action_index,
                                           _Out_ bool                         *is_action_present);
static sai_status_t mlnx_acl_flex_rules_set_helper(_In_ sx_access_cmd_t                cmd,
                                                   _In_ const sx_acl_key_type_t        key_type,
                                                   _In_ const sx_acl_region_id_t       region_id,
                                                   _In_ sx_acl_rule_offset_t          *offsets_list_p,
                                                   _In_ const sx_flex_acl_flex_rule_t *rules_list_p,
                                                   _In_ uint32_t                       rules_count);
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
static sai_status_t acl_db_find_group_free_index(_Out_ uint32_t *free_index);
static sai_status_t acl_db_find_port_list_free_index(_Out_ uint32_t *free_index);
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
static sai_status_t mlnx_sai_port_to_index(_In_ sai_object_id_t sai_port_id, _Out_ uint32_t *port_index);
static sai_status_t mlnx_sx_port_to_index(_In_ sx_port_log_id_t sx_port_id, _Out_ uint32_t *port_index);
static void mlnx_acl_entry_res_ref_invalidate(_In_ acl_entry_res_refs_t *entry_stats);
static sai_status_t mlnx_acl_entry_res_ref_update(_In_ uint32_t               entry_index,
                                                  _In_ acl_port_stat_type_t   stat_type,
                                                  _In_ const sai_object_id_t *port_list,
                                                  _In_ uint32_t               port_count);
static void mlnx_acl_entry_res_ref_set(_In_ const acl_entry_res_refs_t *entry_stats, _In_ bool add_reference);
static void mlnx_acl_port_list_ref_update(_In_ uint64_t ports_mask, _In_ bool add_reference);
static void mlnx_acl_res_ref_update(_In_ uint32_t res_index, _In_ bool is_lag, _In_ bool add_reference);
static sai_status_t mlnx_acl_sai_port_list_to_mask(_In_ const sai_object_id_t *sai_ports,
                                                   _In_ uint32_t               sai_port_count,
                                                   _In_ uint64_t              *port_mask);
static sai_status_t mlnx_acl_pbs_get_simple_map_index(_In_ const sx_port_id_t  *ports,
                                                      _In_ uint32_t             ports_number,
                                                      _Inout_ port_pbs_index_t *pbs_index);

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_acl_pbs_get_map_index_and_key(_In_ const sx_port_id_t *ports,
                                                       _In_ uint32_t            ports_number,
                                                       _Out_ port_pbs_index_t  *pbs_index,
                                                       _Out_ acl_pbs_map_key_t *pbs_key);
static sai_status_t mlnx_acl_pbs_entry_create_or_get(_In_ sx_port_id_t        *ports,
                                                     _In_ uint32_t             ports_number,
                                                     _Inout_ sx_acl_pbs_id_t  *pbs_id,
                                                     _Inout_ port_pbs_index_t *pbs_index);
static sai_status_t mlnx_acl_lag_pbs_create_or_get(_In_ sx_port_log_id_t  sx_lag_id,
                                                   _Out_ sx_acl_pbs_id_t *sx_pbs_id,
                                                   _Out_ lag_pbs_index_t *lag_pbs_index);
static sai_status_t mlnx_acl_flood_pbs_create_or_get(_Out_ sx_acl_pbs_id_t *sx_pbs_id);
static sai_status_t mlnx_acl_entry_redirect_pbs_delete(_In_ const acl_entry_redirect_data_t *redirect_data);
static sai_status_t mlnx_acl_sx_port_list_to_mask(_In_ const sx_port_id_t   *ports,
                                                  _In_ uint32_t              port_number,
                                                  _Inout_ acl_pbs_map_key_t *port_mask);
static sai_status_t mlnx_acl_pbs_map_get_ports(_In_ port_pbs_index_t pbs_index,
                                               _Inout_ sx_port_id_t *ports,
                                               _Inout_ uint32_t     *port_number);
static uint32_t mlnx_acl_pbs_map_key_to_index(_In_ acl_pbs_map_key_t key, uint32_t step);
static sai_status_t mlnx_acl_range_attr_get_by_oid(_In_ sai_object_id_t           acl_range_oid,
                                                   _In_ sai_attr_id_t             attr_id,
                                                   _Inout_ sai_attribute_value_t *value);
static void mlnx_acl_fill_rule_list(_In_ sx_flex_acl_flex_rule_t     src_rule,
                                    _Inout_ sx_flex_acl_flex_rule_t *dst_rules,
                                    _In_ uint32_t                    dst_rules_count,
                                    _In_ const sx_port_log_id_t     *ports,
                                    _In_ uint32_t                    port_count,
                                    _In_ uint32_t                    port_key_index);
static sai_status_t mlnx_acl_entry_modify_rules(_In_ uint32_t                       entry_index,
                                                _In_ uint32_t                       table_index,
                                                _In_ const sx_flex_acl_flex_rule_t *rules,
                                                _In_ uint32_t                       rules_count);
static sai_status_t mlnx_acl_sx_list_set(_In_ sx_access_cmd_t           cmd,
                                         _In_ const sai_object_list_t  *ports,
                                         _Inout_ sx_acl_port_list_id_t *sx_port_list_id);
static sai_status_t mlnx_acl_sx_list_delete(_In_ uint32_t port_list_index);
static sai_status_t mlnx_acl_fetch_sx_port_list(_In_ uint32_t           port_list_index,
                                                _Out_ sx_port_log_id_t *ports,
                                                _Out_ uint32_t         *port_count);
static void mlnx_acl_port_mask_to_sx_list(_In_ uint64_t           mask,
                                          _Out_ sx_port_log_id_t *ports,
                                          _Inout_ uint32_t       *port_count);
static sai_status_t mlnx_acl_sx_port_lists_update(_In_ sx_access_cmd_t cmd, _In_ sx_port_log_id_t sx_port);
static sai_status_t mlnx_sai_port_to_sx(_In_ sai_object_id_t sai_port, _Out_ sx_port_log_id_t *sx_port);
static sai_status_t mlnx_sai_lag_to_sx(_In_ sai_object_id_t    sai_lag,
                                       _Out_ sx_port_log_id_t *sx_lag,
                                       _Out_ uint32_t         *lag_index);
static bool mlnx_sai_acl_redirect_action_attr_check(_In_ sai_object_id_t object_id);
static sai_status_t mlnx_sai_acl_redirect_action_create(_In_ sai_object_id_t             object_id,
                                                        _Out_ acl_entry_res_refs_t      *res_refs,
                                                        _Out_ acl_entry_redirect_data_t *redirect_data,
                                                        _Out_ sx_flex_acl_flex_action_t *sx_action);
static const char* mlnx_acl_entry_redirect_type_to_str(acl_entry_redirect_type_t redirect_type);
static bool mlnx_acl_index_is_group(_In_ acl_index_t index);
static bool mlnx_acl_indexes_is_equal(_In_ acl_index_t a, _In_ acl_index_t b);
static bool mlnx_acl_bind_point_indexes_is_equal(_In_ acl_bind_point_index_t a, _In_ acl_bind_point_index_t b);
static sai_status_t mlnx_acl_index_to_sai_object(_In_ acl_index_t acl_index, _Out_ sai_object_id_t *objet_id);
static uint32_t mlnx_acl_group_capacity_get(_In_ uint32_t group_index);
static void mlnx_acl_group_db_bind_point_find(_In_ uint32_t               group_index,
                                              _In_ acl_bind_point_index_t bind_point_index,
                                              _In_ uint32_t              *index);
static bool mlnx_acl_group_db_bind_point_is_present(_In_ uint32_t               group_index,
                                                    _In_ acl_bind_point_index_t bind_point_index);
static sai_status_t mlnx_acl_bind_point_type_list_validate_and_fetch(_In_ const sai_s32_list_t        *types,
                                                                     _In_ uint32_t                     attr_idnex,
                                                                     _Out_ acl_bind_point_type_list_t *list);
static sai_status_t mlnx_acl_bind_point_oid_fetch_data(_In_ sai_object_id_t oid,
                                                       _In_ uint32_t        attr_index,
                                                       _Out_ acl_index_t   *acl_index);
static const acl_bind_point_type_list_t* mlnx_acl_table_or_group_bind_point_list_fetch(_In_ acl_index_t acl_index);
static sai_acl_stage_t mlnx_acl_index_stage_get(_In_ acl_index_t acl_index);
static sx_acl_direction_t mlnx_acl_sai_bind_point_type_to_sx_direction(_In_ sai_acl_bind_point_type_t bind_point_type,
                                                                       _In_ sai_acl_stage_t           stage);
static sx_acl_direction_t mlnx_acl_bind_point_type_to_sx_direction(_In_ mlnx_acl_bind_point_type_t bind_point_type);
static sai_acl_bind_point_type_t mlnx_acl_bind_point_type_to_sai(_In_ mlnx_acl_bind_point_type_t bind_point_type);
static sai_acl_stage_t mlnx_acl_bind_point_type_to_sai_stage(_In_ mlnx_acl_bind_point_type_t bind_point_type);
static sai_status_t mlnx_acl_port_lag_bind_point_clear(_In_ const mlnx_port_config_t *port_config,
                                                       _In_ sai_acl_stage_t           sai_acl_stage);
static sai_status_t mlnx_acl_port_bind_refresh(_In_ const mlnx_port_config_t *port_config);
static void mlnx_acl_group_db_bind_point_remove(_In_ uint32_t               group_index,
                                                _In_ acl_bind_point_index_t bind_point_index);
static void mlnx_acl_group_db_bind_point_add(_In_ uint32_t group_index, _In_ acl_bind_point_index_t bind_point_index);
static sai_status_t mlnx_acl_bind_point_sx_group_remove(_In_ acl_bind_point_data_t *bind_point_data);
static sai_status_t mlnx_acl_bind_point_group_sx_set(_In_ acl_bind_point_data_t *bind_point_data,
                                                     _In_ uint32_t               group_index);
static sai_status_t mlnx_acl_bind_point_table_sx_set(_In_ acl_bind_point_data_t *bind_point_data,
                                                     _In_ uint32_t               table_index);
static void mlnx_acl_bind_point_db_update(_In_ acl_bind_point_data_t *bind_point_data,
                                          _In_ acl_index_t            acl_index,
                                          _In_ acl_bind_point_index_t bind_point_index);
static sai_status_t mlnx_acl_bind_point_sx_update(_In_ acl_bind_point_data_t *bind_point_data);
static sai_status_t mlnx_acl_bind_point_sai_acl_apply(_In_ acl_bind_point_data_t *bind_point_data,
                                                      _In_ acl_index_t            acl_index,
                                                      _In_ acl_bind_point_index_t bind_point_index);
static sai_status_t mlnx_acl_port_lag_db_index_validate_and_get(_In_ sai_object_id_t oid, _In_ uint32_t        *index);
static sai_status_t mlnx_acl_bind_point_port_lag_index_get(_In_ sai_object_id_t            oid,
                                                           _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                           _In_ acl_bind_point_index_t    *index);
static sai_status_t mlnx_acl_bind_point_rif_index_get(_In_ sai_object_id_t oid, _In_ acl_bind_point_index_t *index);
static sai_status_t mlnx_acl_bind_point_port_lag_rif_index_get(_In_ sai_object_id_t            oid,
                                                               _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                               _In_ acl_bind_point_index_t    *index);
static sai_status_t mlnx_acl_bind_point_port_lag_data_fetch(_In_ sai_object_id_t            oid,
                                                            _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                            _In_ acl_bind_point_data_t    **data);
static sai_status_t mlnx_acl_bind_point_rif_data_get(_In_ sai_object_id_t            oid,
                                                     _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                     _Out_ acl_bind_point_data_t   **data);
static sai_status_t mlnx_acl_bind_point_vlan_is_bound(_In_ sai_object_id_t            vlan_oid,
                                                      _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                      _Out_ bool                     *is_bound);
static sai_status_t mlnx_acl_bind_point_vlan_data_get(_In_ sai_object_id_t            vlan_oid,
                                                      _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                      _Out_ acl_bind_point_data_t   **data);
static sai_status_t mlnx_acl_bind_point_port_lag_rif_data_get(_In_ sai_object_id_t            target,
                                                              _In_ mlnx_acl_bind_point_type_t type,
                                                              _Out_ acl_bind_point_data_t   **data);
static sai_status_t mlnx_acl_bind_point_port_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                      _In_ acl_bind_point_data_t *bind_point_data);
static sai_status_t mlnx_acl_bind_point_rif_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                     _In_ acl_bind_point_data_t *bind_point_data);
static sai_status_t mlnx_acl_bind_point_vlan_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                      _In_ acl_bind_point_data_t *bind_point_data);
static sai_status_t mlnx_acl_bind_point_sx_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                    _In_ acl_bind_point_data_t *bind_point_data);
static bool mlnx_acl_is_bind_point_lag_member(_In_ acl_bind_point_index_t bind_point_index);
static sai_status_t mlnx_acl_lag_member_bind_set(_In_ acl_bind_point_index_t     lag_member_bind_point_index,
                                                 _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                 _In_ acl_index_t                acl_index);
static sai_status_t mlnx_acl_vlan_group_create_or_get(_In_ sx_vlan_id_t       sx_vlan_id,
                                                      _In_ acl_index_t        acl_index,
                                                      _In_ sx_acl_direction_t sx_acl_direction,
                                                      _Out_ uint32_t         *vlan_group_index);
static sai_status_t mlnx_acl_vlan_group_remove(_In_ sx_vlan_id_t sx_vlan_id, _In_ uint32_t vlan_group_index);
static sai_status_t mlnx_acl_bind_point_set_impl(_In_ sai_object_id_t            target,
                                                 _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                 _In_ acl_index_t                acl_index);
static sai_status_t mlnx_acl_wrapping_group_create(_In_ uint32_t table_index);
static sai_status_t mlnx_acl_wrapping_group_delete(_In_ uint32_t table_index);
static sai_status_t mlnx_acl_table_set_def_rule(_In_ uint32_t src_table_index, _In_ uint32_t dst_table_index);
static sai_status_t mlnx_acl_bind_point_index_to_data(_In_ acl_bind_point_index_t   index,
                                                      _In_ sai_acl_stage_t          stage,
                                                      _Out_ acl_bind_point_data_t **data);
static sai_status_t mlnx_acl_group_bind_points_update(_In_ uint32_t group_index);
static bool mlnx_acl_table_bind_point_list_fits_group(_In_ uint32_t group_index, _In_ uint32_t table_index);
static sai_status_t mlnx_acl_group_add_table(_In_ uint32_t group_index,
                                             _In_ uint32_t table_index,
                                             _In_ uint32_t table_priority);
static sai_status_t mlnx_acl_group_del_table(_In_ uint32_t group_index, _In_ uint32_t table_index);
static sai_status_t mlnx_acl_group_member_oid_create(_Out_ sai_object_id_t *group_member_oid,
                                                     _In_ uint32_t          table_index,
                                                     _In_ uint32_t          group_index,
                                                     _In_ uint32_t          table_priority);
static sai_status_t mlnx_acl_group_member_data_fetch(_In_ sai_object_id_t group_member_oid,
                                                     _Out_ uint32_t      *table_index,
                                                     _Out_ uint32_t      *group_index,
                                                     _Out_ uint32_t      *table_priority);
static bool mlnx_acl_range_type_list_is_unique(_In_ const sai_acl_range_type_t *range_types,
                                               _In_ uint32_t                    range_type_count);
static sai_status_t mlnx_acl_range_validate_and_fetch(_In_ const sai_object_list_t   *range_list,
                                                      _Out_ sx_flex_acl_port_range_t *sx_acl_range,
                                                      _In_ uint32_t                   table_index);
static sai_status_t mlnx_acl_action_list_validate(_In_ const sai_s32_list_t *action_list,
                                                  _In_ sai_acl_stage_t       stage,
                                                  _In_ uint32_t              attr_index);
static sai_status_t acl_resources_init();
static sai_status_t acl_background_threads_close();
static sai_status_t acl_psort_background_close();
static sai_status_t acl_psort_rpc_thread_close();
static void mlnx_acl_psort_deinit();
static void mlnx_acl_table_locks_deinit();
static void psort_background_thread(void *arg);
static void psort_rpc_thread(void *arg);
static bool mlnx_acl_field_is_not_trivial(sai_attr_id_t attr_id);
static const mlnx_acl_single_key_field_info_t* mlnx_acl_single_key_field_info_fetch(_In_ sai_attr_id_t attr_id);
static const mlnx_acl_multi_key_field_info_t* mlnx_acl_multi_key_field_info_fetch(_In_ sai_attr_id_t attr_id);
static sai_status_t mlnx_acl_non_trivial_field_to_sx_key(_In_ sai_acl_entry_attr_t attr_id,
                                                         _Out_ sx_acl_key_t       *sx_keys,
                                                         _Out_ uint32_t           *sx_key_count);
static sai_status_t mlnx_acl_table_is_entry_field_supported(_In_ uint32_t             acl_table_index,
                                                            _In_ sai_acl_entry_attr_t attr_id,
                                                            _Out_ bool               *is_supported);
static sai_status_t mlnx_acl_field_info_data_fetch(_In_ sai_attr_id_t               attr_id,
                                                   _Out_opt_ mlnx_acl_field_type_t *fields_types,
                                                   _Out_opt_ sx_acl_key_t          *sx_keys,
                                                   _Inout_opt_ uint32_t            *sx_key_count);
static sai_status_t mlnx_acl_table_fields_to_sx(_In_ const sai_attribute_t *attr_list,
                                                _In_ uint32_t               attr_count,
                                                _Out_ sx_acl_key_t         *sx_keys,
                                                _Inout_ uint32_t           *sx_key_count);
static sai_status_t mlnx_acl_entry_fields_to_sx(_In_ const sai_attribute_t   *attr_list,
                                                _In_ uint32_t                 attr_count,
                                                _In_ uint32_t                 table_index,
                                                _Out_ sx_flex_acl_key_desc_t *sx_keys,
                                                _Inout_ uint32_t             *sx_key_count);
static sai_status_t mlnx_acl_field_types_check(_Inout_ mlnx_acl_field_type_t *entry_fields_types,
                                               _In_ mlnx_acl_field_type_t     field_type);
static sai_status_t mlnx_acl_field_types_to_extra_sx_keys(_In_ mlnx_acl_field_type_t fields_types,
                                                          _Out_ sx_acl_key_t        *sx_keys,
                                                          _Inout_ uint32_t          *sx_key_count);
static sai_status_t mlnx_acl_field_type_extend(_Inout_ mlnx_acl_field_type_t *fields_types);
static sai_status_t mlnx_acl_extra_key_descs_merge(_Inout_ sx_flex_acl_flex_rule_t   *rule,
                                                   _In_ const sx_flex_acl_key_desc_t *key_descs,
                                                   _In_ uint32_t                      key_desc_count);
static sai_status_t mlnx_acl_field_types_to_sx(_In_ mlnx_acl_field_type_t    fields_types,
                                               _Out_ sx_flex_acl_key_desc_t *sx_keys,
                                               _Inout_ uint32_t             *sx_key_count);
static sai_status_t mlnx_acl_entry_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                               _In_ const sai_attribute_value_t *value,
                                               _In_ uint32_t                     attr_index,
                                               _In_ uint32_t                     table_index,
                                               _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                               _Inout_ uint32_t                 *sx_key_count,
                                               _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_single_key_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                    _In_ const sai_attribute_value_t *value,
                                                    _In_ uint32_t                     attr_index,
                                                    _In_ uint32_t                     table_index,
                                                    _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                    _Inout_ uint32_t                 *sx_key_count,
                                                    _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_ip_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                            _In_ const sai_attribute_value_t *vallue,
                                            _In_ uint32_t                     attr_index,
                                            _In_ uint32_t                     table_index,
                                            _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                            _Inout_ uint32_t                 *sx_key_count,
                                            _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_packet_vlan_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                     _In_ const sai_attribute_value_t *value,
                                                     _In_ uint32_t                     attr_index,
                                                     _In_ uint32_t                     table_index,
                                                     _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                     _Inout_ uint32_t                 *sx_key_count,
                                                     _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_tos_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                             _In_ const sai_attribute_value_t *value,
                                             _In_ uint32_t                     attr_index,
                                             _In_ uint32_t                     table_index,
                                             _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                             _Inout_ uint32_t                 *sx_key_count,
                                             _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_ip_type_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                 _In_ const sai_attribute_value_t *value,
                                                 _In_ uint32_t                     attr_index,
                                                 _In_ uint32_t                     table_index,
                                                 _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                 _Inout_ uint32_t                 *sx_key_count,
                                                 _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_ip_frag_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                 _In_ const sai_attribute_value_t *value,
                                                 _In_ uint32_t                     attr_index,
                                                 _In_ uint32_t                     table_index,
                                                 _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                 _Inout_ uint32_t                 *sx_key_count,
                                                 _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_range_type_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                    _In_ const sai_attribute_value_t *value,
                                                    _In_ uint32_t                     attr_index,
                                                    _In_ uint32_t                     table_index,
                                                    _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                    _Inout_ uint32_t                 *sx_key_count,
                                                    _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_user_meta_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                   _In_ const sai_attribute_value_t *value,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ uint32_t                     table_index,
                                                   _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                   _Inout_ uint32_t                 *sx_key_count,
                                                   _Inout_ mlnx_acl_field_type_t    *field_type);
static const mlnx_acl_single_key_field_info_t mlnx_acl_single_key_fields_info[] = {
#ifndef _WIN32
    /* L2 */
    [SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC]        = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_SMAC, smac),
    [SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC]        = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_DMAC, dmac),
    [SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE]     = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_ETHERTYPE, ethertype),
    [SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID]  = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_VLAN_ID, vlan_id),
    [SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_PCP, pcp),
    [SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_DEI, dei),
    /* [SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID] = MLNX_ACL_FIELD_INNER_VLAN_DEFINE(FLEX_ACL_KEY_INNER_VLAN_ID, inner_vlan_id), */
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI] = MLNX_ACL_FIELD_INNER_VLAN_DEFINE(FLEX_ACL_KEY_INNER_PCP, inner_pcp),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI] = MLNX_ACL_FIELD_INNER_VLAN_DEFINE(FLEX_ACL_KEY_INNER_DEI, inner_dei),

    /* L3 */
    [SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP]   = MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_SIP, sip),
    [SAI_ACL_ENTRY_ATTR_FIELD_DST_IP]   = MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_DIP, dip),
    [SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = MLNX_ACL_FIELD_IPV6_DEFINE(FLEX_ACL_KEY_SIPV6, sipv6),
    [SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = MLNX_ACL_FIELD_IPV6_DEFINE(FLEX_ACL_KEY_DIPV6, dipv6),

    [SAI_ACL_ENTRY_ATTR_FIELD_TTL]              = MLNX_ACL_FIELD_IP_DEFINE(FLEX_ACL_KEY_TTL, ttl),
    [SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL]      = MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_IP_PROTO, ip_proto),
    [SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER] = MLNX_ACL_FIELD_IPV6_DEFINE(FLEX_ACL_KEY_IP_PROTO, ip_proto),

    [SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_DSCP, dscp),
    [SAI_ACL_ENTRY_ATTR_FIELD_ECN]  = MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_ECN, ecn),
    /* [SAI_ACL_ENTRY_ATTR_FIELD_TOS] */

    /* Inner L3 */
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP]   = MLNX_ACL_FIELD_INNER_IPV4_DEFINE(FLEX_ACL_KEY_INNER_SIP, inner_sip),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP]   = MLNX_ACL_FIELD_INNER_IPV4_DEFINE(FLEX_ACL_KEY_INNER_DIP, inner_dip),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6] =
        MLNX_ACL_FIELD_INNER_IPV6_DEFINE(FLEX_ACL_KEY_INNER_SIPV6, inner_sipv6),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6] =
        MLNX_ACL_FIELD_INNER_IPV6_DEFINE(FLEX_ACL_KEY_INNER_DIPV6, inner_dipv6),

    /* L4 */
    [SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = MLNX_ACL_FIELD_L4_DEFINE(FLEX_ACL_KEY_L4_SOURCE_PORT, l4_source_port),
    [SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT] = MLNX_ACL_FIELD_L4_DEFINE(FLEX_ACL_KEY_L4_DESTINATION_PORT,
                                                                      l4_destination_port),
    [SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS]   = MLNX_ACL_FIELD_TCP_DEFINE(FLEX_ACL_KEY_TCP_CONTROL, tcp_control),

    /* Other */
    [SAI_ACL_ENTRY_ATTR_FIELD_TC]             = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_SWITCH_PRIO, switch_prio),
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META]  = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_USER_TOKEN, user_token),
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE] = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_L4_PORT_RANGE, l4_port_range),
#else
    { 0, 0, 0 }
#endif
};
static const size_t                           mlnx_acl_single_key_field_max_id = ARRAY_SIZE(
    mlnx_acl_single_key_fields_info);
static const mlnx_acl_multi_key_field_info_t mlnx_acl_multi_key_fields_info[]  = {
#ifndef _WIN32
    [SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_VLAN_TAGGED, FLEX_ACL_KEY_INNER_VLAN_VALID),
        MLNX_ACL_FIELD_TYPE_EMPTY),
    [SAI_ACL_ENTRY_ATTR_FIELD_TOS] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_DSCP, FLEX_ACL_KEY_ECN),
        MLNX_ACL_FIELD_TYPE_IPV4),
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        3,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_IP_OK, FLEX_ACL_KEY_IS_IP_V4, FLEX_ACL_KEY_L3_TYPE),
        MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_IPV6 | MLNX_ACL_FIELD_TYPE_ARP),
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_IP_FRAGMENTED, FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST),
        MLNX_ACL_FIELD_TYPE_IPV4),
#else
    { 0, 0, 0 }
#endif
};
static const size_t                          mlnx_acl_multi_key_field_max_id = ARRAY_SIZE(
    mlnx_acl_multi_key_fields_info);
static const sai_attr_id_t mlnx_acl_non_trivial_fields[]                     = {
    SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
    SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
    SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
    SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
    SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION,
};
static const size_t        mlnx_acl_non_trivial_field_count =
    ARRAY_SIZE(mlnx_acl_non_trivial_fields);

/* ACL TABLE ATTRIBUTES */
static const sai_attribute_entry_t acl_table_attribs[] = {
    { SAI_ACL_TABLE_ATTR_ACL_STAGE, true, true, false, true,
      "ACL Table Stage", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST, false, true, false, true,
      "ACL Table Bind point", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ACL_TABLE_ATTR_SIZE, false, true, false, true,
      "ACL Table Size", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST, false, true, false, false,
      "List of actions in sai_acl_action_type_t", SAI_ATTR_VAL_TYPE_S32LIST },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6, false, true, false, true,
      "Src IPV6 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6, false, true, false, true,
      "Dst IPV6 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IPV6, false, true, false, true,
      "Inner Src IPV6 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IPV6, false, true, false, true,
      "Inner Dst IPV6 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC, false, true, false, true,
      "Src MAC Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_MAC, false, true, false, true,
      "Dst MAC Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IP, false, true, false, true,
      "Src IPv4 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IP, false, true, false, true,
      "Dst IPv4 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IP, false, true, false, true,
      "Inner Src IPv4 Address", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IP, false, true, false, true,
      "Inner Dst IPv4 Address", SAI_ATTR_VAL_TYPE_BOOL },
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
    { SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION, false, true, false, true,
      "Ip Identification", SAI_ATTR_VAL_TYPE_BOOL },
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
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE, false, true, false, true,
      "Ip Type", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG, false, true, false, true,
      "Ip Frag", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL, false, false, false, false,
      "IPV6 Flow Label", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_TC, false, true, false, true,
      "Class-of-Service", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE, false, true, false, true,
      "ICMP Type", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE, false, true, false, true,
      "ICMP Code", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ACL_TABLE_ATTR_FIELD_PACKET_VLAN, false, true, false, true,
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
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, false, true, false, true,
      "Range type", SAI_ATTR_VAL_TYPE_S32LIST },
    { SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER, false, true, false, true,
      "IPv6 Next Header", SAI_ATTR_VAL_TYPE_BOOL },
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
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6, false, true, true, true,
      "Src IPV6 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6, false, true, true, true,
      "Dst IPV6 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6, false, true, true, true,
      "Inner Src IPV6 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6, false, true, true, true,
      "Inner Dst IPV6 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC, false, true, true, true,
      "Src MAC Address", SAI_ATTR_VAL_TYPE_ACLFIELD_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC, false, true, true, true,
      "Dst MAC Address", SAI_ATTR_VAL_TYPE_ACLFIELD_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP, false, true, true, true,
      "Src IPv4 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4 },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IP, false, true, true, true,
      "Dst IPv4 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP, false, true, true, true,
      "Inner Src IPv4 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP, false, true, true, true,
      "Inner Dst IPv4 Address", SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4 },
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
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION, false, true, true, true,
      "IP Identification", SAI_ATTR_VAL_TYPE_ACLFIELD_U16 },
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
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE, false, true, true, true,
      "Ip Type",  SAI_ATTR_VAL_TYPE_ACLFIELD_S32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG, false, true, true, true,
      "Ip Frag", SAI_ATTR_VAL_TYPE_ACLFIELD_S32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL, false, false, false, false,
      "IPV6 Flow Label",  SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_TC, false, true, true, true,
      "Class-of-Service (Traffic Class)", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE, false, true, true, true,
      "ICMP Type", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE, false, true, true, true,
      "ICMP Code", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN, false, true, true, true,
      "Vlan tags", SAI_ATTR_VAL_TYPE_ACLFIELD_S32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META, false, false, false, false,
      "FDB DST user meta data", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META, false, false, false, false,
      "ROUTE DST User Meta data", SAI_ATTR_VAL_TYPE_ACLFIELD_U32 },
    { SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META, false, false, false, false,
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
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE, false, true, true, true,
      "Range Type", SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST },
    { SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER, false, true, true, true,
      "IPv6 Next Header", SAI_ATTR_VAL_TYPE_ACLFIELD_U8 },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT, false, true, true, true,
      "Redirect Packet to a destination", SAI_ATTR_VAL_TYPE_ACLACTION_OID },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST, false, true, true, true,
      "Redirect Packet to a destination list", SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST },
    { SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION, false, true, true, true,
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
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR, false, true, true, true,
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
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6, false, false, false, false,
      "Set Packet Src IPV6 Address", SAI_ATTR_VAL_TYPE_ACLACTION_IPV6 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6, false, false, false, false,
      "Set Packet Dst IPV6 Address", SAI_ATTR_VAL_TYPE_ACLACTION_IPV6 },
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
static const sai_attribute_entry_t acl_group_attribs[] = {
    { SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE, true, true, false, true,
      "ACL stage", SAI_ATTR_VAL_TYPE_S32},
    { SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST, false, true, false, true,
      "List of ACL bind points", SAI_ATTR_VAL_TYPE_S32LIST },
    { SAI_ACL_TABLE_GROUP_ATTR_TYPE, true, true, false, true,
      "ACL table group type", SAI_ATTR_VAL_TYPE_S32},
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_attribute_entry_t acl_group_member_attribs[] = {
    { SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID, true, true, false, true,
      "ACL table group id", SAI_ATTR_VAL_TYPE_OID},
    { SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID, true, true, false, true,
      "ACL table id", SAI_ATTR_VAL_TYPE_OID },
    { SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY, false, true, false, true,
      "Priority", SAI_ATTR_VAL_TYPE_U32},
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

/* ACL TABLE VENDOR ATTRIBUTES */
static const sai_vendor_attribute_entry_t acl_table_vendor_attribs[] = {
    { SAI_ACL_TABLE_ATTR_ACL_STAGE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_ACL_STAGE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_SIZE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_SIZE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST,
      {true, false, false, false},
      {true, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IPV6,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IPV6,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IPV6,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IPV6,
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
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IP,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IP,
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
    { SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION,
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
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_TOS,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL,
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
    { SAI_ACL_TABLE_ATTR_FIELD_PACKET_VLAN,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_PACKET_VLAN,
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
    { SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_range_type_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER,
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
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_entry_attrib_get, (void*)SAI_ACL_ENTRY_ATTR_ADMIN_STATE,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6 },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP },
    { SAI_ACL_ENTRY_ATTR_FIELD_DST_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IP,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IP },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP },
    { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ports_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
      mlnx_acl_entry_in_ports_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ports_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
      mlnx_acl_entry_out_ports_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS },
    { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_port_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
      mlnx_acl_entry_in_ports_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_port_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
      mlnx_acl_entry_out_ports_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_SRC_PORT,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI },
    { SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_ident_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION,
      mlnx_acl_entry_ip_ident_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION },
    { SAI_ACL_ENTRY_ATTR_FIELD_DSCP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DSCP,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_DSCP },
    { SAI_ACL_ENTRY_ATTR_FIELD_ECN,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ECN,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ECN },
    { SAI_ACL_ENTRY_ATTR_FIELD_TTL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TTL,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TTL },
    { SAI_ACL_ENTRY_ATTR_FIELD_TOS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_tos_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TOS,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TOS },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL, },
    { SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS },
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_type_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_frag_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG },
    { SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_TC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TC,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TC },
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
    { SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN,
      { true, false, false, true },
      { true, false, true, true },
      mlnx_acl_entry_vlan_tags_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN },
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
    { SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META,
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
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META },
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
    { SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_range_list_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_redirect_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
      mlnx_acl_entry_action_redirect_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_redirect_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST,
      mlnx_acl_entry_action_redirect_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST },
    { SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_packet_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,
      mlnx_acl_entry_packet_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION },
    { SAI_ACL_ENTRY_ATTR_ACTION_FLOOD,
      { true, false, true, false },
      { true, false, true, false },
      NULL, NULL,
      mlnx_acl_entry_action_redirect_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_FLOOD },
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
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR },
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
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6,
      { false, false, false, false},
      { false, false, false, false},
      NULL, NULL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6,
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
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_range_attr_get, (void*)SAI_ACL_RANGE_ATTR_TYPE,
      NULL, NULL },
    { SAI_ACL_RANGE_ATTR_LIMIT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_range_attr_get, (void*)SAI_ACL_RANGE_ATTR_LIMIT,
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
      "Bytes Counter Value", SAI_ATTR_VAL_TYPE_U64 },
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
static const sai_vendor_attribute_entry_t acl_group_vendor_attribs[] = {
    { SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_group_attrib_get, (void*)SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE,
      NULL, NULL },
    { SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_group_attrib_get, (void*)SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST,
      NULL, NULL },
    { SAI_ACL_TABLE_GROUP_ATTR_TYPE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_group_attrib_get, (void*)SAI_ACL_TABLE_GROUP_ATTR_TYPE,
      NULL, NULL }
};
static const sai_vendor_attribute_entry_t acl_group_member_vendor_attribs[] = {
    { SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_group_member_attrib_get, (void*)SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID,
      NULL, NULL },
    { SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_group_member_attrib_get, (void*)SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID,
      NULL, NULL },
    { SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_group_member_attrib_get, (void*)SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY,
      NULL, NULL }
};
acl_group_db_t* sai_acl_db_group_ptr(_In_ uint32_t group_index)
{
    return (acl_group_db_t*)((uint8_t*)sai_acl_db->acl_groups_db +
                             (sizeof(acl_group_db_t) + sizeof(uint32_t) * ACL_GROUP_SIZE) * group_index);
}

acl_group_bound_to_t* sai_acl_db_group_bount_to(_In_ uint32_t group_index)
{
    return ((acl_group_bound_to_t*)((uint8_t*)sai_acl_db->acl_group_bound_to_db +
                                    (sizeof(acl_group_bound_to_t) + (sizeof(acl_bind_point_index_t) *
                                                                     SAI_ACL_MAX_BIND_POINT_BOUND)) * group_index));
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
static sai_status_t acl_resources_init()
{
    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    struct mq_attr mq_attributes;
#endif

    SX_LOG_ENTER();

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

#ifndef _WIN32
out:
#endif
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
    uint32_t table_index;

    for (table_index = 0; table_index < ACL_MAX_TABLE_NUMBER; table_index++) {
        if (acl_db_table(table_index).is_used) {
            __delete_psort_table(table_index);
        }
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
    sai_status_t               status;
    uint32_t                   acl_table_index, bind_point_type_count, ii;
    sai_acl_bind_point_type_t *bind_point_types;

    SX_LOG_ENTER();

    assert((SAI_ACL_TABLE_ATTR_ACL_STAGE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_SIZE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION == (int64_t)arg));

    status = extract_acl_table_index(key->key.object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_ATTR_ACL_STAGE:
        value->s32 = acl_db_table(acl_table_index).stage;
        break;

    case SAI_ACL_TABLE_ATTR_SIZE:
        value->u32 = acl_db_table(acl_table_index).table_size;
        break;

    case SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST:
        bind_point_type_count = acl_db_table(acl_table_index).bind_point_types.count;
        bind_point_types      = acl_db_table(acl_table_index).bind_point_types.types;

        if (value->s32list.count < bind_point_type_count) {
            SX_LOG_ERR(" Re-allocate list size as list size is not large enough \n");
            value->s32list.count = bind_point_type_count;
            status               = SAI_STATUS_BUFFER_OVERFLOW;
            goto out;
        } else {
            for (ii = 0; ii < bind_point_type_count; ii++) {
                value->s32list.list[ii] = bind_point_types[ii];
            }

            value->s32list.count = bind_point_type_count;
        }
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION:
        value->booldata = acl_db_table(acl_table_index).is_ip_ident_used;
        break;
    }

out:
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
    sai_status_t  status;
    sai_attr_id_t attr_id;
    uint32_t      acl_table_index;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_TABLE_ATTR_FIELD_START <= attr_id) && (attr_id <= SAI_ACL_TABLE_ATTR_FIELD_END));

    status = extract_acl_table_index(key->key.object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, attr_id, &value->booldata);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_range_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t status;
    uint32_t     acl_table_index, table_range_count, ii;

    SX_LOG_ENTER();

    assert(SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE == (int64_t)arg);

    status = extract_acl_table_index(key->key.object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    table_range_count = acl_db_table(acl_table_index).range_type_count;

    if (0 == table_range_count) {
        value->s32list.count = 0;
    } else {
        if (value->s32list.count < table_range_count) {
            SX_LOG_ERR(" Re-allocate list size as list size is not large enough \n");
            value->s32list.count = table_range_count;
            status               = SAI_STATUS_BUFFER_OVERFLOW;
        } else {
            for (ii = 0; ii < table_range_count; ii++) {
                value->s32list.list[ii] = acl_db_table(acl_table_index).range_types[ii];
            }

            value->s32list.count = table_range_count;
        }
    }

    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_acl_stage_action_list_fetch(_In_ uint32_t                       stage,
                                              _Out_ const sai_acl_action_type_t **actions,
                                              _Out_ uint32_t                     *action_count)
{
    assert(NULL != actions);
    assert(NULL != action_count);

    switch (stage) {
    case SAI_ACL_STAGE_INGRESS:
        *actions      = mlnx_acl_action_list_ingress;
        *action_count = mlnx_acl_action_list_ingress_count;
        break;

    case SAI_ACL_STAGE_EGRESS:
        *actions      = mlnx_acl_action_list_egress;
        *action_count = mlnx_acl_action_list_egress_count;
        break;

    default:
        SX_LOG_ERR("Unexpected acl stage (%d)\n", stage);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_list_validate(_In_ const sai_s32_list_t *action_list,
                                                  _In_ sai_acl_stage_t       stage,
                                                  _In_ uint32_t              attr_index)
{
    sai_status_t                 status;
    const sai_acl_action_type_t *stage_action_list;
    uint32_t                     stage_action_count, ii, jj;
    bool                         is_action_present;

    assert((SAI_ACL_STAGE_INGRESS == stage) || (SAI_ACL_STAGE_EGRESS == stage));

    status = mlnx_acl_stage_action_list_fetch(stage, &stage_action_list, &stage_action_count);
    if (SAI_ERR(status)) {
        return status;
    }

    for (ii = 0; ii < action_list->count; ii++) {
        is_action_present = false;

        for (jj = 0; jj < mlnx_acl_action_list_common_count; jj++) {
            if (mlnx_acl_action_list_common[jj] == (sai_acl_action_type_t)action_list->list[ii]) {
                is_action_present = true;
                break;
            }
        }

        if (is_action_present) {
            continue;
        }

        for (jj = 0; jj < stage_action_count; jj++) {
            if (stage_action_list[jj] == (sai_acl_action_type_t)action_list->list[ii]) {
                is_action_present = true;
                break;
            }
        }

        if (false == is_action_present) {
            SX_LOG_ERR("Invalid action id (%d)\n", action_list->list[ii]);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static bool mlnx_acl_field_is_not_trivial(sai_attr_id_t attr_id)
{
    uint32_t ii;

    assert((SAI_ACL_TABLE_ATTR_FIELD_START <= attr_id) && (attr_id <= SAI_ACL_TABLE_ATTR_FIELD_END));

    for (ii = 0; ii < mlnx_acl_non_trivial_field_count; ii++) {
        if (attr_id == mlnx_acl_non_trivial_fields[ii]) {
            return true;
        }
    }

    return false;
}

static const mlnx_acl_single_key_field_info_t* mlnx_acl_single_key_field_info_fetch(_In_ sai_attr_id_t attr_id)
{
    const mlnx_acl_single_key_field_info_t *info;

    if (mlnx_acl_single_key_field_max_id <= attr_id) {
        return NULL;
    }

    info = &mlnx_acl_single_key_fields_info[attr_id];

    if (MLNX_ACL_FIELD_TYPE_INVALID == info->field_type) {
        return NULL;
    }

    return info;
}

static const mlnx_acl_multi_key_field_info_t* mlnx_acl_multi_key_field_info_fetch(_In_ sai_attr_id_t attr_id)
{
    const mlnx_acl_multi_key_field_info_t *info;

    if (mlnx_acl_multi_key_field_max_id <= attr_id) {
        return NULL;
    }

    info = &mlnx_acl_multi_key_fields_info[attr_id];

    if (MLNX_ACL_FIELD_TYPE_INVALID == info->field_type) {
        return NULL;
    }

    return info;
}

static sai_status_t mlnx_acl_non_trivial_field_to_sx_key(_In_ sai_acl_entry_attr_t attr_id,
                                                         _Out_ sx_acl_key_t       *sx_keys,
                                                         _Out_ uint32_t           *sx_key_count)
{
    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
        sx_keys[*sx_key_count] = FLEX_ACL_KEY_RX_LIST;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
        sx_keys[*sx_key_count] = FLEX_ACL_KEY_DST_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        sx_keys[*sx_key_count] = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        sx_keys[*sx_key_count] = FLEX_ACL_KEY_DST_PORT;
        break;

    default:
        SX_LOG_ERR("Invalid attr id for non-trivial field\n");
        return SAI_STATUS_FAILURE;
    }

    (*sx_key_count)++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_is_entry_field_supported(_In_ uint32_t             acl_table_index,
                                                            _In_ sai_acl_entry_attr_t attr_id,
                                                            _Out_ bool               *is_supported)
{
    sx_status_t           sx_status;
    sai_status_t          status;
    sx_acl_key_t          table_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    sx_acl_key_t          field_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    sx_acl_key_type_t     key_handle;
    mlnx_acl_field_type_t field_type;
    uint32_t              table_key_count, field_key_count;
    uint32_t              table_key_index, field_key_index;
    bool                  is_key_present;

    assert(NULL != is_supported);

    field_key_count = 0;

    if (mlnx_acl_field_is_not_trivial(attr_id)) {
        status = mlnx_acl_non_trivial_field_to_sx_key(attr_id, field_keys, &field_key_count);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = mlnx_acl_field_info_data_fetch(attr_id, &field_type, field_keys, &field_key_count);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_acl_field_types_to_extra_sx_keys(field_type, field_keys, &field_key_count);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    key_handle = acl_db_table(acl_table_index).key_type;

    sx_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, table_keys, &table_key_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR(" Failed to get flex acl key in SDK - %s \n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    *is_supported = true;

    for (field_key_index = 0; field_key_index < field_key_count; field_key_index++) {
        is_key_present = false;

        for (table_key_index = 0; table_key_index < table_key_count; table_key_index++) {
            if (field_keys[field_key_index] == table_keys[table_key_index]) {
                is_key_present = true;
                break;
            }
        }

        if (false == is_key_present) {
            *is_supported = false;
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_field_info_data_fetch(_In_ sai_attr_id_t               attr_id,
                                                   _Out_opt_ mlnx_acl_field_type_t *fields_types,
                                                   _Out_opt_ sx_acl_key_t          *sx_keys,
                                                   _Inout_opt_ uint32_t            *sx_key_count)
{
    const mlnx_acl_single_key_field_info_t *single_key_field;
    const mlnx_acl_multi_key_field_info_t  *multi_key_field;
    uint32_t                                ii;

    assert((sx_keys && sx_key_count) || (fields_types));

    single_key_field = mlnx_acl_single_key_field_info_fetch(attr_id);
    if (NULL != single_key_field) {
        if (sx_keys) {
            sx_keys[*sx_key_count] = single_key_field->key_id;
            (*sx_key_count)++;
        }

        if (fields_types) {
            *fields_types = single_key_field->field_type;
        }

        return SAI_STATUS_SUCCESS;
    }

    multi_key_field = mlnx_acl_multi_key_field_info_fetch(attr_id);

    if (NULL != multi_key_field) {
        if (sx_keys) {
            for (ii = 0; ii < multi_key_field->key_count; ii++) {
                sx_keys[*sx_key_count] = multi_key_field->key_list[ii];
                (*sx_key_count)++;
            }
        }

        if (fields_types) {
            *fields_types = multi_key_field->field_type;
        }

        return SAI_STATUS_SUCCESS;
    }

    SX_LOG_ERR("Faield to find info for attribute (%d)\n", attr_id);
    return SAI_STATUS_FAILURE;
}

static sai_status_t mlnx_acl_table_fields_to_sx(_In_ const sai_attribute_t *attr_list,
                                                _In_ uint32_t               attr_count,
                                                _Out_ sx_acl_key_t         *sx_keys,
                                                _Inout_ uint32_t           *sx_key_count)
{
    sai_status_t          status;
    mlnx_acl_field_type_t table_fields_types, field_type;
    uint32_t              new_key_count, ii;

    assert(NULL != attr_list);
    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);

    table_fields_types = MLNX_ACL_FIELD_TYPE_EMPTY;
    new_key_count      = *sx_key_count;

    for (ii = 0; ii < attr_count; ii++) {
        if ((attr_list[ii].id < SAI_ACL_TABLE_ATTR_FIELD_START) || (SAI_ACL_TABLE_ATTR_FIELD_END < attr_list[ii].id)) {
            continue;
        }

        if (mlnx_acl_field_is_not_trivial(attr_list[ii].id)) {
            continue;
        }

        if (false == attr_list[ii].value.booldata) {
            continue;
        }

        field_type = MLNX_ACL_FIELD_TYPE_INVALID;

        /* Don't fetch IP Type's fields
         * They will be added as a result of 'fields_types' processing */
        if (SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE != attr_list[ii].id) {
            status = mlnx_acl_field_info_data_fetch(attr_list[ii].id, &field_type, sx_keys, &new_key_count);
        } else {
            status = mlnx_acl_field_info_data_fetch(attr_list[ii].id, &field_type, NULL, NULL);
        }

        if (SAI_ERR(status)) {
            return status;
        }

        table_fields_types |= field_type;
    }

    status = mlnx_acl_field_types_to_extra_sx_keys(table_fields_types, sx_keys, &new_key_count);
    if (SAI_ERR(status)) {
        return status;
    }

    *sx_key_count = new_key_count;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_fields_to_sx(_In_ const sai_attribute_t   *attr_list,
                                                _In_ uint32_t                 attr_count,
                                                _In_ uint32_t                 table_index,
                                                _Out_ sx_flex_acl_key_desc_t *sx_keys,
                                                _Inout_ uint32_t             *sx_key_count)
{
    sai_status_t          status;
    mlnx_acl_field_type_t entry_fields_type, field_type;
    uint32_t              ii;

    assert(NULL != attr_list);
    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);

    entry_fields_type = MLNX_ACL_FIELD_TYPE_EMPTY;

    for (ii = 0; ii < attr_count; ii++) {
        if ((attr_list[ii].id < SAI_ACL_ENTRY_ATTR_FIELD_START) || (SAI_ACL_ENTRY_ATTR_FIELD_END < attr_list[ii].id)) {
            continue;
        }

        if (mlnx_acl_field_is_not_trivial(attr_list[ii].id)) {
            continue;
        }

        field_type = MLNX_ACL_FIELD_TYPE_EMPTY;

        status = mlnx_acl_entry_field_to_sx(attr_list[ii].id,
                                            &attr_list[ii].value,
                                            ii,
                                            table_index,
                                            sx_keys,
                                            sx_key_count,
                                            &field_type);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_acl_field_types_check(&entry_fields_type, field_type);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    status = mlnx_acl_field_types_to_sx(entry_fields_type, sx_keys, sx_key_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_field_types_check(_Inout_ mlnx_acl_field_type_t *entry_fields_types,
                                               _In_ mlnx_acl_field_type_t     field_type)
{
    bool is_valid;

    assert((NULL != entry_fields_types) && (MLNX_ACL_FIELD_TYPE_INVALID != *entry_fields_types));
    assert(MLNX_ACL_FIELD_TYPE_INVALID != field_type);

    if (MLNX_ACL_FIELD_TYPE_EMPTY == field_type) {
        return SAI_STATUS_SUCCESS;
    }

    is_valid = true;

    switch (field_type) {
    case MLNX_ACL_FIELD_TYPE_IP:
        if ((MLNX_ACL_FIELD_TYPE_NON_IP | MLNX_ACL_FIELD_TYPE_ARP) & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_NON_IP:
        if ((MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_IPV6) & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_IPV4:
        if ((MLNX_ACL_FIELD_TYPE_NON_IP | MLNX_ACL_FIELD_TYPE_ARP |
             MLNX_ACL_FIELD_TYPE_IPV6) & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_NON_IPV4:
        if (MLNX_ACL_FIELD_TYPE_IPV4 & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_IPV6:
        if (MLNX_ACL_FIELD_TYPE_IPV4 & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_ARP:
        if ((MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_IPV6) & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_INNER_IPV4:
        if (MLNX_ACL_FIELD_TYPE_INNER_IPV6 & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_INNER_IPV6:
        if (MLNX_ACL_FIELD_TYPE_INNER_IPV4 & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_L4:
        if ((MLNX_ACL_FIELD_TYPE_NON_IP | MLNX_ACL_FIELD_TYPE_ARP) & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    case MLNX_ACL_FIELD_TYPE_TCP:
        if ((MLNX_ACL_FIELD_TYPE_NON_IP | MLNX_ACL_FIELD_TYPE_ARP) & (*entry_fields_types)) {
            is_valid = false;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected type of ACL field type (%d)\n", field_type);
        return SAI_STATUS_FAILURE;
    }

    if (false == is_valid) {
        SX_LOG_ERR("Failed to validate ACL Entry field type - conflicting field types\n");
        return SAI_STATUS_FAILURE;
    }

    (*entry_fields_types) |= field_type;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_field_types_to_extra_sx_keys(_In_ mlnx_acl_field_type_t fields_types,
                                                          _Out_ sx_acl_key_t        *sx_keys,
                                                          _Inout_ uint32_t          *sx_key_count)
{
    sai_status_t status;
    uint32_t     new_key_count;

    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);
    assert(MLNX_ACL_FIELD_TYPE_INVALID != fields_types);

    status = mlnx_acl_field_type_extend(&fields_types);
    if (SAI_ERR(status)) {
        return status;
    }

    new_key_count = *sx_key_count;

    if ((MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID | MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID) & fields_types) {
        sx_keys[new_key_count] = FLEX_ACL_KEY_INNER_VLAN_VALID;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_NON_IP) & fields_types) {
        sx_keys[new_key_count] = FLEX_ACL_KEY_IP_OK;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_NON_IPV4) & fields_types) {
        sx_keys[new_key_count] = FLEX_ACL_KEY_IS_IP_V4;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_IPV6 | MLNX_ACL_FIELD_TYPE_ARP) & fields_types) {
        sx_keys[new_key_count] = FLEX_ACL_KEY_L3_TYPE;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_INNER_IPV4 | MLNX_ACL_FIELD_TYPE_INNER_IPV6) & fields_types) {
        sx_keys[new_key_count] = FLEX_ACL_KEY_INNER_L3_TYPE;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_L4)&fields_types) {
        sx_keys[new_key_count] = FLEX_ACL_KEY_L4_OK;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_TCP)&fields_types) {
        sx_keys[new_key_count] = FLEX_ACL_KEY_L4_TYPE;
        new_key_count++;
    }

    *sx_key_count = new_key_count;

    return SAI_STATUS_SUCCESS;
}

/* Adds extra field types needed to generate a proper list of SX ACL Keys needed to match some specific L3/L4 field
 * e.g. For TCP related field we add an L4 field type and for L4 - type IP
 */
static sai_status_t mlnx_acl_field_type_extend(_Inout_ mlnx_acl_field_type_t *fields_types)
{
    assert((NULL != fields_types) && (*fields_types != MLNX_ACL_FIELD_TYPE_INVALID));

    if ((MLNX_ACL_FIELD_TYPE_TCP)&(*fields_types)) {
        (*fields_types) |= MLNX_ACL_FIELD_TYPE_L4;
    }

    if ((MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_IPV6 | MLNX_ACL_FIELD_TYPE_L4) & (*fields_types)) {
        (*fields_types) |= MLNX_ACL_FIELD_TYPE_IP;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_field_types_to_sx(_In_ mlnx_acl_field_type_t    fields_types,
                                               _Out_ sx_flex_acl_key_desc_t *sx_keys,
                                               _Inout_ uint32_t             *sx_key_count)
{
    sai_status_t status;
    uint32_t     new_key_count;

    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);
    assert(MLNX_ACL_FIELD_TYPE_INVALID != fields_types);

    status = mlnx_acl_field_type_extend(&fields_types);
    if (SAI_ERR(status)) {
        return status;
    }

    new_key_count = *sx_key_count;

    if ((MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID)&fields_types) {
        sx_keys[new_key_count].key_id                = FLEX_ACL_KEY_INNER_VLAN_VALID;
        sx_keys[new_key_count].key.inner_vlan_valid  = true;
        sx_keys[new_key_count].mask.inner_vlan_valid = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID)&fields_types) {
        sx_keys[new_key_count].key_id                = FLEX_ACL_KEY_INNER_VLAN_VALID;
        sx_keys[new_key_count].key.inner_vlan_valid  = false;
        sx_keys[new_key_count].mask.inner_vlan_valid = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_IP)&fields_types) {
        sx_keys[new_key_count].key_id     = FLEX_ACL_KEY_IP_OK;
        sx_keys[new_key_count].key.ip_ok  = true;
        sx_keys[new_key_count].mask.ip_ok = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_NON_IP)&fields_types) {
        sx_keys[new_key_count].key_id     = FLEX_ACL_KEY_IP_OK;
        sx_keys[new_key_count].key.ip_ok  = false;
        sx_keys[new_key_count].mask.ip_ok = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_IPV4)&fields_types) {
        sx_keys[new_key_count].key_id        = FLEX_ACL_KEY_IS_IP_V4;
        sx_keys[new_key_count].key.is_ip_v4  = true;
        sx_keys[new_key_count].mask.is_ip_v4 = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_NON_IPV4)&fields_types) {
        sx_keys[new_key_count].key_id        = FLEX_ACL_KEY_IS_IP_V4;
        sx_keys[new_key_count].key.is_ip_v4  = false;
        sx_keys[new_key_count].mask.is_ip_v4 = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_IPV6)&fields_types) {
        sx_keys[new_key_count].key_id       = FLEX_ACL_KEY_L3_TYPE;
        sx_keys[new_key_count].key.l3_type  = SX_ACL_L3_TYPE_IPV6;
        sx_keys[new_key_count].mask.l3_type = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_ARP)&fields_types) {
        sx_keys[new_key_count].key_id       = FLEX_ACL_KEY_L3_TYPE;
        sx_keys[new_key_count].key.l3_type  = SX_ACL_L3_TYPE_ARP;
        sx_keys[new_key_count].mask.l3_type = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_INNER_IPV4)&fields_types) {
        sx_keys[new_key_count].key_id             = FLEX_ACL_KEY_INNER_L3_TYPE;
        sx_keys[new_key_count].key.inner_l3_type  = SX_ACL_L3_TYPE_IPV4;
        sx_keys[new_key_count].mask.inner_l3_type = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_INNER_IPV6)&fields_types) {
        sx_keys[new_key_count].key_id             = FLEX_ACL_KEY_INNER_L3_TYPE;
        sx_keys[new_key_count].key.inner_l3_type  = SX_ACL_L3_TYPE_IPV6;
        sx_keys[new_key_count].mask.inner_l3_type = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_L4)&fields_types) {
        sx_keys[new_key_count].key_id     = FLEX_ACL_KEY_L4_OK;
        sx_keys[new_key_count].key.l4_ok  = true;
        sx_keys[new_key_count].mask.l4_ok = true;
        new_key_count++;
    }

    if ((MLNX_ACL_FIELD_TYPE_TCP)&fields_types) {
        sx_keys[new_key_count].key_id       = FLEX_ACL_KEY_L4_TYPE;
        sx_keys[new_key_count].key.l4_type  = SX_ACL_L4_TYPE_TCP;
        sx_keys[new_key_count].mask.l4_type = true;
        new_key_count++;
    }

    *sx_key_count = new_key_count;

    return SAI_STATUS_SUCCESS;
}

/* Adds extra key_desc to rule key desc list
 * Ignores the key_desc that already present in the rule
 */
static sai_status_t mlnx_acl_extra_key_descs_merge(_Inout_ sx_flex_acl_flex_rule_t   *rule,
                                                   _In_ const sx_flex_acl_key_desc_t *key_descs,
                                                   _In_ uint32_t                      key_desc_count)
{
    uint32_t key_desc_index, rule_key_desc_index;
    bool     is_key_desc_present;

    assert(NULL != rule);
    assert(NULL != key_descs);

    for (key_desc_index = 0; key_desc_index < key_desc_count; key_desc_index++) {
        is_key_desc_present = false;

        for (rule_key_desc_index = 0; rule_key_desc_index < rule->key_desc_count; rule_key_desc_index++) {
            if (rule->key_desc_list_p[rule_key_desc_index].key_id == key_descs[key_desc_index].key_id) {
                is_key_desc_present = true;
                break;
            }
        }

        if (false == is_key_desc_present) {
            memcpy(&rule->key_desc_list_p[rule->key_desc_count], &key_descs[key_desc_index],
                   sizeof(key_descs[key_desc_index]));
            rule->key_desc_count++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                               _In_ const sai_attribute_value_t *value,
                                               _In_ uint32_t                     attr_index,
                                               _In_ uint32_t                     table_index,
                                               _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                               _Inout_ uint32_t                 *sx_key_count,
                                               _Inout_ mlnx_acl_field_type_t    *field_type)
{
    sai_status_t status;

    assert(NULL != value);
    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);
    assert(NULL != field_type);

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6:
        status = mlnx_acl_ip_field_to_sx(attr_id, value, attr_index, table_index, sx_keys, sx_key_count, field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN:
        status = mlnx_acl_packet_vlan_field_to_sx(attr_id,
                                                  value,
                                                  attr_index,
                                                  table_index,
                                                  sx_keys,
                                                  sx_key_count,
                                                  field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_TOS:
        status = mlnx_acl_tos_field_to_sx(attr_id, value, attr_index, table_index, sx_keys, sx_key_count, field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE:
        status = mlnx_acl_ip_type_field_to_sx(attr_id,
                                              value,
                                              attr_index,
                                              table_index,
                                              sx_keys,
                                              sx_key_count,
                                              field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG:
        status = mlnx_acl_ip_frag_field_to_sx(attr_id,
                                              value,
                                              attr_index,
                                              table_index,
                                              sx_keys,
                                              sx_key_count,
                                              field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE:
        status = mlnx_acl_range_type_field_to_sx(attr_id,
                                                 value,
                                                 attr_index,
                                                 table_index,
                                                 sx_keys,
                                                 sx_key_count,
                                                 field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
        status = mlnx_acl_user_meta_field_to_sx(attr_id,
                                                value,
                                                attr_index,
                                                table_index,
                                                sx_keys,
                                                sx_key_count,
                                                field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    default:
        status = mlnx_acl_single_key_field_to_sx(attr_id,
                                                 value,
                                                 attr_index,
                                                 table_index,
                                                 sx_keys,
                                                 sx_key_count,
                                                 field_type);
        if (SAI_ERR(status)) {
            return status;
        }
        break;
    }

    return status;
}

static sai_status_t mlnx_acl_single_key_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                    _In_ const sai_attribute_value_t *value,
                                                    _In_ uint32_t                     attr_index,
                                                    _In_ uint32_t                     table_index,
                                                    _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                    _Inout_ uint32_t                 *sx_key_count,
                                                    _Inout_ mlnx_acl_field_type_t    *field_type)
{
    const mlnx_acl_single_key_field_info_t *field_info;

    field_info = &mlnx_acl_single_key_fields_info[attr_id];

    if (NULL == field_info) {
        SX_LOG_ERR("Failed to fetch field info for ACL field (%d)\n", attr_id);
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    assert(FLEX_ACL_KEY_INVALID != field_info->key_id);

    sx_keys[*sx_key_count].key_id = field_info->key_id;
    memcpy(&sx_keys[*sx_key_count].key, &value->aclfield.data, field_info->key_size);
    memcpy(&sx_keys[*sx_key_count].mask, &value->aclfield.mask, field_info->key_size);
    (*sx_key_count)++;

    *field_type = field_info->field_type;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_ip_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                            _In_ const sai_attribute_value_t *value,
                                            _In_ uint32_t                     attr_index,
                                            _In_ uint32_t                     table_index,
                                            _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                            _Inout_ uint32_t                 *sx_key_count,
                                            _Inout_ mlnx_acl_field_type_t    *field_type)
{
    sai_status_t                            status;
    sai_ip_addr_family_t                    addr_family;
    sai_ip_address_t                        sai_ip_addr, sai_ip_mask;
    const mlnx_acl_single_key_field_info_t *field_info;
    sx_ip_addr_t                            sx_ip_addr, sx_ip_mask;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6 == attr_id));

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP:
        addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6:
        addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        break;

    default:
        SX_LOG_ERR("Unexpected ip field type (%u)\n", attr_id);
        return SAI_STATUS_FAILURE;
    }

    field_info = &mlnx_acl_single_key_fields_info[attr_id];
    assert(NULL != field_info);

    memset(&sai_ip_addr, 0, sizeof(sai_ip_addr));
    memset(&sai_ip_mask, 0, sizeof(sai_ip_mask));
    memset(&sx_ip_addr, 0, sizeof(sx_ip_addr));
    memset(&sx_ip_mask, 0, sizeof(sx_ip_mask));

    sai_ip_addr.addr_family = addr_family;
    sai_ip_mask.addr_family = addr_family;

    if (SAI_IP_ADDR_FAMILY_IPV4 == addr_family) {
        sai_ip_addr.addr.ip4 = value->aclfield.data.ip4;
        sai_ip_mask.addr.ip4 = value->aclfield.mask.ip4;
    } else {
        memcpy(&sai_ip_addr.addr.ip6, &value->aclfield.data.ip6, sizeof(value->aclfield.data.ip6));
        memcpy(&sai_ip_mask.addr.ip6, &value->aclfield.mask.ip6, sizeof(value->aclfield.mask.ip6));
    }

    status = mlnx_translate_sai_ip_address_to_sdk(&sai_ip_addr, &sx_ip_addr);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_translate_sai_ip_address_to_sdk(&sai_ip_mask, &sx_ip_mask);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_keys[*sx_key_count].key_id = field_info->key_id;
    memcpy(&sx_keys[*sx_key_count].key, &sx_ip_addr, sizeof(sx_ip_addr));
    memcpy(&sx_keys[*sx_key_count].mask, &sx_ip_mask, sizeof(sx_ip_mask));

    (*sx_key_count)++;

    *field_type = field_info->field_type;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_packet_vlan_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                     _In_ const sai_attribute_value_t *value,
                                                     _In_ uint32_t                     attr_index,
                                                     _In_ uint32_t                     table_index,
                                                     _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                     _Inout_ uint32_t                 *sx_key_count,
                                                     _Inout_ mlnx_acl_field_type_t    *field_type)
{
    sai_packet_vlan_t packet_vlan;

    assert(SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN == attr_id);

    packet_vlan = value->aclfield.data.s32;

    switch (packet_vlan) {
    case SAI_PACKET_VLAN_UNTAG:
        sx_keys[*sx_key_count].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
        sx_keys[*sx_key_count].key.vlan_tagged  = false;
        sx_keys[*sx_key_count].mask.vlan_tagged = true;
        (*sx_key_count)++;
        break;

    case SAI_PACKET_VLAN_SINGLE_OUTER_TAG:
        sx_keys[*sx_key_count].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
        sx_keys[*sx_key_count].key.vlan_tagged  = true;
        sx_keys[*sx_key_count].mask.vlan_tagged = true;
        (*sx_key_count)++;

        *field_type = MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID;
        break;

    case SAI_PACKET_VLAN_DOUBLE_TAG:
        sx_keys[*sx_key_count].key_id           = FLEX_ACL_KEY_VLAN_TAGGED;
        sx_keys[*sx_key_count].key.vlan_tagged  = true;
        sx_keys[*sx_key_count].mask.vlan_tagged = true;
        (*sx_key_count)++;

        *field_type = MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID;
        break;

    default:
        SX_LOG_ERR("Invalid type of packet vlan (%d)\n", packet_vlan);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_tos_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                             _In_ const sai_attribute_value_t *value,
                                             _In_ uint32_t                     attr_index,
                                             _In_ uint32_t                     table_index,
                                             _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                             _Inout_ uint32_t                 *sx_key_count,
                                             _Inout_ mlnx_acl_field_type_t    *field_type)
{
    assert(SAI_ACL_ENTRY_ATTR_FIELD_TOS == attr_id);

    sx_keys[*sx_key_count].key_id    = FLEX_ACL_KEY_DSCP;
    sx_keys[*sx_key_count].key.dscp  = (value->aclfield.data.u8 >> 0x02) & 0x3f;
    sx_keys[*sx_key_count].mask.dscp = (value->aclfield.mask.u8 >> 0x02) & 0x3f;
    (*sx_key_count)++;

    sx_keys[*sx_key_count].key_id   = FLEX_ACL_KEY_ECN;
    sx_keys[*sx_key_count].key.ecn  = (value->aclfield.data.u8) & 0x03;
    sx_keys[*sx_key_count].mask.ecn = (value->aclfield.mask.u8) & 0x03;
    (*sx_key_count)++;

    *field_type = MLNX_ACL_FIELD_TYPE_IPV4;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_ip_type_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                 _In_ const sai_attribute_value_t *value,
                                                 _In_ uint32_t                     attr_index,
                                                 _In_ uint32_t                     table_index,
                                                 _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                 _Inout_ uint32_t                 *sx_key_count,
                                                 _Inout_ mlnx_acl_field_type_t    *field_type)
{
    sai_acl_ip_type_t ip_type;

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE == attr_id);

    ip_type = value->aclfield.data.s32;

    switch (ip_type) {
    case SAI_ACL_IP_TYPE_ANY:
        /* Do nothing */
        *field_type = MLNX_ACL_FIELD_TYPE_EMPTY;
        break;

    case SAI_ACL_IP_TYPE_IP:
        *field_type = MLNX_ACL_FIELD_TYPE_IP;
        break;

    case SAI_ACL_IP_TYPE_NON_IP:
        *field_type = MLNX_ACL_FIELD_TYPE_NON_IP;
        break;

    case SAI_ACL_IP_TYPE_IPV4ANY:
        *field_type = MLNX_ACL_FIELD_TYPE_IPV4;
        break;

    case SAI_ACL_IP_TYPE_NON_IPV4:
        *field_type = MLNX_ACL_FIELD_TYPE_NON_IPV4;
        break;

    case SAI_ACL_IP_TYPE_IPV6ANY:
        *field_type = MLNX_ACL_FIELD_TYPE_IPV6;
        break;

    case SAI_ACL_IP_TYPE_NON_IPV6:
        SX_LOG_ERR("SAI_ACL_IP_TYPE_NON_IPV6 is not supported");
        return SAI_STATUS_NOT_SUPPORTED;

    case SAI_ACL_IP_TYPE_ARP:
        *field_type = MLNX_ACL_FIELD_TYPE_ARP;
        break;

    case SAI_ACL_IP_TYPE_ARP_REQUEST:
        SX_LOG_ERR("SAI_ACL_IP_TYPE_NON_IPV6 is not supported");
        return SAI_STATUS_NOT_SUPPORTED;

    case SAI_ACL_IP_TYPE_ARP_REPLY:
        SX_LOG_ERR("SAI_ACL_IP_TYPE_NON_IPV6 is not supported");
        return SAI_STATUS_NOT_SUPPORTED;

    default:
        SX_LOG_ERR("Invalid type of ip type (%d)\n", ip_type);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_ip_frag_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                 _In_ const sai_attribute_value_t *value,
                                                 _In_ uint32_t                     attr_index,
                                                 _In_ uint32_t                     table_index,
                                                 _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                 _Inout_ uint32_t                 *sx_key_count,
                                                 _Inout_ mlnx_acl_field_type_t    *field_type)
{
    sai_acl_ip_frag_t ip_frag;

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG == attr_id);

    ip_frag = value->aclfield.data.s32;

    switch (ip_frag) {
    case SAI_ACL_IP_FRAG_ANY:
        sx_keys[*sx_key_count].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented  = true;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_NON_FRAG:
        sx_keys[*sx_key_count].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented  = false;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_NON_FRAG_OR_HEAD:
        sx_keys[*sx_key_count].key_id                     = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
        sx_keys[*sx_key_count].key.ip_fragment_not_first  = false;
        sx_keys[*sx_key_count].mask.ip_fragment_not_first = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_HEAD:
        sx_keys[*sx_key_count].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented  = true;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;

        sx_keys[*sx_key_count].key_id                     = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
        sx_keys[*sx_key_count].key.ip_fragment_not_first  = false;
        sx_keys[*sx_key_count].mask.ip_fragment_not_first = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_NON_HEAD:
        sx_keys[*sx_key_count].key_id             = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented  = true;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;

        sx_keys[*sx_key_count].key_id                     = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
        sx_keys[*sx_key_count].key.ip_fragment_not_first  = true;
        sx_keys[*sx_key_count].mask.ip_fragment_not_first = true;
        (*sx_key_count)++;
        break;

    default:
        SX_LOG_ERR("Invalid type of ip frag (%d)\n", ip_frag);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    *field_type = MLNX_ACL_FIELD_TYPE_IPV4;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_type_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                    _In_ const sai_attribute_value_t *value,
                                                    _In_ uint32_t                     attr_index,
                                                    _In_ uint32_t                     table_index,
                                                    _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                    _Inout_ uint32_t                 *sx_key_count,
                                                    _Inout_ mlnx_acl_field_type_t    *field_type)
{
    sai_status_t status;

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE == attr_id);

    status = mlnx_acl_range_validate_and_fetch(&value->aclfield.data.objlist,
                                               &sx_keys[*sx_key_count].key.l4_port_range,
                                               table_index);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_keys[*sx_key_count].key_id             = FLEX_ACL_KEY_L4_PORT_RANGE;
    sx_keys[*sx_key_count].mask.l4_port_range = true;
    (*sx_key_count)++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_user_meta_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                   _In_ const sai_attribute_value_t *value,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ uint32_t                     table_index,
                                                   _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                   _Inout_ uint32_t                 *sx_key_count,
                                                   _Inout_ mlnx_acl_field_type_t    *field_type)
{
    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == attr_id);

    if ((value->aclfield.data.u32 <= ACL_USER_META_RANGE_MAX) &&
        (value->aclfield.mask.u32 <= ACL_USER_META_RANGE_MAX)) {
        sx_keys[*sx_key_count].key_id          = FLEX_ACL_KEY_USER_TOKEN;
        sx_keys[*sx_key_count].key.user_token  = (uint16_t)value->aclfield.data.u32;
        sx_keys[*sx_key_count].mask.user_token = (uint16_t)value->aclfield.mask.u32;
        (*sx_key_count)++;
    } else {
        SX_LOG_ERR("ACL user Meta values %u %u is out of range [%d, %d]\n",
                   value->aclfield.data.u32, value->aclfield.mask.u32,
                   ACL_USER_META_RANGE_MIN, ACL_USER_META_RANGE_MAX);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
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

static sai_status_t acl_db_find_group_free_index(_Out_ uint32_t *free_index)
{
    sai_status_t status;
    uint32_t     ii;

    SX_LOG_ENTER();
    assert(free_index != NULL);

    for (ii = 0; ii < ACL_GROUP_NUMBER; ii++) {
        if (false == sai_acl_db_group_ptr(ii)->is_used) {
            *free_index                       = ii;
            sai_acl_db_group_ptr(ii)->is_used = true;
            status                            = SAI_STATUS_SUCCESS;
            break;
        }
    }

    if (ii == ACL_GROUP_NUMBER) {
        SX_LOG_ERR("Max Limit of ACL Groups Reached\n");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t acl_db_find_port_list_free_index(_Out_ uint32_t *free_index)
{
    sai_status_t status;
    uint32_t     ii;

    SX_LOG_ENTER();
    assert(free_index != NULL);

    for (ii = 0; ii < ACL_MAX_PORT_LISTS_COUNT; ii++) {
        if (false == acl_db_port_list(ii).is_used) {
            *free_index                  = ii;
            acl_db_port_list(ii).is_used = true;
            status                       = SAI_STATUS_SUCCESS;
            sai_acl_db->acl_settings_tbl->port_lists_count++;
            break;
        }
    }

    if (ii == ACL_MAX_PORT_LISTS_COUNT) {
        SX_LOG_ERR("Max Limit of ACL Port lists Reached\n");
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
        status = SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (false == acl_db_table(*acl_table_index).is_used) {
        SX_LOG_ERR("Table [%d] is deleted\n", *acl_table_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
    }

    *acl_entry_index = entry_data;
    if (!acl_entry_index_check_range(*acl_entry_index)) {
        SX_LOG_ERR("Got bad ACL Entry index from object_id - %x\n", *acl_entry_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (false == acl_db_entry(*acl_entry_index).is_used) {
        SX_LOG_ERR("Entry [%d] is deleted\n", *acl_entry_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
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
static sai_status_t extract_acl_table_index(_In_ sai_object_id_t table_object_id, _Out_ uint32_t      *acl_table_index)
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
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    if (false == acl_db_table(*acl_table_index).is_used) {
        SX_LOG_ERR("Table [%d] is deleted\n", *acl_table_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
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
           (SAI_ACL_ENTRY_ATTR_PRIORITY == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ADMIN_STATE == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    case SAI_ACL_ENTRY_ATTR_ADMIN_STATE:
        value->booldata = true;
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
    uint32_t             rule_count;

    assert(flex_acl_rule_p != NULL);

    SX_LOG_ENTER();

    rule_offset = acl_db_entry(acl_entry_index).offset;
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

    rule_count = 1;
    sx_status  = sx_api_acl_flex_rules_get(gh_sdk, region_id, &rule_offset, flex_acl_rule_p, &rule_count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get rules from region - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out_deinit;
    }

out_deinit:
    if (SAI_STATUS_SUCCESS != status) {
        mlnx_acl_flex_rule_free(flex_acl_rule_p);
    }

out:
    SX_LOG_EXIT();
    return status;
}

static void mlnx_acl_single_field_key_to_sai(_In_ sai_acl_entry_attr_t          attr_id,
                                             _Out_ sai_attribute_value_t       *value,
                                             _In_ const sx_flex_acl_key_desc_t *sx_key,
                                             _In_ uint32_t                      key_size)
{
    if (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == attr_id) {
        value->aclfield.data.u32 = sx_key->key.user_token;
        value->aclfield.mask.u32 = sx_key->mask.user_token;
    } else {
        memcpy(&value->aclfield.data, &sx_key->key, key_size);
        memcpy(&value->aclfield.mask, &sx_key->mask, key_size);
    }
}

static sai_status_t mlnx_acl_entry_single_key_field_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t                            status = SAI_STATUS_SUCCESS;
    sai_attr_id_t                           attr_id;
    const mlnx_acl_single_key_field_info_t *field_info;
    sx_flex_acl_flex_rule_t                 flex_acl_rule;
    sx_acl_key_t                            field_extra_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    uint32_t                                key_desc_index, ii, field_extra_key_count;
    uint32_t                                acl_table_index, acl_entry_index;
    bool                                    is_field_suppoted, is_key_type_present, is_extra_keys_present;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DSCP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == attr_id));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    field_info = mlnx_acl_single_key_field_info_fetch(attr_id);
    if (NULL == field_info) {
        SX_LOG_ERR("Faield to fetch info for attr (%d)\n", attr_id);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    field_extra_key_count = 0;

    status = mlnx_acl_field_types_to_extra_sx_keys(field_info->field_type, field_extra_keys, &field_extra_key_count);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, attr_id, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%d) is not supported for this entry [%lx]\n", attr_id, key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    memset(value, 0, sizeof(*value));

    /* Check if all the extra keys for this field are present in the rule
     * e.g. IS_IPV4 for src/dst ipv4
     */
    is_extra_keys_present = true;
    for (ii = 0; ii < field_extra_key_count; ii++) {
        mlnx_acl_flex_rule_key_find(&flex_acl_rule, field_extra_keys[ii], &key_desc_index, &is_key_type_present);

        if (false == is_key_type_present) {
            is_extra_keys_present = false;
            break;
        }
    }

    if (is_extra_keys_present) {
        mlnx_acl_flex_rule_key_find(&flex_acl_rule, field_info->key_id, &key_desc_index, &is_key_type_present);

        if (is_key_type_present) {
            value->aclfield.enable = true;
            mlnx_acl_single_field_key_to_sai(attr_id,
                                             value,
                                             &flex_acl_rule.key_desc_list_p[key_desc_index],
                                             field_info->key_size);
        } else {
            value->aclfield.enable = false;
        }
    } else {
        value->aclfield.enable = false;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_type_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                acl_table_index, acl_entry_index, key_desc_index;
    bool                    is_key_present;

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        acl_table_unlock(acl_table_index);
        SX_LOG_EXIT();
        return status;
    }

    value->aclfield.enable = true;

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, FLEX_ACL_KEY_L3_TYPE, &key_desc_index, &is_key_present);

    if (is_key_present) {
        if (SX_ACL_L3_TYPE_IPV6 == flex_acl_rule.key_desc_list_p[key_desc_index].key.l3_type) {
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IPV6ANY;
        } else {
            assert(SX_ACL_L3_TYPE_ARP == flex_acl_rule.key_desc_list_p[key_desc_index].key.l3_type);
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_ARP;
        }

        goto out;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, FLEX_ACL_KEY_IS_IP_V4, &key_desc_index, &is_key_present);

    if (is_key_present) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v4) {
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IPV4ANY;
        } else {
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_NON_IPV4;
        }

        goto out;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, FLEX_ACL_KEY_IP_OK, &key_desc_index, &is_key_present);

    if (is_key_present) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key.ip_ok) {
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IP;
        } else {
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_NON_IP;
        }
    } else {
        value->aclfield.data.s32 = SAI_ACL_IP_TYPE_ANY;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_frag_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_acl_key_t            ip_frag_key, ip_frag_not_first_key;
    uint32_t                key_desc_index         = 0;
    uint32_t                ip_frag_key_desc_index = 0, ip_frag_not_first_key_desc_index = 0;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_ip_frag_key_present = false, is_ip_frag_not_first_key_present = false;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG == (int64_t)arg);

    ip_frag_key           = FLEX_ACL_KEY_IP_FRAGMENTED;
    ip_frag_not_first_key = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    value->aclfield.enable = true;

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
        value->aclfield.enable = false;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

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
    sai_attr_id_t           attr_id;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_ip_addr_t            ipaddr_data, ipaddr_mask;
    sai_ip_address_t        ip_address_data, ip_address_mask;
    uint32_t                key_id         = 0;
    uint32_t                key_desc_index = 0;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_key_type_present = true;
    bool                    is_field_suppoted;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6 == attr_id));

    memset(&ipaddr_data, 0, sizeof(ipaddr_data));
    memset(&ip_address_data, 0, sizeof(ip_address_data));
    memset(&ipaddr_mask, 0, sizeof(ipaddr_mask));
    memset(&ip_address_mask, 0, sizeof(ip_address_mask));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, attr_id, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%d) is not supported for this entry [%lx]\n", attr_id, key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6:
        key_id = FLEX_ACL_KEY_SIPV6;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6:
        key_id = FLEX_ACL_KEY_DIPV6;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
        key_id = FLEX_ACL_KEY_SIP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
        key_id = FLEX_ACL_KEY_DIP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP:
        key_id = FLEX_ACL_KEY_INNER_SIP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP:
        key_id = FLEX_ACL_KEY_INNER_DIP;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6:
        key_id = FLEX_ACL_KEY_INNER_SIPV6;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6:
        key_id = FLEX_ACL_KEY_INNER_DIPV6;
        break;

    default:
        SX_LOG_ERR(" Unexpected attribute id - %d\n", attr_id);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    value->aclfield.enable = true;

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, key_id, &key_desc_index, &is_key_type_present);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6:
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
            value->aclfield.enable = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6:
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
            value->aclfield.enable = false;
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
            value->aclfield.enable = false;
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
            value->aclfield.enable = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP:
        if (is_key_type_present) {
            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_sip,
                                                          &ip_address_data);
            if (SAI_ERR(status)) {
                goto out_deinit;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_sip,
                &ip_address_mask);
            if (SAI_ERR(status)) {
                goto out_deinit;
            }
            memcpy(&value->aclfield.data.ip4, &ip_address_data.addr.ip4,
                   sizeof(value->ipaddr.addr.ip4));
            memcpy(&value->aclfield.mask.ip4, &ip_address_mask.addr.ip4,
                   sizeof(value->ipaddr.addr.ip4));
        } else {
            value->aclfield.enable = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP:
        if (is_key_type_present) {
            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_dip,
                                                          &ip_address_data);
            if (SAI_ERR(status)) {
                goto out_deinit;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_dip,
                &ip_address_mask);
            if (SAI_ERR(status)) {
                goto out_deinit;
            }
            memcpy(&value->aclfield.data.ip4, &ip_address_data.addr.ip4,
                   sizeof(value->ipaddr.addr.ip4));
            memcpy(&value->aclfield.mask.ip4, &ip_address_mask.addr.ip4,
                   sizeof(value->ipaddr.addr.ip4));
        } else {
            value->aclfield.enable = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6:
        if (is_key_type_present) {
            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_sipv6,
                &ip_address_data);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_sipv6,
                &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
            memcpy(&value->aclfield.data.ip6, &ip_address_data.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
            memcpy(&value->aclfield.mask.ip6, &ip_address_mask.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
        } else {
            value->aclfield.enable = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6:
        if (is_key_type_present) {
            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].key.inner_dipv6,
                &ip_address_data);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_dipv6,
                &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
            memcpy(&value->aclfield.data.ip6, &ip_address_data.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
            memcpy(&value->aclfield.mask.ip6, &ip_address_mask.addr.ip6,
                   sizeof(value->ipaddr.addr.ip6));
        } else {
            value->aclfield.enable = false;
        }
        break;
    }

out_deinit:
    mlnx_acl_flex_rule_free(&flex_acl_rule);

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
    sai_status_t             status;
    sx_port_log_id_t         sx_port_list[MAX_PORTS] = {0};
    sx_flex_acl_flex_rule_t *out_port_rules          = NULL;
    uint32_t                 acl_table_index, acl_entry_index, rule_count;
    uint32_t                 out_port_key_desc_index;
    uint32_t                 port_count = 0, ii;
    bool                     is_field_suppoted, is_in_port_present = false, is_out_port_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, (int64_t)arg, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%ld) is not supported for this entry [%lx]\n",
                   (int64_t)arg,
                   key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    if (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg) {
        status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index,
                                                   &out_port_rules, NULL, NULL, &rule_count);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        mlnx_acl_flex_rule_key_find(&out_port_rules[0], FLEX_ACL_KEY_DST_PORT, &out_port_key_desc_index,
                                    &is_out_port_present);

        if (false == is_out_port_present) {
            assert(rule_count == 1);
            port_count = 0;
        } else {
            port_count = rule_count;
            for (ii = 0; ii < port_count; ii++) {
                sx_port_list[ii] = out_port_rules[ii].key_desc_list_p[out_port_key_desc_index].key.dst_port;
            }
        }
    } else { /* IN_PORTS */
        is_in_port_present = (ACL_INVALID_DB_INDEX != acl_db_entry(acl_entry_index).rx_list_index);
        if (false == is_in_port_present) {
            port_count = 0;
        } else {
            status = mlnx_acl_fetch_sx_port_list(acl_db_entry(acl_entry_index).rx_list_index,
                                                 sx_port_list, &port_count);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }
    }

    value->aclfield.enable = (port_count > 0);

    if (value->aclfield.data.objlist.count < port_count) {
        value->aclfield.data.objlist.count = port_count;
        status                             = SAI_STATUS_BUFFER_OVERFLOW;
        SX_LOG_ERR(" Re-allocate list size as list size is not large enough \n");
        goto out;
    } else if (value->aclfield.data.objlist.count > port_count) {
        value->aclfield.data.objlist.count = port_count;
    }

    for (ii = 0; ii < port_count; ii++) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, sx_port_list[ii], NULL,
                                    &value->aclfield.data.objlist.list[ii]);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }
    }

out:
    acl_table_unlock(acl_table_index);
    mlnx_acl_flex_rule_list_free(out_port_rules, rule_count);

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
    sx_flex_acl_flex_rule_t flex_acl_rule;
    sx_acl_key_t            key_id = 0;
    uint32_t                key_desc_index;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_field_suppoted, is_key_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, (int64_t)arg, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%ld) is not supported for this entry [%lx]\n",
                   (int64_t)arg,
                   key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, key_id, &key_desc_index, &is_key_type_present);

    value->aclfield.enable = true;

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        if (is_key_type_present) {
            status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                        flex_acl_rule.key_desc_list_p[key_desc_index].key.
                                        src_port, NULL, &value->aclfield.data.oid);
            if (SAI_STATUS_SUCCESS != status) {
                goto out_deinit;
            }
        } else {
            value->aclfield.enable = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        if (acl_db_entry(acl_entry_index).rule_number > 1) {
            SX_LOG_ERR(" Entry contains more then one OUT_PORT\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        } else {
            if (is_key_type_present) {
                status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                            flex_acl_rule.key_desc_list_p[key_desc_index].key.dst_port,
                                            NULL,
                                            &value->aclfield.data.oid);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out_deinit;
                }
            } else {
                value->aclfield.enable = false;
            }
        }
        break;
    }

out_deinit:
    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_vlan_tags_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                key_desc_index;
    uint32_t                acl_table_index, acl_entry_index;
    uint32_t                vlan_tagged_key_desc_index = 0, inner_vlan_valid_key_desc_index = 0;
    bool                    is_vlan_tagged             = false, is_inner_vlan_valid = false, is_field_suppoted;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, (int64_t)arg, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%ld) is not supported for this entry [%lx]\n",
                   (int64_t)arg,
                   key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

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

    value->aclfield.enable = true;

    if (is_vlan_tagged) {
        if (!flex_acl_rule.key_desc_list_p[vlan_tagged_key_desc_index].key.vlan_tagged) {
            value->aclfield.data.s32 = SAI_PACKET_VLAN_UNTAG;
        } else if (!flex_acl_rule.key_desc_list_p[inner_vlan_valid_key_desc_index].key.inner_vlan_valid) {
            value->aclfield.data.s32 = SAI_PACKET_VLAN_SINGLE_OUTER_TAG;
        } else {
            value->aclfield.data.s32 = SAI_PACKET_VLAN_DOUBLE_TAG;
        }
    } else {
        value->aclfield.enable = false;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static bool mlnx_acl_ip_idnet_key_is_supported(_In_ uint32_t table_index)
{
    if (false == acl_db_table(table_index).is_ip_ident_used) {
        return false;
    }

    assert(sai_acl_db->acl_settings_tbl->ip_ident_keys.refs > 0);
    return true;
}

static sai_status_t mlnx_acl_entry_ip_ident_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    const sx_acl_key_t     *sx_ip_ident_keys;
    uint32_t                first_sx_key_index, second_sx_key_index;
    uint32_t                acl_table_index, acl_entry_index;
    uint16_t                data, mask;
    bool                    is_first_sx_key_present, is_second_sx_key_present, rule_inited = false;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    if (false == mlnx_acl_ip_idnet_key_is_supported(acl_table_index)) {
        SX_LOG_ERR("Invalid Attribute to Get : IP_IDENTIFICATION\n");
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    rule_inited = true;

    sx_ip_ident_keys = sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys;

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, sx_ip_ident_keys[0], &first_sx_key_index, &is_first_sx_key_present);
    mlnx_acl_flex_rule_key_find(&flex_acl_rule, sx_ip_ident_keys[1], &second_sx_key_index, &is_second_sx_key_present);

    if (is_first_sx_key_present != is_second_sx_key_present) {
        SX_LOG_ERR("Faield to get IP_IDENTIFICATION failed - sx rule is broken\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (false == is_first_sx_key_present) {
        value->aclfield.enable = false;
        goto out;
    }

    data = flex_acl_rule.key_desc_list_p[first_sx_key_index].key.custom_byte;
    mask = flex_acl_rule.key_desc_list_p[first_sx_key_index].mask.custom_byte;

    data |= flex_acl_rule.key_desc_list_p[second_sx_key_index].key.custom_byte << 8;
    mask |= flex_acl_rule.key_desc_list_p[second_sx_key_index].mask.custom_byte << 8;

    value->aclfield.enable   = true;
    value->aclfield.data.u16 = htons(data);
    value->aclfield.mask.u16 = htons(mask);

out:
    acl_table_unlock(acl_table_index);

    if (rule_inited) {
        mlnx_acl_flex_rule_free(&flex_acl_rule);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_ident_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    const sx_acl_key_t        *sx_ip_ident_keys;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p    = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p     = NULL;
    uint32_t                   flex_acl_rules_num = 0;
    uint32_t                   acl_table_index, acl_entry_index, ii;
    uint32_t                   first_sx_key_index, second_sx_key_index;
    bool                       is_first_sx_key_present, is_second_sx_key_present;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    if (false == mlnx_acl_ip_idnet_key_is_supported(acl_table_index)) {
        SX_LOG_ERR("Invalid Attribute to Set : IP_IDENTIFICATION\n");
        status = SAI_STATUS_INVALID_ATTRIBUTE_0;
        goto out;
    }

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    sx_ip_ident_keys = sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys;

    mlnx_acl_flex_rule_key_find(flex_acl_rule_p, sx_ip_ident_keys[0], &first_sx_key_index, &is_first_sx_key_present);
    mlnx_acl_flex_rule_key_find(flex_acl_rule_p, sx_ip_ident_keys[1], &second_sx_key_index, &is_second_sx_key_present);

    if (is_first_sx_key_present != is_second_sx_key_present) {
        SX_LOG_ERR("Faield to get IP_IDENTIFICATION failed - sx rule is broken\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (is_first_sx_key_present) {
            mlnx_acl_flex_rule_key_del_by_key_id(&flex_acl_rule_p[ii], sx_ip_ident_keys[0]);
            mlnx_acl_flex_rule_key_del_by_key_id(&flex_acl_rule_p[ii], sx_ip_ident_keys[1]);
        }

        if (value->aclfield.enable) {
            mlnx_acl_ip_ident_key_desc_create(value->aclfield.data.u16, value->aclfield.mask.u16,
                                              flex_acl_rule_p[ii].key_desc_list_p, flex_acl_rule_p[ii].key_desc_count);
            flex_acl_rule_p[ii].key_desc_count += ACL_IP_IDENT_FIELD_BYTE_COUNT;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, flex_acl_rules_num);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_acl_rules_num);
    free(offsets_list_p);

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
    uint32_t                     acl_table_index, acl_entry_index;
    bool                         is_trap_action_present    = false;
    bool                         is_forward_action_present = false;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_range_list_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t                    status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t         rule;
    const sx_flex_acl_port_range_t *sx_port_range;
    uint32_t                        acl_table_index, acl_entry_index;
    uint32_t                        key_desc_index, range_count, ii;
    bool                            is_range_key_present = false, rule_inited = false;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }
    rule_inited = true;

    mlnx_acl_flex_rule_key_find(&rule, FLEX_ACL_KEY_L4_PORT_RANGE, &key_desc_index, &is_range_key_present);

    if (false == is_range_key_present) {
        range_count = 0;
    } else {
        sx_port_range = &rule.key_desc_list_p[key_desc_index].key.l4_port_range;
        range_count   = sx_port_range->port_range_cnt;
    }

    if (value->aclfield.data.objlist.count < range_count) {
        value->aclfield.data.objlist.count = range_count;
        status                             = SAI_STATUS_BUFFER_OVERFLOW;
        SX_LOG_ERR(" Re-allocate list size as list size is not large enough \n");
        goto out;
    }

    for (ii = 0; ii < range_count; ii++) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_RANGE, sx_port_range->port_range_list[ii], NULL,
                                    &value->aclfield.data.objlist.list[ii]);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }
    }

    value->aclfield.data.objlist.count = range_count;

out:
    acl_table_unlock(acl_table_index);

    if (rule_inited) {
        mlnx_acl_flex_rule_free(&rule);
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
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule;
    uint32_t                acl_table_index, acl_entry_index, counter_id;
    bool                    is_action_type_present = false;
    sx_acl_pbs_id_t         action_id              = 0, action_index;
    uint32_t                policer_db_entry_index;
    sai_object_id_t         sai_policer;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_COUNTER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN == (int64_t)arg) ||
           (SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    case SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR:
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

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, action_id, &action_index, &is_action_type_present);

    switch ((int64_t)arg) {
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

    case SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR:
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
    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_redirect_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    sai_status_t                     status;
    sx_flex_acl_flex_rule_t          rule;
    uint32_t                         acl_table_index, acl_entry_index;
    sx_port_id_t                     object_id_data;
    sx_ecmp_id_t                     sx_ecmp_id;
    sx_port_log_id_t                 pbs_ports[MAX_PORTS] = {0};
    port_pbs_index_t                 port_pbs_index;
    sai_object_type_t                object_type;
    acl_entry_redirect_type_t        entry_redirect_type;
    const acl_entry_redirect_data_t *entry_redirect_data;
    lag_pbs_index_t                  lag_pbs_index;
    uint32_t                         action_index = 0, pbs_ports_number, ii;
    bool                             is_action_present, rule_inited = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    entry_redirect_data = &acl_db_entry(acl_entry_index).redirect_data;
    entry_redirect_type = entry_redirect_data->redirect_type;

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        if (ACL_ENTRY_REDIRECT_TYPE_REDIRECT != entry_redirect_type) {
            SX_LOG_ERR(" Invalid Attribute to get : ACL Action Redirect \n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
        if (ACL_ENTRY_REDIRECT_TYPE_REDIRECT_LIST != entry_redirect_type) {
            SX_LOG_ERR(" Invalid Attribute to get : ACL Action Redirect \n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }
        break;

    default:
        assert(false);
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }
    rule_inited = true;

    is_action_present = false;
    for (ii = 0; ii < rule.action_count; ii++) {
        if ((rule.action_list_p[ii].type == SX_FLEX_ACL_ACTION_PBS) ||
            (rule.action_list_p[ii].type == SX_FLEX_ACL_ACTION_UC_ROUTE)) {
            if (is_action_present) {
                SX_LOG_ERR("Flex action type related to SAI Redirect actions appears twice in flex rule\n");
                assert(false);
            }

            is_action_present = true;
            action_index      = ii;
        }
    }

    assert(is_action_present);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        if (rule.action_list_p[action_index].type == SX_FLEX_ACL_ACTION_PBS) {
            if (is_entry_redirect_pbs_type_lag(*entry_redirect_data)) {
                lag_pbs_index = entry_redirect_data->lag_pbs_index;
                assert(lag_pbs_index < MAX_PORTS);
                assert(acl_db_lag_pbs(lag_pbs_index).ref_counter > 0);

                object_id_data = acl_lag_pbs_index_to_sx(lag_pbs_index);
                object_type    = SAI_OBJECT_TYPE_LAG;
            } else {
                port_pbs_index   = entry_redirect_data->port_pbs_index;
                pbs_ports_number = 1;
                status           = mlnx_acl_pbs_map_get_ports(port_pbs_index, &object_id_data, &pbs_ports_number);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }

                object_type = SAI_OBJECT_TYPE_PORT;
            }

            status = mlnx_create_object(object_type, object_id_data, NULL, &value->aclaction.parameter.oid);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        } else { /* UC_ROUTE */
            assert(rule.action_list_p[action_index].fields.action_uc_route.uc_route_type == SX_UC_ROUTE_TYPE_NEXT_HOP);

            sx_ecmp_id = rule.action_list_p[action_index].fields.action_uc_route.uc_route_param.ecmp_id;
            status     = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                                            sx_ecmp_id,
                                            NULL,
                                            &value->aclaction.parameter.oid);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
        assert(is_entry_redirect_pbs_type_port(*entry_redirect_data));

        port_pbs_index   = entry_redirect_data->port_pbs_index;
        pbs_ports_number = value->aclaction.parameter.objlist.count;

        status = mlnx_acl_pbs_map_get_ports(port_pbs_index, pbs_ports, &pbs_ports_number);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        if (value->aclaction.parameter.objlist.count > pbs_ports_number) {
            value->aclaction.parameter.objlist.count = pbs_ports_number;
        }

        for (ii = 0; ii < pbs_ports_number; ii++) {
            status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, pbs_ports[ii], NULL,
                                        &value->aclaction.parameter.objlist.list[ii]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }

        break;

    default:
        assert(false);
    }

out:
    acl_table_unlock(acl_table_index);

    if (rule_inited) {
        mlnx_acl_flex_rule_free(&rule);
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
    uint32_t                acl_table_index, acl_entry_index, key_desc_index;
    bool                    is_field_suppoted, is_key_type_present = false, is_key_id_two_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_TOS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, (int64_t)arg, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%ld) is not supported for this entry [%lx]\n",
                   (int64_t)arg,
                   key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    value->aclfield.data.u8 = 0;      /* Initialise the value */
    mlnx_acl_flex_rule_key_find(&flex_acl_rule, FLEX_ACL_KEY_ECN, &key_desc_index, &is_key_type_present);

    if (is_key_type_present) {
        value->aclfield.data.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].key.ecn;
        value->aclfield.mask.u8 = flex_acl_rule.key_desc_list_p[key_desc_index].mask.ecn;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, FLEX_ACL_KEY_DSCP, &key_desc_index, &is_key_id_two_present);

    if (is_key_id_two_present) {
        value->aclfield.data.u8 = value->aclfield.data.u8 +
                                  (flex_acl_rule.key_desc_list_p[key_desc_index].key.dscp << 0x02);
        value->aclfield.mask.u8 = value->aclfield.mask.u8 +
                                  (flex_acl_rule.key_desc_list_p[key_desc_index].mask.dscp << 0x02);
    }

    if (!is_key_type_present && !is_key_id_two_present) {
        value->aclfield.enable = false;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

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
    sx_flex_acl_flex_rule_t        flex_acl_rule;
    sx_flex_acl_flex_action_type_t action_type = 0;
    uint32_t                       acl_table_index, acl_entry_index, flex_action_index;
    bool                           is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI == (int64_t)arg));

    memset(&flex_acl_rule, 0, sizeof(sx_flex_acl_flex_rule_t));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, action_type, &flex_action_index, &is_action_type_present);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID:
        if (is_action_type_present) {
            value->aclaction.parameter.u16 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_id.vlan_id;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Inner Vlan Id\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI:
        if (is_action_type_present) {
            value->aclaction.parameter.u8 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_prio.pcp;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Inner Vlan Pri\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID:
        if (is_action_type_present) {
            value->aclaction.parameter.u16 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_id.vlan_id;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Outer Vlan Id\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI:
        if (is_action_type_present) {
            value->aclaction.parameter.u8 =
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_prio.pcp;
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Outer Vlan Pri\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        break;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

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
    uint32_t                acl_entry_index, acl_table_index, flex_action_index;
    bool                    is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, SX_FLEX_ACL_ACTION_MIRROR,
                                   &flex_action_index, &is_action_type_present);

    if (is_action_type_present) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_MIRROR_SESSION,
                                    flex_acl_rule.action_list_p[flex_action_index].fields.action_mirror.session_id,
                                    NULL,
                                    &value->aclaction.parameter.objlist.list[0]);
        if (SAI_STATUS_SUCCESS != status) {
            goto out_deinit;
        }
    } else {
        SX_LOG_ERR(" Invalid Attribute to Get :  ACTION MIRROR \n");
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

out_deinit:
    mlnx_acl_flex_rule_free(&flex_acl_rule);

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
    uint32_t                       acl_table_index, acl_entry_index, flex_action_index;
    bool                           is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, action_type,
                                   &flex_action_index, &is_action_type_present);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC:
        if (is_action_type_present) {
            memcpy(value->aclaction.parameter.mac,
                   &flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac, \
                   sizeof(value->aclaction.parameter.mac));
        } else {
            SX_LOG_ERR(" Invalid Action to Get :Set SRC MAC\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC:
        if (is_action_type_present) {
            memcpy(value->aclaction.parameter.mac,
                   &flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dst_mac.mac, \
                   sizeof(value->aclaction.parameter.mac));
        } else {
            SX_LOG_ERR(" Invalid Action to Get :DST MAC\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        break;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t fetch_flex_acl_rule_params_to_set(_In_ uint32_t                      acl_table_index,
                                                      _In_ uint32_t                      acl_entry_index,
                                                      _Inout_ sx_flex_acl_flex_rule_t  **rules,
                                                      _Inout_opt_ sx_acl_rule_offset_t **offsets,
                                                      _Inout_opt_ sx_acl_region_id_t    *region_id,
                                                      _Inout_ uint32_t                  *rule_count)
{
    sai_status_t             status;
    sx_status_t              sx_status;
    sx_acl_key_type_t        enrty_key_type;
    sx_acl_region_id_t       entry_region_id, entry_rule_count;
    sx_acl_rule_offset_t    *entry_offsets = NULL;
    sx_flex_acl_flex_rule_t *entry_rules   = NULL;

    assert((rules != NULL) && (rule_count != NULL));

    enrty_key_type   = acl_db_table(acl_table_index).key_type;
    entry_region_id  = acl_db_table(acl_table_index).region_id;
    entry_rule_count = acl_db_entry(acl_entry_index).rule_number;

    status = mlnx_acl_flex_rule_list_init(&entry_rules, entry_rule_count, enrty_key_type);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    entry_offsets = (sx_acl_rule_offset_t*)malloc(sizeof(sx_acl_rule_offset_t) * entry_rule_count);
    if (NULL == entry_offsets) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(entry_offsets, 0, sizeof(sx_acl_rule_offset_t) * entry_rule_count);

    status = acl_get_entries_offsets(acl_entry_index, entry_rule_count, entry_offsets);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    sx_status = sx_api_acl_flex_rules_get(gh_sdk, entry_region_id, entry_offsets, entry_rules,
                                          &entry_rule_count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get rules from region - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    *rules      = entry_rules;
    *rule_count = entry_rule_count;

    if (region_id) {
        *region_id = entry_region_id;
    }

    if (offsets) {
        *offsets = entry_offsets;
    } else {
        free(entry_offsets);
        entry_offsets = NULL;
    }

out:
    if (SAI_STATUS_SUCCESS != status) {
        free(entry_offsets);
        mlnx_acl_flex_rule_list_free(entry_rules, entry_rule_count);
        *rules = NULL;
        if (offsets) {
            *offsets = NULL;
        }
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

    if ((value->u32 < ACL_MIN_ENTRY_PRIO) || (value->u32 > ACL_MAX_ENTRY_PRIO)) {
        SX_LOG_ERR(" priority %u out of range (%u,%u)\n", value->u32, ACL_MIN_ENTRY_PRIO, ACL_MAX_ENTRY_PRIO);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    entry_rules_num = acl_db_entry(acl_entry_index).rule_number;
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

static sai_status_t mlnx_acl_entry_field_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t               status;
    sx_acl_region_id_t         region_id = 0;
    const sx_acl_key_t        *ip_type_keys;
    sx_acl_key_t               field_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    sx_flex_acl_key_desc_t     rule_extra_key_desc[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p = NULL;
    sx_flex_acl_rule_offset_t *offsets_list_p  = NULL;
    sai_acl_entry_attr_t       attr_id;
    mlnx_acl_field_type_t      field_type;
    uint32_t                   acl_table_index, acl_entry_index;
    uint32_t                   rule_count, field_key_count, field_extra_key_count, ii;
    uint32_t                   rule_index, field_key_index, found_key_index, ip_type_key_count;
    bool                       is_key_present;

    SX_LOG_ENTER();

    attr_id = (int64_t)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DSCP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TOS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE) == attr_id);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    field_key_count = 0;

    status = mlnx_acl_field_info_data_fetch(attr_id, &field_type, field_keys, &field_key_count);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &flex_acl_rule_p,
                                               &offsets_list_p, &region_id, &rule_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fetch ACL rule params\n");
        goto out;
    }

    /* Upadte of IP Type is limited
     * because all the L3/L4 keys use IP Type related keys
     * So it is only allowed when entry doesn't contain any L3/L4 fields
     */
    if (SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE == attr_id) {
        ip_type_keys      = mlnx_acl_multi_key_fields_info[SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE].key_list;
        ip_type_key_count = mlnx_acl_multi_key_fields_info[SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE].key_count;

        for (ii = 0; ii < ip_type_key_count; ii++) {
            mlnx_acl_flex_rule_key_find(flex_acl_rule_p, ip_type_keys[ii], &found_key_index, &is_key_present);

            if (is_key_present) {
                SX_LOG_ERR("Failed to update IP Type - entry already contains a field with specific IP Type\n");
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        }
    }

    for (rule_index = 0; rule_index < rule_count; rule_index++) {
        /* Remove all the sx keys related to this sai field */
        for (field_key_index = 0; field_key_index < field_key_count; field_key_index++) {
            mlnx_acl_flex_rule_key_find(&flex_acl_rule_p[rule_index],
                                        field_keys[field_key_index],
                                        &found_key_index,
                                        &is_key_present);

            if (is_key_present) {
                mlnx_acl_flex_rule_key_del(&flex_acl_rule_p[rule_index], found_key_index);
            }
        }

        status = mlnx_acl_entry_field_to_sx(attr_id, value, 0, acl_table_index,
                                            flex_acl_rule_p[rule_index].key_desc_list_p,
                                            &flex_acl_rule_p[rule_index].key_desc_count, &field_type);
        if (SAI_ERR(status)) {
            goto out;
        }

        field_extra_key_count = 0;
        status                = mlnx_acl_field_types_to_sx(field_type, rule_extra_key_desc, &field_extra_key_count);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_acl_extra_key_descs_merge(&flex_acl_rule_p[rule_index],
                                                rule_extra_key_desc,
                                                field_extra_key_count);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets_list_p,
                                            flex_acl_rule_p, rule_count);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, rule_count);
    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_out_ports_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t first_rule, *rules = NULL;
    sx_acl_key_type_t       key_type;
    sx_port_log_id_t        sx_port_list[MAX_PORTS] = {0};
    const sai_object_id_t  *port_obj_list           = NULL;
    uint32_t                acl_table_index, acl_entry_index;
    uint32_t                rule_count = 0, inited_rule_count = 0, port_count;
    uint32_t                port_key_index;
    bool                    is_key_type_present = false, first_rule_inited = false;
    uint32_t                ii;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);

    if (acl_db_table(acl_table_index).stage != SAI_ACL_STAGE_EGRESS) {
        SX_LOG_ERR("Port type(OUT PORT) and stage do not match\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    key_type = acl_db_table(acl_table_index).key_type;

    port_count = 0;
    if (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == (int64_t)arg) {
        if (true == value->aclfield.enable) {
            port_obj_list = value->aclfield.data.objlist.list;
            port_count    = value->aclfield.data.objlist.count;
            for (ii = 0; ii < port_count; ii++) {
                status = mlnx_sai_port_to_sx(value->aclfield.data.objlist.list[ii], &sx_port_list[ii]);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }
            }
        }
    } else {
        if (true == value->aclfield.enable) {
            port_obj_list = &value->aclfield.data.oid;
            port_count    = 1;
            status        = mlnx_sai_port_to_sx(value->aclfield.data.oid, &sx_port_list[0]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }
    }

    status = fetch_flex_acl_rule_params_to_get(acl_table_index, acl_entry_index, &first_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }
    first_rule_inited = true;

    mlnx_acl_flex_rule_key_find(&first_rule, FLEX_ACL_KEY_DST_PORT, &port_key_index, &is_key_type_present);

    if ((false == is_key_type_present) && (0 != port_count)) {
        first_rule.key_desc_count++;
        first_rule.key_desc_list_p[port_key_index].key_id = FLEX_ACL_KEY_DST_PORT;
    }

    if ((true == is_key_type_present) && (0 == port_count)) {
        mlnx_acl_flex_rule_key_del(&first_rule, port_key_index);
    }

    rule_count = MAX(port_count, 1);

    status = mlnx_acl_flex_rule_list_init(&rules, rule_count, key_type);
    if (SAI_ERR(status)) {
        goto out;
    }
    inited_rule_count = rule_count;

    mlnx_acl_fill_rule_list(first_rule, rules, rule_count, sx_port_list, port_count, port_key_index);

    status = mlnx_acl_entry_modify_rules(acl_entry_index, acl_table_index, rules, rule_count);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    status = mlnx_acl_entry_res_ref_update(acl_entry_index, ACL_PORT_REFS_DST, port_obj_list, port_count);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    if (first_rule_inited) {
        mlnx_acl_flex_rule_free(&first_rule);
    }

    mlnx_acl_flex_rule_list_free(rules, inited_rule_count);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_in_ports_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sai_status_t               status;
    sx_acl_region_id_t         region_id;
    sx_flex_acl_flex_rule_t   *rules        = NULL;
    sx_flex_acl_rule_offset_t *offsets      = NULL;
    sx_acl_port_list_id_t      sx_port_list = 0;
    sx_port_log_id_t           sx_port;
    const sai_object_id_t     *port_obj_list = NULL;
    uint32_t                   port_list_index, port_list_index_to_delete = ACL_INVALID_DB_INDEX;
    uint32_t                   rule_count = 0, ii;
    uint32_t                   acl_entry_index, acl_table_index, new_port_count = 0;
    uint8_t                    key_desc_index, src_port_key_index = 0, rx_key_index = 0;
    bool                       is_src_port_key_present = false, is_rx_key_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &rules,
                                               &offsets, &region_id, &rule_count);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    for (key_desc_index = 0; key_desc_index < rules[0].key_desc_count; key_desc_index++) {
        if (FLEX_ACL_KEY_SRC_PORT == rules[0].key_desc_list_p[key_desc_index].key_id) {
            is_src_port_key_present = true;
            src_port_key_index      = key_desc_index;
        }

        if (FLEX_ACL_KEY_RX_LIST == rules[0].key_desc_list_p[key_desc_index].key_id) {
            is_rx_key_present = true;
            rx_key_index      = key_desc_index;
        }

        if (is_src_port_key_present && is_rx_key_present) {
            break;
        }
    }

    if ((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == (int64_t)arg) &&
        (true == is_rx_key_present)) {
        SX_LOG_ERR("Entry already has IN_PORTS attribute\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if ((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) &&
        (true == is_src_port_key_present)) {
        SX_LOG_ERR("Entry already has IN_PORT attribute\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == (int64_t)arg) {
        if ((false == value->aclfield.enable) || (0 == value->aclfield.data.objlist.count)) {
            port_list_index_to_delete = acl_db_entry(acl_entry_index).rx_list_index;
        } else {
            if (ACL_INVALID_DB_INDEX == acl_db_entry(acl_entry_index).rx_list_index) {
                status = mlnx_acl_sx_list_set(SX_ACCESS_CMD_CREATE, &value->aclfield.data.objlist,
                                              &acl_db_entry(acl_entry_index).rx_list_index);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }
            } else {
                status = mlnx_acl_sx_list_set(SX_ACCESS_CMD_SET, &value->aclfield.data.objlist,
                                              &acl_db_entry(acl_entry_index).rx_list_index);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }
            }

            port_list_index = acl_db_entry(acl_entry_index).rx_list_index;
            sx_port_list    = acl_db_port_list(port_list_index).sx_port_list_id;

            if (false == is_rx_key_present) {
                rx_key_index = key_desc_index;
            }

            new_port_count = value->aclfield.data.objlist.count;
            port_obj_list  = value->aclfield.data.objlist.list;
        }
    } else { /* IN_PORT */
        if (value->aclfield.enable) {
            status = mlnx_sai_port_to_sx(value->aclfield.data.oid, &sx_port);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            if (false == is_src_port_key_present) {
                src_port_key_index = key_desc_index;
            }

            new_port_count = 1;
            port_obj_list  = &value->aclfield.data.oid;
        }
    }

    for (ii = 0; ii < rule_count; ii++) {
        switch ((int64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
            if (value->aclfield.enable) {
                if (false == is_src_port_key_present) {
                    rules[ii].key_desc_count++;
                    rules[ii].key_desc_list_p[src_port_key_index].key_id = FLEX_ACL_KEY_SRC_PORT;
                }

                rules[ii].key_desc_list_p[src_port_key_index].key.src_port  = sx_port;
                rules[ii].key_desc_list_p[src_port_key_index].mask.src_port = true;
            } else {
                if (is_src_port_key_present) {
                    mlnx_acl_flex_rule_key_del(&rules[ii], src_port_key_index);
                }
            }
            break;

        case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
            if (value->aclfield.enable && (0 != value->aclfield.data.objlist.count)) {
                if (false == is_rx_key_present) {
                    rules[ii].key_desc_count++;
                    rules[ii].key_desc_list_p[rx_key_index].key_id = FLEX_ACL_KEY_RX_LIST;
                }

                rules[ii].key_desc_list_p[rx_key_index].key.rx_list  = sx_port_list;
                rules[ii].key_desc_list_p[rx_key_index].mask.rx_list = true;
            } else {
                if (is_rx_key_present) {
                    mlnx_acl_flex_rule_key_del(&rules[ii], rx_key_index);
                }
            }
            break;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets, rules, rule_count);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (port_list_index_to_delete != ACL_INVALID_DB_INDEX) {
        status = mlnx_acl_sx_list_delete(port_list_index_to_delete);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        acl_db_entry(acl_entry_index).rx_list_index = ACL_INVALID_DB_INDEX;
    }

    status = mlnx_acl_entry_res_ref_update(acl_entry_index, ACL_PORT_REFS_SRC, port_obj_list, new_port_count);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_list_free(rules, rule_count);
    free(offsets);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_packet_action_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
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

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_acl_rules_num);
    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_status_t                   status;
    sx_acl_region_id_t             region_id          = 0;
    uint32_t                       flex_acl_rules_num = 0;
    uint32_t                       ii, flex_action_index;
    uint32_t                       action_set_policer_id_data;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    bool                           is_action_type_present = false;
    sx_flex_acl_flex_action_type_t action_type            = 0;
    uint32_t                       acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP == (int64_t)arg) ||
           (SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
        action_type = SX_FLEX_ACL_ACTION_POLICER;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC:
        action_type = SX_FLEX_ACL_ACTION_SET_PRIO;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP:
        action_type = SX_FLEX_ACL_ACTION_SET_DSCP;
        break;

    case SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR:
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

    mlnx_acl_flex_rule_action_find(flex_acl_rule_p, action_type, &flex_action_index, &is_action_type_present);

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        switch ((int64_t)arg) {
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

        case SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR:
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
                    status = SAI_STATUS_INVALID_PARAMETER;
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

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_acl_rules_num);
    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_redirect_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg)
{
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0;
    sx_flex_acl_flex_rule_t   *rules              = NULL;
    sx_flex_acl_rule_offset_t *offsets            = NULL;
    sx_acl_pbs_id_t            sx_pbs_id;
    sx_port_log_id_t           sx_ports[MAX_PORTS]     = {0};
    acl_entry_redirect_data_t  new_entry_redirect_data = ACL_INVALID_ENTRY_REDIRECT;
    acl_entry_redirect_data_t  old_entry_redirect_data;
    acl_entry_res_refs_t       old_entry_res_refs, new_entry_res_refs;
    const sai_object_id_t     *port_obj_list = NULL;
    acl_entry_redirect_type_t  old_entry_redirect_type;
    port_pbs_index_t           port_pbs_index;
    bool                       is_action_present;
    uint32_t                   acl_table_index, acl_entry_index;
    uint32_t                   pbs_ports_number, ii, action_index;
    uint64_t                   pbs_ports_mask;

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_FLOOD == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);

    if (SAI_ACL_STAGE_EGRESS == acl_db_table(acl_table_index).stage) {
        SX_LOG_NTC("This action is not supported on STAGE_EGRESS\n");
        status = SAI_STATUS_INVALID_ATTRIBUTE_0;
        goto out;
    }

    old_entry_redirect_data = acl_db_entry(acl_entry_index).redirect_data;
    old_entry_redirect_type = old_entry_redirect_data.redirect_type;

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        if ((ACL_ENTRY_REDIRECT_TYPE_EMPTY != old_entry_redirect_type) &&
            (ACL_ENTRY_REDIRECT_TYPE_REDIRECT != old_entry_redirect_type)) {
            SX_LOG_ERR("Failed to update ACTION_REDIRECT - entry contains %s\n",
                       mlnx_acl_entry_redirect_type_to_str(old_entry_redirect_type));
            status = SAI_STATUS_INVALID_ATTRIBUTE_0;
            goto out;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
        if ((ACL_ENTRY_REDIRECT_TYPE_EMPTY != old_entry_redirect_type) &&
            (ACL_ENTRY_REDIRECT_TYPE_REDIRECT_LIST != old_entry_redirect_type)) {
            SX_LOG_ERR("Failed to update ACTION_REDIRECT_LIST - entry contains %s\n",
                       mlnx_acl_entry_redirect_type_to_str(old_entry_redirect_type));
            status = SAI_STATUS_INVALID_ATTRIBUTE_0;
            goto out;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
        if ((ACL_ENTRY_REDIRECT_TYPE_EMPTY != old_entry_redirect_type) &&
            (ACL_ENTRY_REDIRECT_TYPE_FLOOD != old_entry_redirect_type)) {
            SX_LOG_ERR("Failed to update ACTION_FLOOD - entry contains %s\n",
                       mlnx_acl_entry_redirect_type_to_str(old_entry_redirect_type));
            status = SAI_STATUS_INVALID_ATTRIBUTE_0;
            goto out;
        }
        break;

    default:
        assert(false);
        break;
    }

    status = fetch_flex_acl_rule_params_to_set(acl_table_index, acl_entry_index, &rules,
                                               &offsets, &region_id, &flex_acl_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    is_action_present = false;
    for (ii = 0; ii < rules[0].action_count; ii++) {
        if ((rules[0].action_list_p[ii].type == SX_FLEX_ACL_ACTION_PBS) ||
            (rules[0].action_list_p[ii].type == SX_FLEX_ACL_ACTION_UC_ROUTE)) {
            if (is_action_present) {
                SX_LOG_ERR("Flex action type related to SAI Redirect actions appears twice in flex rule\n");
                assert(false);
            }

            is_action_present = true;
            action_index      = ii;
            break;
        }
    }

    if (ii == rules[0].action_count) {
        action_index = ii;
    }

    old_entry_res_refs = new_entry_res_refs = acl_db_entry(acl_entry_index).res_refs;

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
        if (value->aclaction.enable) {
            status = mlnx_acl_flood_pbs_create_or_get(&sx_pbs_id);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            new_entry_redirect_data.redirect_type = ACL_ENTRY_REDIRECT_TYPE_FLOOD;
            new_entry_redirect_data.pbs_type      = ACL_ENTRY_PBS_TYPE_EMPTY;

            rules[0].action_list_p[action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            rules[0].action_list_p[action_index].fields.action_pbs.pbs_id = sx_pbs_id;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
        assert((false == is_action_present) || is_entry_redirect_pbs_type_port(old_entry_redirect_data));

        pbs_ports_number = value->aclaction.parameter.objlist.count;
        if (value->aclaction.enable) {
            if (0 == pbs_ports_number) {
                SX_LOG_ERR("Count of ports for ACTION_REDIRECT_LIST is 0\n");
                status = SAI_STATUS_INVALID_ATTR_VALUE_0;
                goto out;
            }

            for (ii = 0; ii < pbs_ports_number; ii++) {
                status = mlnx_sai_port_to_sx(value->aclaction.parameter.objlist.list[ii], &sx_ports[ii]);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }
            }

            port_obj_list = value->aclaction.parameter.objlist.list;
            status        = mlnx_acl_pbs_entry_create_or_get(sx_ports, pbs_ports_number, &sx_pbs_id, &port_pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            rules[0].action_list_p[action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            rules[0].action_list_p[action_index].fields.action_pbs.pbs_id = sx_pbs_id;

            new_entry_redirect_data.redirect_type  = ACL_ENTRY_REDIRECT_TYPE_REDIRECT_LIST;
            new_entry_redirect_data.pbs_type       = ACL_ENTRY_PBS_TYPE_PORT;
            new_entry_redirect_data.port_pbs_index = port_pbs_index;

            status = mlnx_acl_sai_port_list_to_mask(port_obj_list, pbs_ports_number, &pbs_ports_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            new_entry_res_refs.is_pbs_ports_present = true;
            new_entry_res_refs.pbs_ports_mask       = pbs_ports_mask;
        } else {
            new_entry_res_refs.is_pbs_ports_present = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
        if (value->aclaction.enable) {
            status = mlnx_sai_acl_redirect_action_create(value->aclaction.parameter.oid, &new_entry_res_refs,
                                                         &new_entry_redirect_data,
                                                         &rules[0].action_list_p[action_index]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            new_entry_redirect_data.redirect_type = ACL_ENTRY_REDIRECT_TYPE_REDIRECT;
        } else {
            new_entry_res_refs.is_lags_present      = false;
            new_entry_res_refs.is_pbs_ports_present = false;
        }
        break;

    default:
        assert(false);
    }

    for (ii = 0; ii < flex_acl_rules_num; ii++) {
        if (value->aclaction.enable) {
            rules[ii].action_list_p[action_index] = rules[0].action_list_p[action_index];
            if (false == is_action_present) {
                rules[ii].action_count++;
            }
        } else {
            if (is_action_present) {
                mlnx_acl_flex_rule_action_del(&rules[ii], action_index);
            }
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, 0, region_id, offsets,
                                            rules, flex_acl_rules_num);
    if (SX_STATUS_SUCCESS != status) {
        goto out;
    }

    acl_db_entry(acl_entry_index).redirect_data = new_entry_redirect_data;

    status = mlnx_acl_entry_redirect_pbs_delete(&old_entry_redirect_data);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    mlnx_acl_entry_res_ref_set(&old_entry_res_refs, false);
    mlnx_acl_entry_res_ref_set(&new_entry_res_refs, true);

    acl_db_entry(acl_entry_index).res_refs = new_entry_res_refs;

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    if (status != SAI_STATUS_SUCCESS) {
        mlnx_acl_entry_redirect_pbs_delete(&new_entry_redirect_data);
    }

    mlnx_acl_flex_rule_list_free(rules, flex_acl_rules_num);
    free(offsets);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mirror_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t               status;
    sx_acl_region_id_t         region_id          = 0;
    uint32_t                   flex_acl_rules_num = 0, ii;
    sai_acl_stage_t            acl_stage          = SAI_ACL_STAGE_INGRESS;
    uint32_t                   acl_table_index, acl_entry_index, flex_action_index;
    uint32_t                   session_id;
    sx_flex_acl_rule_offset_t *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t   *flex_acl_rule_p        = NULL;
    bool                       is_action_type_present = false;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_action_find(flex_acl_rule_p,
                                   SX_FLEX_ACL_ACTION_MIRROR,
                                   &flex_action_index,
                                   &is_action_type_present);

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

            status = mlnx_object_to_type(value->aclaction.parameter.objlist.list[0], SAI_OBJECT_TYPE_MIRROR_SESSION,
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

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_acl_rules_num);
    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mac_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    sai_status_t                   status;
    sx_acl_region_id_t             region_id              = 0;
    uint32_t                       flex_acl_rules_num     = 0, ii;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_flex_action_type_t action_type            = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
    bool                           is_action_type_present = false;
    uint32_t                       acl_table_index, acl_entry_index, flex_action_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_action_find(flex_acl_rule_p, action_type, &flex_action_index, &is_action_type_present);

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

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_acl_rules_num);
    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_vlan_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg)
{
    sai_status_t                   status;
    sx_acl_region_id_t             region_id              = 0;
    uint32_t                       flex_acl_rules_num     = 0, ii;
    sx_flex_acl_rule_offset_t     *offsets_list_p         = NULL;
    sx_flex_acl_flex_rule_t       *flex_acl_rule_p        = NULL;
    sx_flex_acl_flex_action_type_t action_type            = 0;
    bool                           is_action_type_present = false;
    uint32_t                       acl_table_index, acl_entry_index, flex_action_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_action_find(flex_acl_rule_p, action_type, &flex_action_index, &is_action_type_present);

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

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_acl_rules_num);
    free(offsets_list_p);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_counter_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg)
{
    sai_status_t             status;
    sx_acl_region_id_t       region_id;
    sx_acl_rule_offset_t    *offsets_list_p  = NULL;
    sx_flex_acl_flex_rule_t *flex_acl_rule_p = NULL;
    uint32_t                 flex_acl_rules_num, flex_action_index;
    uint32_t                 acl_table_index, acl_entry_index;
    uint32_t                 rule_counter;
    bool                     is_action_type_present = false;
    uint32_t                 counter_index;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
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

    mlnx_acl_flex_rule_action_find(flex_acl_rule_p, SX_FLEX_ACL_ACTION_COUNTER,
                                   &flex_action_index, &is_action_type_present);

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

    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_acl_rules_num);
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

static sai_status_t mlnx_acl_ip_ident_key_create_or_get(_Out_ sx_acl_key_t *keys)
{
    sx_status_t                          sx_status;
    sx_acl_custom_bytes_set_attributes_t sx_custom_bytes_attrs[ACL_IP_IDENT_FIELD_BYTE_COUNT];
    uint32_t                             ii, bytes_count;

    assert(NULL != keys);

    memset(sx_custom_bytes_attrs, 0, sizeof(sx_custom_bytes_attrs));

    if (0 == sai_acl_db->acl_settings_tbl->ip_ident_keys.refs) {
        for (ii = 0; ii < ACL_IP_IDENT_FIELD_BYTE_COUNT; ii++) {
            sx_custom_bytes_attrs[ii].extraction_point.extraction_group_type = SX_ACL_CUSTOM_BYTES_EXTRACTION_GROUP_L3;

            sx_custom_bytes_attrs[ii].extraction_point.params.extraction_l3_group.extraction_ipv4.extraction_point_type
                =
                    ACL_EXTRACTION_POINT_TYPE_IPV4_START_OF_HEADER;

            sx_custom_bytes_attrs[ii].extraction_point.params.extraction_l3_group.extraction_ipv4.offset =
                ACL_IP_IDENT_FIELD_START_OFFSET + ii;
        }

        bytes_count = ACL_IP_IDENT_FIELD_BYTE_COUNT;

        sx_status = sx_api_acl_custom_bytes_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_custom_bytes_attrs,
                                                sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys, &bytes_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create sx acl custom bytes set - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        if (bytes_count != ACL_IP_IDENT_FIELD_BYTE_COUNT) {
            SX_LOG_ERR("Failed to create enoght custom bytes\n");
            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    sai_acl_db->acl_settings_tbl->ip_ident_keys.refs++;

    memcpy(keys, sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys,
           sizeof(sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_ip_ident_key_ref_remove()
{
    sx_status_t                          sx_status;
    sx_acl_custom_bytes_set_attributes_t sx_custom_bytes_attrs[ACL_IP_IDENT_FIELD_BYTE_COUNT];
    uint32_t                             bytes_count;

    assert(sai_acl_db->acl_settings_tbl->ip_ident_keys.refs > 0);

    sai_acl_db->acl_settings_tbl->ip_ident_keys.refs--;

    if (0 == sai_acl_db->acl_settings_tbl->ip_ident_keys.refs) {
        memset(sx_custom_bytes_attrs, 0, sizeof(sx_custom_bytes_attrs));

        bytes_count = ACL_IP_IDENT_FIELD_BYTE_COUNT;

        sx_status = sx_api_acl_custom_bytes_set(gh_sdk, SX_ACCESS_CMD_DESTROY, sx_custom_bytes_attrs,
                                                sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys, &bytes_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to destroy sx acl custom bytes set - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_ip_ident_key_desc_create(_In_ uint16_t                   value,
                                                      _In_ uint16_t                   mask,
                                                      _Inout_ sx_flex_acl_key_desc_t *key_descs,
                                                      _Inout_ uint32_t                key_desc_count)
{
    const sx_acl_key_t *ip_ident_keys;

    assert(NULL != key_descs);

    assert(sai_acl_db->acl_settings_tbl->ip_ident_keys.refs > 0);

    ip_ident_keys = sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys;

    value = ntohs(value);
    mask  = ntohs(mask);

    key_descs[key_desc_count].key_id           = ip_ident_keys[0];
    key_descs[key_desc_count].key.custom_byte  = value & 0xFF;
    key_descs[key_desc_count].mask.custom_byte = mask & 0xFF;

    key_descs[key_desc_count + 1].key_id           = ip_ident_keys[1];
    key_descs[key_desc_count + 1].key.custom_byte  = (value >> 8) & 0xFF;
    key_descs[key_desc_count + 1].mask.custom_byte = (mask >> 8) & 0xFF;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_attr_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();

    assert((SAI_ACL_RANGE_ATTR_TYPE == (int64_t)arg) ||
           (SAI_ACL_RANGE_ATTR_LIMIT == (int64_t)arg));

    status = mlnx_acl_range_attr_get_by_oid(key->key.object_id, (uint32_t)(int64_t)arg, value);

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
                                   _In_ sai_object_id_t        switch_id,
                                   _In_ uint32_t               attr_count,
                                   _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    sx_flex_acl_flex_rule_t      flex_acl_rule;
    sx_flex_acl_flex_rule_t     *flex_acl_rule_p     = NULL;
    sx_acl_pbs_id_t              pbs_id              = 0;
    sx_port_log_id_t             port_arr[MAX_PORTS] = {0};
    sx_acl_region_id_t           region_id;
    sx_acl_rule_offset_t        *offsets_list_p = NULL;
    sx_ip_addr_t                 ipaddr_data, ipaddr_mask;
    sx_port_log_id_t             sx_port_list[MAX_PORTS] = {0};
    sx_flex_acl_key_desc_t      *sx_key_descs            = NULL;
    sai_acl_stage_t              stage;
    sai_ip_address_t             ip_address_data, ip_address_mask;
    sai_packet_action_t          packet_action_type;
    sai_object_id_t              redirect_target;
    const sai_attribute_value_t *table_id, *priority;
    const sai_attribute_value_t *in_port, *in_ports, *out_port, *out_ports, *ip_ident;
    const sai_attribute_value_t *packet_action, *action_counter;
    const sai_attribute_value_t *action_set_src_mac, *action_set_dst_mac;
    const sai_attribute_value_t *action_set_dscp;
    const sai_attribute_value_t *action_set_color, *action_set_ecn;
    const sai_attribute_value_t *action_mirror_ingress, *action_mirror_egress;
    const sai_attribute_value_t *action_dec_ttl, *action_set_user_token, *action_set_policer;
    const sai_attribute_value_t *action_set_tc, *action_redirect, *action_redirect_list;
    const sai_attribute_value_t *action_set_inner_vlan_id, *action_set_inner_vlan_pri;
    const sai_attribute_value_t *action_set_outer_vlan_id, *action_set_outer_vlan_pri;
    const sai_attribute_value_t *action_flood;
    const sai_attribute_value_t *admin_state;
    const sai_object_list_t     *out_port_obj_list = NULL;
    acl_entry_res_refs_t         entry_res_refs;
    acl_entry_redirect_data_t    entry_redirect_data = ACL_INVALID_ENTRY_REDIRECT;
    port_pbs_index_t             pbs_index           = ACL_INVALID_PORT_PBS_INDEX;
    uint32_t                     out_port_obj_count  = 0;
    uint32_t                     table_id_index, priority_index;
    uint32_t                     in_port_index, admin_state_index, in_ports_index, ip_ident_index;
    uint32_t                     out_port_index, out_ports_index;
    uint32_t                     action_set_src_mac_index, action_set_dst_mac_index;
    uint32_t                     action_set_dscp_index;
    uint32_t                     packet_action_index, action_counter_index, action_redirect_index,
                                 action_redirect_list_index;
    uint32_t action_set_policer_index, action_set_tc_index;
    uint32_t action_mirror_ingress_index, action_mirror_egress_index,
             egress_session_id, ingress_session_id;
    uint32_t action_set_color_index, action_set_ecn_index;
    uint32_t action_set_user_token_index, action_dec_ttl_index;
    uint32_t action_set_inner_vlan_id_index, action_set_inner_vlan_pri_index;
    uint32_t action_set_outer_vlan_id_index, action_set_outer_vlan_pri_index;
    uint32_t action_flood_index, port_key_index = 0;
    uint32_t in_port_data, out_port_data, action_set_policer_data;
    uint32_t acl_table_index, acl_entry_index, counter_index =
        ACL_INVALID_DB_INDEX;
    uint32_t rule_number       = 0, set_flex_rules_num = 0;
    uint32_t flex_rules_num    = 0, db_indexes_num = 0, psort_offsets_num = 0;
    uint32_t key_desc_index    = 0;    /* acl_table_size = 0; */
    uint16_t trap_id           = SX_TRAP_ID_ACL_MIN;
    uint8_t  flex_action_index = 0;
    char     list_str[MAX_LIST_VALUE_STR_LEN];
    char     key_str[MAX_KEY_STR_LEN];
    bool     is_redirect_action_present = false;
    bool     is_in_port_key_present     = false, is_out_port_key_present = false;
    uint32_t ii                         = 0;
    uint32_t table_size, created_entry_count, max_flex_keys;
    bool     is_table_dynamic_sized, is_ip_idnet_used;
    uint32_t entry_priority;
    uint32_t port_list_index  = ACL_INVALID_DB_INDEX;
    uint32_t pbs_ports_number = 0;

    SX_LOG_ENTER();

    memset(&flex_acl_rule, 0, sizeof(flex_acl_rule));
    memset(&ipaddr_data, 0, sizeof(ipaddr_data));
    memset(&ip_address_data, 0, sizeof(ip_address_data));
    memset(&ipaddr_mask, 0, sizeof(ipaddr_mask));
    memset(&ip_address_mask, 0, sizeof(ip_address_mask));
    memset(&entry_res_refs, 0, sizeof(entry_res_refs));
    memset(&sx_key_descs, 0, sizeof(sx_key_descs));

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

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);
    acl_global_lock();

    stage                  = acl_db_table(acl_table_index).stage;
    region_id              = acl_db_table(acl_table_index).region_id;
    table_size             = acl_db_table(acl_table_index).table_size;
    created_entry_count    = acl_db_table(acl_table_index).created_entry_count;
    is_table_dynamic_sized = acl_db_table(acl_table_index).is_dynamic_sized;
    is_ip_idnet_used       = acl_db_table(acl_table_index).is_ip_ident_used;


    if ((created_entry_count == table_size) &&
        (false == is_table_dynamic_sized)) {
        SX_LOG_ERR("Table is full\n");
        status = SAI_STATUS_TABLE_FULL;
        goto out;
    }

    sx_key_descs = malloc(sizeof(*sx_key_descs) * ACL_MAX_FLEX_KEY_COUNT);
    if (NULL == sx_key_descs) {
        SX_LOG_ERR(" Unable to allocate memory for sx_key_descs\n");
        status = SAI_STATUS_NO_MEMORY;
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

    status = mlnx_acl_entry_fields_to_sx(attr_list, attr_count, acl_table_index, sx_key_descs, &key_desc_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS, &in_ports, &in_ports_index)) {
        if (is_in_port_key_present) {
            SX_LOG_ERR("Both IN_PORT and IN_PORTS in one entry are not allowed\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        is_in_port_key_present = true;

        status = mlnx_acl_sx_list_set(SX_ACCESS_CMD_CREATE, &in_ports->aclfield.data.objlist, &port_list_index);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        status = mlnx_acl_sai_port_list_to_mask(in_ports->aclfield.data.objlist.list,
                                                in_ports->aclfield.data.objlist.count,
                                                &entry_res_refs.src_ports_mask);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        entry_res_refs.is_src_ports_present = true;

        sx_key_descs[key_desc_index].key_id       = FLEX_ACL_KEY_RX_LIST;
        sx_key_descs[key_desc_index].key.rx_list  = acl_db_port_list(port_list_index).sx_port_list_id;
        sx_key_descs[key_desc_index].mask.rx_list = true;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS, &out_ports, &out_ports_index)) {
        if (stage != SAI_ACL_STAGE_EGRESS) {
            SX_LOG_ERR("Port type and stage do not match\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        if (is_out_port_key_present) {
            SX_LOG_ERR("Both OUT_PORT and OUT_PORTS in one entry are not allowed\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        is_out_port_key_present = true;

        status = mlnx_acl_sai_port_list_to_mask(out_ports->aclfield.data.objlist.list,
                                                out_ports->aclfield.data.objlist.count,
                                                &entry_res_refs.dst_ports_mask);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        entry_res_refs.is_dst_ports_present = true;

        out_port_obj_list                   = &out_ports->aclfield.data.objlist;
        out_port_obj_count                  = out_port_obj_list->count;
        sx_key_descs[key_desc_index].key_id = FLEX_ACL_KEY_DST_PORT;
        port_key_index                      = key_desc_index;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT, &in_port, &in_port_index)) {
        if (is_in_port_key_present) {
            SX_LOG_ERR("Both IN_PORT and IN_PORTS in one entry are not allowed\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        is_in_port_key_present = true;

        status = mlnx_sai_port_to_sx(in_port->aclfield.data.oid, &in_port_data);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        status = mlnx_acl_sai_port_list_to_mask(&in_port->aclfield.data.oid,
                                                1,
                                                &entry_res_refs.src_ports_mask);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        entry_res_refs.is_src_ports_present = true;

        sx_key_descs[key_desc_index].key.src_port  = in_port_data;
        sx_key_descs[key_desc_index].mask.src_port = true;
        sx_key_descs[key_desc_index].key_id        = FLEX_ACL_KEY_SRC_PORT;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT, &out_port, &out_port_index)) {
        if (is_out_port_key_present) {
            SX_LOG_ERR("Both OUT_PORT and OUT_PORTS in one entry are not allowed\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        is_out_port_key_present = true;

        status = mlnx_sai_port_to_sx(out_port->aclfield.data.oid, &out_port_data);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        if (stage != SAI_ACL_STAGE_EGRESS) {
            SX_LOG_ERR("Port type and stage do not match\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        status = mlnx_acl_sai_port_list_to_mask(&out_port->aclfield.data.oid,
                                                1,
                                                &entry_res_refs.dst_ports_mask);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        entry_res_refs.is_dst_ports_present = true;

        sx_key_descs[key_desc_index].key.dst_port  = out_port_data;
        sx_key_descs[key_desc_index].mask.dst_port = true;
        sx_key_descs[key_desc_index].key_id        = FLEX_ACL_KEY_DST_PORT;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION, &ip_ident,
                            &ip_ident_index)) {
        if (false == is_ip_idnet_used) {
            SX_LOG_ERR("Table [%lx] was not created with ATTR_FIELD_IP_IDENTIFICATION\n", table_id->oid);
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + ip_ident_index;
            goto out;
        }

        status = mlnx_acl_ip_ident_key_desc_create(ip_ident->aclfield.data.u16, ip_ident->aclfield.mask.u16,
                                                   sx_key_descs, key_desc_index);
        if (SAI_ERR(status)) {
            goto out;
        }

        key_desc_index += ACL_IP_IDENT_FIELD_BYTE_COUNT;
    }

    /* ACL Field Atributes ...End */
    if (0 == key_desc_index) {
        SX_LOG_ERR(" Mandatory to Send Atleast one ACL Field during ACL Entry Create \n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    max_flex_keys = GET_NUM_OF_KEYS(acl_db_table(acl_table_index).key_type);
    if (max_flex_keys < key_desc_index) {
        SX_LOG_ERR("Too many Entry Fields for table id [%lx], max - [%d]\n", table_id->oid, max_flex_keys);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    memcpy(flex_acl_rule.key_desc_list_p, sx_key_descs, sizeof(sx_flex_acl_key_desc_t) * key_desc_index);

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT, &action_redirect,
                            &action_redirect_index)) {
        if (SAI_ACL_STAGE_EGRESS == acl_db_table(acl_table_index).stage) {
            SX_LOG_NTC("ACTION_REDIRECT is not supported on STAGE_EGRESS\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + action_redirect_index;
            goto out;
        }

        if (action_redirect->aclaction.enable == true) {
            redirect_target = action_redirect->aclaction.parameter.oid;
            if (false == mlnx_sai_acl_redirect_action_attr_check(redirect_target)) {
                status = SAI_STATUS_INVALID_ATTR_VALUE_0 + action_redirect_index;
                goto out;
            }

            status = mlnx_sai_acl_redirect_action_create(redirect_target, &entry_res_refs, &entry_redirect_data,
                                                         &flex_acl_rule.action_list_p[flex_action_index]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            is_redirect_action_present = true;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST, &action_redirect_list,
                            &action_redirect_list_index)) {
        if (SAI_ACL_STAGE_EGRESS == acl_db_table(acl_table_index).stage) {
            SX_LOG_NTC("This action is not supported on STAGE_EGRESS\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + action_redirect_list_index;
            goto out;
        }

        if (action_redirect_list->aclaction.enable == true) {
            if (is_redirect_action_present == true) {
                SX_LOG_ERR(" Redirect Action is already present as an ACL Entry Attribute \n");
                status = SAI_STATUS_INVALID_ATTR_VALUE_0 + action_redirect_list_index;
                goto out;
            }

            pbs_ports_number = action_redirect_list->aclaction.parameter.objlist.count;
            if (0 == pbs_ports_number) {
                SX_LOG_ERR("Count of ports for ACTION_REDIRECT_LIST is 0\n");
                status = SAI_STATUS_INVALID_ATTR_VALUE_0 + action_redirect_list_index;
                goto out;
            }

            for (ii = 0; ii < pbs_ports_number; ii++) {
                status = mlnx_sai_port_to_sx(action_redirect_list->aclaction.parameter.objlist.list[ii],
                                             &port_arr[ii]);
                if (SAI_STATUS_SUCCESS != status) {
                    goto out;
                }
            }

            status = mlnx_acl_pbs_entry_create_or_get(port_arr, pbs_ports_number, &pbs_id, &pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            entry_redirect_data.redirect_type  = ACL_ENTRY_REDIRECT_TYPE_REDIRECT_LIST;
            entry_redirect_data.pbs_type       = ACL_ENTRY_PBS_TYPE_PORT;
            entry_redirect_data.port_pbs_index = pbs_index;

            status = mlnx_acl_sai_port_list_to_mask(action_redirect_list->aclaction.parameter.objlist.list,
                                                    pbs_ports_number,
                                                    &entry_res_refs.pbs_ports_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            entry_res_refs.is_pbs_ports_present = true;

            is_redirect_action_present                                              = true;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_pbs.pbs_id = pbs_id;
            flex_acl_rule.action_list_p[flex_action_index].type                     = SX_FLEX_ACL_ACTION_PBS;
            flex_action_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION, &packet_action,
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
        if (SAI_ACL_STAGE_EGRESS == acl_db_table(acl_table_index).stage) {
            SX_LOG_NTC("ACTION_FLOOD is not supported on STAGE_EGRESS\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + action_flood_index;
            goto out;
        }

        if (action_flood->aclaction.enable == true) {
            if (is_redirect_action_present == true) {
                SX_LOG_ERR(" Redirect Action is already present as an ACL Entry Attribute \n");
                status = SAI_STATUS_INVALID_ATTR_VALUE_0 + action_flood_index;
                goto out;
            }

            status = mlnx_acl_flood_pbs_create_or_get(&pbs_id);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            entry_redirect_data.redirect_type = ACL_ENTRY_REDIRECT_TYPE_FLOOD;

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
                                         SAI_OBJECT_TYPE_MIRROR_SESSION,
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
                                         SAI_OBJECT_TYPE_MIRROR_SESSION,
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
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ACTION_TYPE_SET_PACKET_COLOR, &action_set_color,
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
        if (action_set_user_token->aclaction.parameter.u32 <= ACL_USER_META_RANGE_MAX) {
            if (action_set_user_token->aclaction.enable == true) {
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_user_token.user_token = \
                    (uint16_t)action_set_user_token->aclaction.parameter.u32;
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_user_token.mask =
                    ACL_USER_META_RANGE_MAX;
                flex_acl_rule.action_list_p[flex_action_index].type =
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

    rule_number = MAX(out_port_obj_count, 1);

    flex_acl_rule_p = (sx_flex_acl_flex_rule_t*)malloc(rule_number * sizeof(sx_flex_acl_flex_rule_t));
    if (flex_acl_rule_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    offsets_list_p = (sx_acl_rule_offset_t*)malloc(rule_number * sizeof(sx_acl_rule_offset_t));
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for offsets list\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (ii = 0; ii < rule_number; ii++) {
        sx_status = sx_lib_flex_acl_rule_init(acl_db_table(acl_table_index).key_type,
                                              ACL_MAX_NUM_OF_ACTIONS, &flex_acl_rule_p[ii]);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
            goto out;
        }

        flex_rules_num = ii + 1;
    }

    if (out_port_obj_count > 0) {
        for (ii = 0; ii < out_port_obj_count; ii++) {
            status = mlnx_sai_port_to_sx(out_port_obj_list->list[ii], &sx_port_list[ii]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }
    }

    mlnx_acl_fill_rule_list(flex_acl_rule, flex_acl_rule_p, rule_number,
                            sx_port_list, out_port_obj_count, port_key_index);

    for (ii = 0; ii < rule_number; ii++) {
        status = acl_db_find_entry_free_index(&acl_entry_index);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        acl_db_add_entry_to_table(acl_table_index, acl_entry_index);
        db_indexes_num = ii + 1;

        status = get_new_psort_offset(acl_table_index, acl_entry_index, entry_priority,
                                      &offsets_list_p[ii], rule_number - ii);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to get offset form pSort\n");
            goto out;
        }
        psort_offsets_num = ii + 1;

        acl_db_entry(acl_entry_index).priority      = entry_priority;
        acl_db_entry(acl_entry_index).offset        = offsets_list_p[ii];
        acl_db_entry(acl_entry_index).rule_number   = rule_number;
        acl_db_entry(acl_entry_index).counter_id    = counter_index;
        acl_db_entry(acl_entry_index).rx_list_index = port_list_index;
        acl_db_entry(acl_entry_index).redirect_data = entry_redirect_data;

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

    acl_db_entry(acl_entry_index).res_refs = entry_res_refs;
    mlnx_acl_entry_res_ref_set(&entry_res_refs, true);

    acl_entry_key_to_str(*acl_entry_id, key_str);
    SX_LOG_NTC("Created acl entry %s\n\n", key_str);

out:
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Failed to create Entry \n");

        if (db_indexes_num > 0) {
            acl_db_remove_entry_from_table(acl_table_index, acl_entry_index, db_indexes_num);
        }

        for (ii = 0; ii < psort_offsets_num; ii++) {
            release_psort_offset(acl_table_index, entry_priority, offsets_list_p[ii]);
        }

        mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_DELETE, acl_db_table(acl_table_index).key_type,
                                       region_id, offsets_list_p, NULL, set_flex_rules_num);

        mlnx_acl_entry_redirect_pbs_delete(&entry_redirect_data);

        if (ACL_INVALID_DB_INDEX != port_list_index) {
            mlnx_acl_sx_list_delete(port_list_index);
        }
    }

    acl_global_unlock();
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);
    mlnx_acl_flex_rule_list_free(flex_acl_rule_p, flex_rules_num);

    free(offsets_list_p);
    free(sx_key_descs);

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
                                   _In_ sai_object_id_t        switch_id,
                                   _In_ uint32_t               attr_count,
                                   _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    sx_acl_direction_t           sx_acl_direction;
    sai_acl_stage_t              sai_acl_stage;
    const sai_attribute_value_t *stage, *table_size, *acl_action_list, *ip_ident;
    const sai_attribute_value_t *in_port, *out_port, *in_ports, *out_ports;
    const sai_attribute_value_t *bind_point_types, *range_type;
    acl_bind_point_type_list_t   table_bind_point_types;
    sai_acl_range_type_t         range_types[SAI_ACL_RANGE_TYPE_COUNT] = {0};
    uint32_t                     range_type_count                      = 0;
    uint32_t                     range_type_index;
    uint32_t                     stage_index, table_size_index, acl_action_list_index, ip_ident_index;
    uint32_t                     in_port_index, out_port_index, in_ports_index, out_ports_index;
    uint32_t                     bind_point_types_index;
    uint32_t                     key_count      = 0, key_index = 0;
    uint32_t                     acl_table_size = 0;
    sx_acl_size_t                sx_region_size;
    sx_acl_key_type_t            key_handle;
    sx_acl_rule_offset_t         default_rule_offset;
    const sx_acl_action_type_t   action_type = SX_ACL_ACTION_TYPE_BASIC;
    const sx_acl_type_t          acl_type    = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_region_id_t           region_id;
    sx_acl_region_group_t        region_group;
    sx_acl_id_t                  acl_id;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_acl_key_t                 keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    bool                         is_dynamic_sized;
    uint32_t                     acl_table_index = 0, ii;
    bool                         key_created     = false, region_created = false;
    bool                         acl_created     = false, psort_table_created = false;
    bool                         is_range_types_unique, is_ip_ident_used = false;

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

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_ACL_STAGE, &stage, &stage_index);
    assert(SAI_STATUS_SUCCESS == status);

    if ((SAI_ACL_STAGE_INGRESS != stage->s32) &&
        (SAI_ACL_STAGE_EGRESS != stage->s32)) {
        SX_LOG_ERR("Invalid value for SAI_ACL_TABLE_ATTR_ACL_STAGE - %d\n", stage->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + stage_index;
    }

    sai_acl_stage = stage->s32;

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST,
                                 &acl_action_list, &acl_action_list_index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_acl_action_list_validate(&acl_action_list->s32list, sai_acl_stage, acl_action_list_index);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    status = mlnx_acl_table_fields_to_sx(attr_list, attr_count, keys, &key_index);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS, &in_ports, &in_ports_index)) {
        if (true == in_ports->booldata) {
            keys[key_index] = FLEX_ACL_KEY_RX_LIST;
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
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION, &ip_ident,
                            &ip_ident_index)) {
        if (true == ip_ident->booldata) {
            status = mlnx_acl_ip_ident_key_create_or_get(&keys[key_index]);
            if (SAI_ERR(status)) {
                goto out;
            }

            is_ip_ident_used = true;
            key_index       += ACL_IP_IDENT_FIELD_BYTE_COUNT;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, &range_type,
                            &range_type_index)) {
        if (0 == range_type->s32list.count) {
            SX_LOG_ERR("SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE list count is 0\n");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + range_type_index;
        }

        for (ii = 0; ii < range_type->s32list.count; ii++) {
            if ((SAI_ACL_RANGE_TYPE_INNER_VLAN == range_type->s32list.list[ii]) ||
                (SAI_ACL_RANGE_TYPE_OUTER_VLAN == range_type->s32list.list[ii])) {
                SX_LOG_ERR("Inner/Outer Vlan range is not supported\n");
                return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + range_type_index;
            }

            range_types[ii] = range_type->s32list.list[ii];
        }

        range_type_count = range_type->s32list.count;

        is_range_types_unique = mlnx_acl_range_type_list_is_unique(range_types, range_type_count);
        if (false == is_range_types_unique) {
            return SAI_STATUS_FAILURE;
        }

        keys[key_index] = FLEX_ACL_KEY_L4_PORT_RANGE;
        key_index++;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST,
                                 &bind_point_types, &bind_point_types_index);

    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_acl_bind_point_type_list_validate_and_fetch(&bind_point_types->s32list,
                                                                  bind_point_types_index,
                                                                  &table_bind_point_types);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        table_bind_point_types = default_bind_point_type_list;
    }

    assert(table_bind_point_types.count > 0);

    sx_acl_direction = mlnx_acl_sai_bind_point_type_to_sx_direction(table_bind_point_types.types[0], sai_acl_stage);

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

    /* Additional space for GOTO rule */
    sx_region_size = acl_table_size + 1;

    sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_CREATE, key_handle,
                                      action_type, sx_region_size, &region_id);
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

    status = init_psort_table(acl_table_index, is_dynamic_sized, sx_region_size);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }
    psort_table_created = true;

    status = get_new_psort_offset(acl_table_index, ACL_INVALID_DB_INDEX,
                                  ACL_DEFAULT_RULE_PRIO, &default_rule_offset, 1);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (false == acl_db_table(acl_table_index).is_lock_inited) {
        if (CL_SUCCESS != cl_plock_init_pshared(&acl_db_table(acl_table_index).lock)) {
            SX_LOG_ERR("Failed to init cl_plock for table \n");
            status = SAI_STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        acl_db_table(acl_table_index).is_lock_inited = true;
    }

    /* Update D.B */
    acl_db_table(acl_table_index).table_id               = acl_id;
    acl_db_table(acl_table_index).table_size             = acl_table_size;
    acl_db_table(acl_table_index).region_size            = sx_region_size;
    acl_db_table(acl_table_index).stage                  = sai_acl_stage;
    acl_db_table(acl_table_index).key_type               = key_handle;
    acl_db_table(acl_table_index).region_id              = region_id;
    acl_db_table(acl_table_index).is_dynamic_sized       = is_dynamic_sized;
    acl_db_table(acl_table_index).created_entry_count    = 0;
    acl_db_table(acl_table_index).created_rule_count     = 0;
    acl_db_table(acl_table_index).head_entry_index       = ACL_INVALID_DB_INDEX;
    acl_db_table(acl_table_index).range_type_count       = range_type_count;
    acl_db_table(acl_table_index).group_index            = ACL_INVALID_DB_INDEX;
    acl_db_table(acl_table_index).def_rules_offset       = default_rule_offset;
    acl_db_table(acl_table_index).def_rule_key           = keys[0];
    acl_db_table(acl_table_index).wrapping_group.created = false;
    acl_db_table(acl_table_index).bind_point_types       = table_bind_point_types;
    acl_db_table(acl_table_index).is_ip_ident_used       = is_ip_ident_used;

    if (range_type_count > 0) {
        memcpy(&acl_db_table(acl_table_index).range_types, &range_types, sizeof(range_types[0]) * range_type_count);
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, acl_table_index, NULL, acl_table_id);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    acl_table_key_to_str(*acl_table_id, key_str);
    SX_LOG_NTC("Created acl table %s\n", key_str);

out:
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

static void acl_range_key_to_str(_In_ sai_object_id_t acl_range_id, _Out_ char *key_str)
{
    uint32_t range_id;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(acl_range_id, SAI_OBJECT_TYPE_ACL_RANGE, &range_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid acl range id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL range [%u]", range_id);
    }
}

static void acl_group_key_to_str(_In_ sai_object_id_t acl_group_id, _Out_ char *key_str)
{
    uint32_t group_id;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(acl_group_id, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &group_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid acl group id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL Group [%u]", group_id);
    }
}

static void acl_group_member_key_to_str(_In_ sai_object_id_t acl_group_memeber_id, _Out_ char *key_str)
{
    uint32_t group_member_id;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(acl_group_memeber_id, SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER,
                                                  &group_member_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid acl group member id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL Group memeber [%u]", group_member_id);
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
    const sai_object_key_t key = { .key.object_id = acl_table_id };
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
    const sai_object_key_t key = { .key.object_id = acl_table_id };
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
    const sai_object_key_t key = { .key.object_id = acl_counter_id };
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
    const sai_object_key_t key = { .key.object_id = acl_counter_id };
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

    status = extract_acl_counter_index(key->key.object_id, &acl_counter_index);
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

    status = extract_acl_counter_index(key->key.object_id, &acl_counter_index);
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

    status = extract_acl_counter_index(key->key.object_id, &counter_index);
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
                                            _In_ sai_object_id_t        switch_id,
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
    const sai_object_key_t key = { .key.object_id = acl_entry_id };
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
    const sai_object_key_t key = { .key.object_id = acl_entry_id };
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
    sai_status_t               status;
    char                       key_str[MAX_KEY_STR_LEN];
    uint32_t                   acl_entry_index, acl_table_index, rule_number;
    acl_entry_redirect_data_t *entry_redirect_data;
    uint32_t                   rx_list_index;

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

    rx_list_index       = acl_db_entry(acl_entry_index).rx_list_index;
    entry_redirect_data = &acl_db_entry(acl_entry_index).redirect_data;
    rule_number         = acl_db_entry(acl_entry_index).rule_number;

    status = mlnx_delete_acl_entry_data(acl_table_index, acl_entry_index, rule_number);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    status = mlnx_acl_entry_redirect_pbs_delete(entry_redirect_data);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("failed to delete pbs entry\n");
        goto out;
    }

    memset(entry_redirect_data, 0, sizeof(*entry_redirect_data));

    if (rx_list_index != ACL_INVALID_DB_INDEX) {
        status = mlnx_acl_sx_list_delete(rx_list_index);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("failed to delete sx port list\n");
            goto out;
        }
    }

    acl_db_table(acl_table_index).created_entry_count--;

    status = acl_enqueue_table(acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    mlnx_acl_entry_res_ref_set(&acl_db_entry(acl_entry_index).res_refs, false);
    mlnx_acl_entry_res_ref_invalidate(&acl_db_entry(acl_entry_index).res_refs);

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
    const sx_acl_type_t   acl_type = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_key_type_t     key_handle;
    sai_acl_stage_t       stage;
    uint32_t              key_count = 0;
    uint32_t              table_index;
    sx_acl_key_t          keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    bool                  is_ip_idnet_used;

    SX_LOG_ENTER();

    acl_table_key_to_str(acl_table_id, key_str);
    SX_LOG_NTC("Delete ACL Table %s\n", key_str);

    status = extract_acl_table_index(acl_table_id, &table_index);
    if (SAI_ERR(status)) {
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

    if (ACL_INVALID_DB_INDEX != acl_db_table(table_index).group_index) {
        SX_LOG_ERR("Table is member of group [%d]\n", acl_db_table(table_index).group_index);
        acl_table_unlock(table_index);
        SX_LOG_EXIT();
        return SAI_STATUS_OBJECT_IN_USE;
    }

    acl_global_lock();

    region_id        = acl_db_table(table_index).region_id;
    region_size      = acl_db_table(table_index).region_size;
    sx_acl_id        = acl_db_table(table_index).table_id;
    stage            = acl_db_table(table_index).stage;
    key_handle       = acl_db_table(table_index).key_type;
    is_ip_idnet_used = acl_db_table(table_index).is_ip_ident_used;
    acl_direction    = acl_sai_stage_to_sx_dir(stage);

    /* destroy the ACL */
    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type                           = acl_type;
    region_group.regions.acl_packet_agnostic.region = region_id;

    sx_status = sx_api_acl_set(gh_sdk, SX_ACCESS_CMD_DESTROY, SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC,
                               acl_direction, &region_group, &sx_acl_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy ACL - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_DESTROY, SX_ACL_KEY_TYPE_MAC_IPV4_FULL,
                                      SX_ACL_ACTION_TYPE_BASIC, region_size, &region_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR(" Failed to delete region ACL - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sx_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, keys, &key_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR(" Failed to get flex keys - %s. \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sx_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_DELETE, keys, key_count, &key_handle);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR(" Failed to delete flex keys - %s. \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = delete_psort_table(table_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR(" Failed to delete psort table\n");
        goto out;
    }

    if (is_ip_idnet_used) {
        status = mlnx_acl_ip_ident_key_ref_remove();
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    acl_db_table(table_index).is_used = false;

out:
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
        status = SAI_STATUS_INVALID_OBJECT_ID;
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

static void mlnx_acl_flex_rule_key_del_by_key_id(_Inout_ sx_flex_acl_flex_rule_t *rule, _In_ sx_acl_key_t key_id)
{
    uint32_t key_count, key_index;

    key_count = rule->key_desc_count;

    assert(key_count > 0);

    for (key_index = 0; key_index < key_count; key_index++) {
        if (rule->key_desc_list_p[key_index].key_id == key_id) {
            break;
        }
    }

    assert(key_index < key_count);

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

static sai_status_t mlnx_acl_flex_rule_free(_In_ sx_flex_acl_flex_rule_t *rule)
{
    sx_status_t sx_status;

    sx_status = sx_lib_flex_acl_rule_deinit(rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_flex_rule_list_free(_In_ sx_flex_acl_flex_rule_t *rules, _In_ uint32_t rules_count)
{
    sx_status_t sx_status;
    uint32_t    ii;

    if (rules) {
        for (ii = 0; ii < rules_count; ii++) {
            sx_status = sx_lib_flex_acl_rule_deinit(&rules[ii]);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }
    }

    free(rules);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_flex_rule_list_init(_Inout_ sx_flex_acl_flex_rule_t **rules,
                                                 _In_ uint32_t                     rules_count,
                                                 _In_ sx_acl_key_type_t            key_type)
{
    sai_status_t             status = SAI_STATUS_SUCCESS;
    sx_status_t              sx_status;
    sx_flex_acl_flex_rule_t *flex_rules = NULL;
    uint32_t                 ii, rules_inited = 0;

    assert(rules != NULL);

    flex_rules = (sx_flex_acl_flex_rule_t*)malloc(sizeof(sx_flex_acl_flex_rule_t) * rules_count);
    if (flex_rules == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_rule\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    memset(flex_rules, 0, sizeof(sx_flex_acl_flex_rule_t) * rules_count);

    for (ii = 0; ii < rules_count; ii++) {
        sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS, &flex_rules[ii]);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
            status       = sdk_to_sai(sx_status);
            rules_inited = ii;
            goto out;
        }
    }

    *rules = flex_rules;

out:
    if (SAI_STATUS_SUCCESS != status) {
        mlnx_acl_flex_rule_list_free(flex_rules, rules_inited);
        *rules = NULL;
    }

    return status;
}

static void mlnx_acl_flex_rule_key_find(_In_ const sx_flex_acl_flex_rule_t *rule,
                                        _In_ sx_acl_key_t                   key,
                                        _Out_ uint32_t                     *key_index,
                                        _Out_ bool                         *is_key_present)
{
    uint32_t index;

    assert((rule != NULL) && (key_index != NULL) && (is_key_present != NULL));

    *is_key_present = false;
    for (index = 0; index < rule->key_desc_count; index++) {
        if (key == rule->key_desc_list_p[index].key_id) {
            *is_key_present = true;
            break;
        }
    }

    *key_index = index;
}

static void mlnx_acl_flex_rule_action_find(_In_ const sx_flex_acl_flex_rule_t *rule,
                                           _In_ sx_flex_acl_flex_action_type_t action_type,
                                           _Out_ uint32_t                     *action_index,
                                           _Out_ bool                         *is_action_present)
{
    uint32_t index;

    assert((rule != NULL) && (action_index != NULL) && (is_action_present != NULL));

    *is_action_present = false;
    for (index = 0; index < rule->action_count; index++) {
        if (action_type == rule->action_list_p[index].type) {
            *is_action_present = true;
            break;
        }
    }

    *action_index = index;
}

static sai_status_t mlnx_acl_flex_rules_set_helper(_In_ sx_access_cmd_t                cmd,
                                                   _In_ const sx_acl_key_type_t        key_type,
                                                   _In_ const sx_acl_region_id_t       region_id,
                                                   _In_ sx_acl_rule_offset_t          *offsets_list_p,
                                                   _In_ const sx_flex_acl_flex_rule_t *rules_list_p,
                                                   _In_ uint32_t                       rules_count)
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
    mlnx_acl_flex_rule_list_free(delete_rules_list_p, rules_count);
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

    acl_db_table(table_index).region_size = new_size;

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
    psort_init_param.min_priority   = ACL_PSORT_TABLE_MIN_PRIO;
    psort_init_param.max_priority   = ACL_PSORT_TABLE_MAX_PRIO;
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

    assert(acl_table_index_check_range(table_id));

    if (ACL_INVALID_DB_INDEX != entry_id) {
        assert(acl_entry_index_check_range(entry_id));

        if (acl_db_table(table_id).created_rule_count + requested_num > acl_db_table(table_id).region_size) {
            if (SAI_STATUS_SUCCESS != acl_table_size_increase(table_id, requested_num)) {
                SX_LOG_ERR("Failed to increase a size of psort table\n");
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        }
    }

    psort_handle         = acl_db_table(table_id).psort_handle;
    psort_entry.key      = entry_id;
    psort_entry.priority = priority;

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

    if (acl_db_table(acl_table_index).region_size <= new_offset) {
        SX_LOG_ERR("New offset from pSort is bigger then sx_region size\n");
        sx_status = SX_STATUS_ERROR;
        goto out;
    }

    /* default rule's entry_index is ACL_INVALID_DB_INDEX */
    if (ACL_INVALID_DB_INDEX == acl_entry_index) {
        if (acl_db_table(acl_table_index).def_rules_offset != old_offset) {
            SX_LOG_ERR("Default rule offset in SAI DB (%d) is not equal to pSort DB (%d)\n",
                       acl_db_table(acl_table_index).def_rules_offset, old_offset);
            sx_status = SX_STATUS_ERROR;
            goto out;
        }

        acl_db_table(acl_table_index).def_rules_offset = new_offset;
    } else {
        if (acl_db_entry(acl_entry_index).offset != old_offset) {
            SX_LOG_ERR("ACL DB Rule offset is not equal to pSort offset\n");
            sx_status = SX_STATUS_ERROR;
            goto out;
        }

        acl_db_entry(acl_entry_index).offset = new_offset;
    }

    sx_status = sx_api_acl_rule_block_move_set(*sdk_api_handle, region_id, old_offset, 1, new_offset);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to move rule block\n");
        goto out;
    }

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

static sai_status_t mlnx_sx_port_to_index(_In_ sx_port_log_id_t sx_port_id, _Out_ uint32_t *port_index)
{
    sai_status_t        status = SAI_STATUS_FAILURE;
    mlnx_port_config_t *port;
    uint32_t            ii;

    SX_LOG_ENTER();

    assert(port_index != NULL);

    mlnx_port_phy_foreach(port, ii) {
        if (port->logical == sx_port_id) {
            *port_index = ii;
            status      = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

    SX_LOG_ERR("Couldn't find SX port id [%x] in SAI port DB\n", sx_port_id);

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_sx_lag_to_index(_In_ sx_port_log_id_t sx_lag_id, _Out_ uint32_t        *lag_index)
{
    sai_status_t        status = SAI_STATUS_FAILURE;
    mlnx_port_config_t *lag;
    uint32_t            ii;

    SX_LOG_ENTER();

    assert(lag_index != NULL);

    mlnx_lag_foreach(lag, ii) {
        if (lag->logical == sx_lag_id) {
            *lag_index = ii - MAX_PORTS;
            status     = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

    SX_LOG_ERR("Couldn't find SX LAG id [%x] in SAI port DB\n", sx_lag_id);

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_sai_port_to_index(_In_ sai_object_id_t sai_port_id, _Out_ uint32_t       *port_index)
{
    sai_status_t        status = SAI_STATUS_FAILURE;
    mlnx_port_config_t *port;
    uint32_t            ii;

    SX_LOG_ENTER();

    assert(port_index != NULL);

    mlnx_port_phy_foreach(port, ii) {
        if (port->saiport == sai_port_id) {
            *port_index = ii;
            status      = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

    SX_LOG_ERR("Couldn't find SAI port id [%lx] in SAI port DB\n", sai_port_id);

out:
    SX_LOG_EXIT();
    return status;
}


static void mlnx_acl_entry_res_ref_invalidate(_In_ acl_entry_res_refs_t *entry_stats)
{
    memset(entry_stats, 0, sizeof(*entry_stats));
}

static sai_status_t mlnx_acl_entry_res_ref_update(_In_ uint32_t               entry_index,
                                                  _In_ acl_port_stat_type_t   stat_type,
                                                  _In_ const sai_object_id_t *port_list,
                                                  _In_ uint32_t               port_count)
{
    sai_status_t         status;
    uint64_t             port_mask;
    bool                 is_ports_present;
    acl_entry_res_refs_t new_entry_res_refs, old_entry_res_refs;

    assert(stat_type <= ACL_PORT_REFS_MAX);

    new_entry_res_refs = old_entry_res_refs = acl_db_entry(entry_index).res_refs;

    port_mask        = 0;
    is_ports_present = false;
    if (port_list) {
        status = mlnx_acl_sai_port_list_to_mask(port_list, port_count, &port_mask);
        if (SAI_STATUS_SUCCESS != status) {
            return status;
        }

        is_ports_present = true;
    }

    switch (stat_type) {
    case ACL_PORT_REFS_SRC:
        new_entry_res_refs.is_src_ports_present = is_ports_present;
        new_entry_res_refs.src_ports_mask       = port_mask;
        break;

    case ACL_PORT_REFS_DST:
        new_entry_res_refs.is_dst_ports_present = is_ports_present;
        new_entry_res_refs.dst_ports_mask       = port_mask;
        break;

    case ACL_PORT_REFS_PBS:
        new_entry_res_refs.is_pbs_ports_present = is_ports_present;
        new_entry_res_refs.pbs_ports_mask       = port_mask;
        break;

    default:
        assert(false);
        break;
    }

    mlnx_acl_entry_res_ref_set(&old_entry_res_refs, false);
    mlnx_acl_entry_res_ref_set(&new_entry_res_refs, true);

    acl_db_entry(entry_index).res_refs = new_entry_res_refs;

    return SAI_STATUS_SUCCESS;
}

static void mlnx_acl_entry_res_ref_set(_In_ const acl_entry_res_refs_t *entry_stats, _In_ bool add_reference)
{
    assert(entry_stats != NULL);

    if (entry_stats->is_dst_ports_present) {
        mlnx_acl_port_list_ref_update(entry_stats->dst_ports_mask, add_reference);
    }

    if (entry_stats->is_src_ports_present) {
        mlnx_acl_port_list_ref_update(entry_stats->src_ports_mask, add_reference);
    }

    if (entry_stats->is_pbs_ports_present) {
        mlnx_acl_port_list_ref_update(entry_stats->pbs_ports_mask, add_reference);
    }

    if (entry_stats->is_lags_present) {
        mlnx_acl_res_ref_update(entry_stats->lag_index, true, add_reference);
    }
}

static void mlnx_acl_port_list_ref_update(_In_ uint64_t ports_mask, _In_ bool add_reference)
{
    uint32_t port_index = 0;

    while (ports_mask) {
        if (ports_mask & 1) {
            mlnx_acl_res_ref_update(port_index, false, add_reference);
        }

        port_index++;
        ports_mask >>= 1;
    }
}

static void mlnx_acl_res_ref_update(_In_ uint32_t res_index, _In_ bool is_lag, _In_ bool add_reference)
{
    assert(res_index < MAX_PORTS);

    if (add_reference) {
        if (is_lag) {
            sai_acl_db->acl_settings_tbl->lags_used[res_index].ref_counter++;
        } else {
            sai_acl_db->acl_settings_tbl->ports_used[res_index].ref_counter++;
        }
    } else {
        if (is_lag) {
            assert(sai_acl_db->acl_settings_tbl->lags_used[res_index].ref_counter > 0);
            sai_acl_db->acl_settings_tbl->lags_used[res_index].ref_counter--;
        } else {
            assert(sai_acl_db->acl_settings_tbl->ports_used[res_index].ref_counter > 0);
            sai_acl_db->acl_settings_tbl->ports_used[res_index].ref_counter--;
        }
    }
}

bool mlnx_acl_is_port_lag_used(_In_ const mlnx_port_config_t *config)
{
    uint32_t index;

    if (mlnx_port_is_lag(config)) {
        assert(SAI_STATUS_SUCCESS == mlnx_sx_lag_to_index(config->logical, &index));

        return (sai_acl_db->acl_settings_tbl->lags_used[index].ref_counter > 0);
    } else { /* port */
        assert(SAI_STATUS_SUCCESS == mlnx_sx_port_to_index(config->logical, &index));

        return (sai_acl_db->acl_settings_tbl->ports_used[index].ref_counter > 0);
    }
}

static sai_status_t mlnx_acl_sai_port_list_to_mask(_In_ const sai_object_id_t *sai_ports,
                                                   _In_ uint32_t               sai_port_count,
                                                   _In_ uint64_t              *port_mask)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint64_t     mask;
    uint32_t     port_index, ii;

    assert((sai_ports != NULL) && (port_mask != NULL));

    mask = 0;
    for (ii = 0; ii < sai_port_count; ii++) {
        status = mlnx_sai_port_to_index(sai_ports[ii], &port_index);
        if (SAI_STATUS_SUCCESS != status) {
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        mask |= UINT64_C(1) << port_index;
    }

    *port_mask = mask;

out:
    return status;
}

static sai_status_t mlnx_acl_sx_port_list_to_mask(_In_ const sx_port_id_t *ports,
                                                  _In_ uint32_t            port_number,
                                                  _Inout_ uint64_t        *port_mask)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint64_t     mask;
    uint32_t     port_index;
    uint32_t     ii;

    SX_LOG_ENTER();

    assert(ports != NULL && port_mask != NULL);

    mask = 0;
    for (ii = 0; ii < port_number; ii++) {
        status = mlnx_sx_port_to_index(ports[ii], &port_index);
        if (SAI_STATUS_SUCCESS != status) {
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        mask |= UINT64_C(1) << port_index;
    }

    *port_mask = mask;
out:
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_acl_port_lag_event_handle(_In_ const mlnx_port_config_t *port, _In_ acl_event_type_t event)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_status_t        sx_status;
    sx_access_cmd_t    sx_port_cmd;
    sx_port_log_id_t   sx_port_id;
    sx_acl_pbs_entry_t sx_pbs_entry;
    sx_acl_pbs_id_t    sx_pbs_id;
    sx_swid_t          sx_swid_id = DEFAULT_ETH_SWID;
    bool               clean_bind_point;

    assert(port != NULL);

    sx_port_id = port->logical;

    switch (event) {
    case ACL_EVENT_TYPE_PORT_LAG_ADD:
    case ACL_EVENT_TYPE_LAG_MEMBER_DEL:
        sx_port_cmd      = SX_ACCESS_CMD_ADD_PORTS;
        clean_bind_point = false;
        break;

    case ACL_EVENT_TYPE_PORT_LAG_DEL:
    case ACL_EVENT_TYPE_LAG_MEMBER_ADD:
        sx_port_cmd      = SX_ACCESS_CMD_DELETE_PORTS;
        clean_bind_point = true;
        break;

    default:
        SX_LOG_ERR("ACL event [%d] is not supported\n", event);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    if (false == sai_acl_db->acl_settings_tbl->initialized) {
        status = SAI_STATUS_SUCCESS;
        goto out;
    }

    if (0 != acl_flood_pbs.ref_counter) {
        memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));
        sx_pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
        sx_pbs_entry.port_num   = 1;
        sx_pbs_entry.log_ports  = &sx_port_id;

        sx_pbs_id = acl_flood_pbs.pbs_id;

        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, sx_port_cmd, sx_swid_id, &sx_pbs_entry, &sx_pbs_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to update ACL Flood PBS Entry %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (false == mlnx_port_is_lag(port)) {
        status = mlnx_acl_sx_port_lists_update(sx_port_cmd, sx_port_id);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }
    }

    if (clean_bind_point) {
        /* clear the binding on both stages */
        status = mlnx_acl_port_lag_bind_point_clear(port, SAI_ACL_STAGE_INGRESS);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_acl_port_lag_bind_point_clear(port, SAI_ACL_STAGE_EGRESS);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        status = mlnx_acl_port_bind_refresh(port);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    return status;
}

static sai_status_t mlnx_acl_pbs_get_simple_map_index(_In_ const sx_port_id_t  *ports,
                                                      _In_ uint32_t             ports_number,
                                                      _Inout_ port_pbs_index_t *pbs_index)
{
    uint32_t         port_index;
    port_pbs_index_t pbs_map_index;

    assert(ports != NULL && pbs_index != NULL);

    if (SAI_STATUS_SUCCESS != mlnx_sx_port_to_index(ports[0], &port_index)) {
        return SAI_STATUS_FAILURE;
    }

    pbs_map_index.is_simple = true;
    pbs_map_index.index     = port_index;

    *pbs_index = pbs_map_index;

    return SAI_STATUS_FAILURE;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_acl_pbs_get_map_index_and_key(_In_ const sx_port_id_t *ports,
                                                       _In_ uint32_t            ports_number,
                                                       _Out_ port_pbs_index_t  *pbs_index,
                                                       _Out_ acl_pbs_map_key_t *pbs_key)
{
    sai_status_t      status        = SAI_STATUS_SUCCESS;
    port_pbs_index_t  pbs_map_index = ACL_INVALID_PORT_PBS_INDEX, free_pbs_map_index = ACL_INVALID_PORT_PBS_INDEX;
    acl_pbs_map_key_t pbs_map_key   = ACL_PBS_MAP_EMPTY_KEY;
    uint32_t          ii;

    assert(ports != NULL && pbs_index != NULL && pbs_key != NULL);

    status = mlnx_acl_sx_port_list_to_mask(ports, ports_number, &pbs_map_key);
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

static sai_status_t mlnx_acl_pbs_entry_create_or_get(_In_ sx_port_id_t        *ports,
                                                     _In_ uint32_t             ports_number,
                                                     _Inout_ sx_acl_pbs_id_t  *pbs_id,
                                                     _Inout_ port_pbs_index_t *pbs_index)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_status_t        sx_status;
    sx_acl_pbs_entry_t sx_pbs_entry;
    sx_acl_pbs_id_t    sx_pbs_id;
    sx_swid_t          swid_id       = DEFAULT_ETH_SWID;
    port_pbs_index_t   pbs_map_index = ACL_INVALID_PORT_PBS_INDEX;
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

static sai_status_t mlnx_acl_lag_pbs_create_or_get(_In_ sx_port_log_id_t  sx_lag_id,
                                                   _Out_ sx_acl_pbs_id_t *sx_pbs_id,
                                                   _Out_ lag_pbs_index_t *lag_pbs_index)
{
    sai_status_t       status;
    sx_status_t        sx_status;
    sx_acl_pbs_entry_t sx_pbs_entry;
    uint32_t           lag_index;
    sx_swid_t          swid_id = DEFAULT_ETH_SWID;

    assert((sx_pbs_id != NULL) && (lag_pbs_index != NULL));

    status = mlnx_sx_lag_to_index(sx_lag_id, &lag_index);
    if (SAI_ERR(status)) {
        return status;
    }

    if (acl_db_lag_pbs(lag_index).ref_counter > 0) {
        *sx_pbs_id = acl_db_lag_pbs(lag_index).pbs_id;
        acl_db_lag_pbs(lag_index).ref_counter++;
    } else {
        memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));
        sx_pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_UNICAST;
        sx_pbs_entry.port_num   = 1;
        sx_pbs_entry.log_ports  = &sx_lag_id;

        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_ADD, swid_id,
                                                          &sx_pbs_entry, sx_pbs_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to create LAG PBS %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        acl_db_lag_pbs(lag_index).pbs_id      = *sx_pbs_id;
        acl_db_lag_pbs(lag_index).ref_counter = 1;
    }

    *lag_pbs_index = lag_index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_flood_pbs_create_or_get(_Out_ sx_acl_pbs_id_t *sx_pbs_id)
{
    mlnx_port_config_t *port_config;
    sx_status_t         sx_status;
    sx_port_log_id_t    sx_port_ids[MAX_PORTS] = {0};
    sx_acl_pbs_entry_t  sx_pbs_entry;
    sx_swid_t           swid_id = DEFAULT_ETH_SWID;
    uint32_t            port_count, ii;

    assert(sx_pbs_id != NULL);

    if (acl_flood_pbs.ref_counter > 0) {
        *sx_pbs_id = acl_flood_pbs.pbs_id;
        acl_flood_pbs.ref_counter++;
    } else {
        port_count = 0;
        mlnx_port_phy_foreach(port_config, ii) {
            if (false == mlnx_port_is_lag_member(port_config)) {
                sx_port_ids[port_count++] = port_config->logical;
            }
        }

        mlnx_lag_foreach(port_config, ii) {
            sx_port_ids[port_count++] = port_config->logical;
        }

        assert(port_count <= MAX_PORTS);

        memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));
        sx_pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
        sx_pbs_entry.port_num   = port_count;
        sx_pbs_entry.log_ports  = sx_port_ids;

        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_ADD, swid_id,
                                                          &sx_pbs_entry, sx_pbs_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to create Flood PBS %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        acl_flood_pbs.pbs_id      = *sx_pbs_id;
        acl_flood_pbs.ref_counter = 1;
    }

    return SAI_STATUS_SUCCESS;
}

/*
 *   Routine Description:
 *       Delete all entry data related to ACTION_REDIRECT.
 *       If redirect_data.redirect_type is EMPTY does nothing (entry doesn't contain ACTION_REDIRECT)
 *       If redirect_data.pbs_type is EMPTY does nothing (The destination of ACTION_REDIRECT is NEXT_HOP/NEXT_HOP_GROUP)
 *
 *      Arguments:
 *          redirect_data - represents data related to ACTION_REDIRECT for some specific entry
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */
static sai_status_t mlnx_acl_entry_redirect_pbs_delete(_In_ const acl_entry_redirect_data_t *redirect_data)
{
    sx_status_t      sx_status;
    sai_status_t     status = SAI_STATUS_SUCCESS;
    sx_swid_t        swid   = DEFAULT_ETH_SWID;
    port_pbs_index_t port_pbs_index;
    lag_pbs_index_t  lag_pbs_index;
    sx_acl_pbs_id_t  sx_pbs_id;
    uint32_t        *ref_counter;

    SX_LOG_ENTER();

    if (ACL_ENTRY_REDIRECT_TYPE_EMPTY == redirect_data->redirect_type) {
        status = SAI_STATUS_SUCCESS;
        goto out;
    }

    if (ACL_ENTRY_REDIRECT_TYPE_FLOOD == redirect_data->redirect_type) {
        sx_pbs_id   = acl_flood_pbs.pbs_id;
        ref_counter = &acl_flood_pbs.ref_counter;
    } else {
        switch (redirect_data->pbs_type) {
        case ACL_ENTRY_PBS_TYPE_LAG:
            lag_pbs_index = redirect_data->lag_pbs_index;
            sx_pbs_id     = acl_db_lag_pbs(lag_pbs_index).pbs_id;
            ref_counter   = &acl_db_lag_pbs(lag_pbs_index).ref_counter;
            break;

        case ACL_ENTRY_PBS_TYPE_PORT:
            port_pbs_index = redirect_data->port_pbs_index;
            sx_pbs_id      = acl_db_pbs(port_pbs_index).pbs_id;
            ref_counter    = &acl_db_pbs_ptr(port_pbs_index)->ref_counter;
            break;

        default:
            status = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

    if (1 == *ref_counter) {
        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_DELETE, swid, NULL, &sx_pbs_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to delete PBS Entry  %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    (*ref_counter)--;

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_pbs_map_get_ports(_In_ port_pbs_index_t pbs_index,
                                               _Inout_ sx_port_id_t *ports,
                                               _Inout_ uint32_t     *port_number)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    acl_pbs_map_key_t key;
    sx_port_id_t     *pbs_ports = NULL;
    uint32_t          pbs_port_number, port_index, ii;

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
            for (ii = port_index = 0; ii < MAX_PORTS; ii++) {
                if (g_sai_db_ptr->ports_db[ii].is_present) {
                    pbs_ports[port_index++] = (sx_port_log_id_t)g_sai_db_ptr->ports_db[ii].logical;
                }
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

static sai_status_t mlnx_acl_range_attr_get_by_oid(_In_ sai_object_id_t           acl_range_oid,
                                                   _In_ sai_attr_id_t             attr_id,
                                                   _Inout_ sai_attribute_value_t *value)
{
    sai_status_t              status;
    sx_status_t               sx_status;
    sx_acl_port_range_id_t    sx_port_range_id;
    sx_acl_port_range_entry_t sx_port_range_entry;
    uint32_t                  object_range_id;

    SX_LOG_ENTER();

    assert((SAI_ACL_RANGE_ATTR_TYPE == attr_id) ||
           (SAI_ACL_RANGE_ATTR_LIMIT == attr_id));

    status = mlnx_object_to_type(acl_range_oid, SAI_OBJECT_TYPE_ACL_RANGE, &object_range_id, NULL);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    sx_port_range_id = object_range_id;

    sx_status = sx_api_acl_l4_port_range_get(gh_sdk, sx_port_range_id, &sx_port_range_entry);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get range attributes - %s", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    switch (attr_id) {
    case SAI_ACL_RANGE_ATTR_TYPE:
        if (sx_port_range_entry.port_range_ip_length) {
            value->s32 = SAI_ACL_RANGE_TYPE_PACKET_LENGTH;
            break;
        }

        switch (sx_port_range_entry.port_range_direction) {
        case SX_ACL_PORT_DIRECTION_SOURCE:
            value->s32 = SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE;
            break;

        case SX_ACL_PORT_DIRECTION_DESTINATION:
            value->s32 = SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE;
            break;

        default:
            SX_LOG_ERR("Got invalid range direction from SDK - %d\n", sx_port_range_entry.port_range_direction);
            status = SAI_STATUS_FAILURE;
        }
        break;

    case SAI_ACL_RANGE_ATTR_LIMIT:
        value->u32range.min = sx_port_range_entry.port_range_min;
        value->u32range.max = sx_port_range_entry.port_range_max;
        break;

    default:
        SX_LOG_ERR(" Invalid attribute to get - %d\n", attr_id);
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

/**
 * Routine Description:
 *   @brief Fills flex rule list with port keys.
 *
 * Arguments:
 *    @param[in] src_rule - flex rule to copy into dst_rules
 *    @param[inout] dst_rules - array of flex rules to fill
 *    @param[in] ports - array of ports
 *    @param[in] port_count - port array size
 *    @param[in] port_key_index - index of port key in flex rule
 *
 * Return Values:
 *    @return  void
 */
static void mlnx_acl_fill_rule_list(_In_ sx_flex_acl_flex_rule_t     src_rule,
                                    _Inout_ sx_flex_acl_flex_rule_t *dst_rules,
                                    _In_ uint32_t                    dst_rules_count,
                                    _In_ const sx_port_log_id_t     *ports,
                                    _In_ uint32_t                    port_count,
                                    _In_ uint32_t                    port_key_index)
{
    uint32_t port_index, ii;

    SX_LOG_ENTER();

    assert((ports != NULL) || (0 == port_count));

    port_index = 0;
    for (ii = 0; ii < dst_rules_count; ii++) {
        mlnx_acl_flex_rule_copy(&dst_rules[ii], &src_rule);

        if (port_count > 0) {
            dst_rules[ii].key_desc_list_p[port_key_index].key.dst_port  = ports[port_index];
            dst_rules[ii].key_desc_list_p[port_key_index].mask.dst_port = true;
            port_index++;
        }
    }

    SX_LOG_EXIT();
}

/**
 *   Routine Description:
 *     @brief Sets rules into HW and updates SAI DB (removes unneeded or creates new records)
 *
 *  Arguments:
 *  @param[in] entry_index - entry index in SAI DB
 *  @param[in] table_index - table index in SAI DB
 *  @param[in] rules - array of rules
 *  @param[in] rules_count - rules array size
 *
 *  Return Values:
 *    @return  SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */
static sai_status_t mlnx_acl_entry_modify_rules(_In_ uint32_t                       entry_index,
                                                _In_ uint32_t                       table_index,
                                                _In_ const sx_flex_acl_flex_rule_t *rules,
                                                _In_ uint32_t                       rules_count)
{
    sai_status_t               status = SAI_STATUS_SUCCESS;
    sx_acl_region_id_t         region_id;
    sx_acl_key_type_t          key_type;
    sx_flex_acl_rule_offset_t *offsets_list_p;
    uint32_t                   entry_priority, old_entry_rule_num, new_entry_rule_num, new_entry_index,
                               delete_entry_index;
    uint32_t flex_rules_num, update_rules_num;
    uint32_t processed_entry_count, last_processed_entry_index;
    uint32_t create_entries_num, created_entries_num;

    assert(acl_entry_index_check_range(entry_index) && acl_table_index_check_range(table_index));

    region_id          = acl_db_table(table_index).region_id;
    key_type           = acl_db_table(table_index).key_type;
    entry_priority     = acl_db_entry(entry_index).priority;
    old_entry_rule_num = acl_db_entry(entry_index).rule_number;
    new_entry_rule_num = rules_count;
    flex_rules_num     = MAX(new_entry_rule_num, old_entry_rule_num);

    last_processed_entry_index = entry_index;

    offsets_list_p = (sx_flex_acl_rule_offset_t*)malloc(flex_rules_num * sizeof(sx_flex_acl_rule_offset_t));
    if (offsets_list_p == NULL) {
        SX_LOG_ERR("ERROR: unable to allocate memory for offsets list\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    processed_entry_count = 0;
    update_rules_num      = MIN(new_entry_rule_num, old_entry_rule_num);

    while (processed_entry_count < update_rules_num) {
        offsets_list_p[processed_entry_count] = acl_db_entry(last_processed_entry_index).offset;
        processed_entry_count++;

        if (processed_entry_count != update_rules_num) {
            last_processed_entry_index = acl_db_entry(last_processed_entry_index).next;
        }
    }

    status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, key_type, region_id,
                                            offsets_list_p, rules, update_rules_num);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    if (update_rules_num < new_entry_rule_num) {
        assert(update_rules_num == old_entry_rule_num);
        create_entries_num = new_entry_rule_num - old_entry_rule_num;
        status             = acl_db_insert_entries(table_index, last_processed_entry_index, create_entries_num);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        new_entry_index     = acl_db_entry(last_processed_entry_index).next;
        created_entries_num = 0;
        while (created_entries_num < create_entries_num) {
            status = get_new_psort_offset(table_index, new_entry_index, entry_priority,
                                          &offsets_list_p[processed_entry_count],
                                          create_entries_num - created_entries_num);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            acl_db_entry(new_entry_index).offset   = offsets_list_p[processed_entry_count];
            acl_db_entry(new_entry_index).priority = entry_priority;

            status = mlnx_acl_flex_rules_set_helper(SX_ACCESS_CMD_SET, key_type, region_id,
                                                    &offsets_list_p[processed_entry_count],
                                                    &rules[processed_entry_count], 1);
            if (SX_STATUS_SUCCESS != status) {
                goto out;
            }

            new_entry_index = acl_db_entry(new_entry_index).next;

            created_entries_num++;
            processed_entry_count++;
        }
    } else if (update_rules_num < old_entry_rule_num) {
        assert(update_rules_num == new_entry_rule_num);

        /* delete starting from next entry */
        delete_entry_index = acl_db_entry(last_processed_entry_index).next;

        status = mlnx_delete_acl_entry_data(table_index, delete_entry_index, old_entry_rule_num - new_entry_rule_num);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }
    }

    acl_db_entry(entry_index).rule_number = new_entry_rule_num;

out:
    free(offsets_list_p);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_sx_list_set(_In_ sx_access_cmd_t          cmd,
                                         _In_ const sai_object_list_t *ports,
                                         _Inout_ uint32_t             *port_list_index)
{
    sai_status_t             status = SAI_STATUS_SUCCESS;
    sx_status_t              sx_status;
    sx_acl_port_list_id_t   *sx_port_list_id;
    sx_acl_port_list_entry_t sx_list_entry[MAX_PORTS];
    sx_port_log_id_t         sx_ports[MAX_PORTS];
    mlnx_port_config_t      *port_config;
    uint32_t                 ii, jj, entries_count;
    uint64_t                 port_mask;
    bool                     is_port_present, is_port_list_index_created = false;

    assert((cmd == SX_ACCESS_CMD_CREATE) || (cmd == SX_ACCESS_CMD_SET));
    assert(port_list_index != NULL);

    memset(sx_list_entry, 0, sizeof(sx_list_entry));
    memset(sx_ports, 0, sizeof(sx_ports));

    if (ports->count > MAX_PORTS) {
        SX_LOG_ERR("Too many ports (%d) for IN_PORTS attribute, max - %d\n", ports->count, MAX_PORTS);
        return SAI_STATUS_FAILURE;
    }

    if (SX_ACCESS_CMD_CREATE == cmd) {
        status = acl_db_find_port_list_free_index(port_list_index);
        if (SAI_STATUS_SUCCESS != status) {
            return SAI_STATUS_FAILURE;
        }

        is_port_list_index_created = true;
    }

    assert(acl_db_port_list(*port_list_index).is_used);

    entries_count = 0;
    port_mask     = 0;
    mlnx_port_phy_foreach(port_config, ii) {
        is_port_present = false;
        for (jj = 0; jj < ports->count; jj++) {
            if (port_config->saiport == ports->list[jj]) {
                is_port_present = true;
                break;
            }
        }

        if (false == is_port_present) {
            port_mask                              |= UINT64_C(1) << ii;
            sx_ports[entries_count]                 = port_config->logical;
            sx_list_entry[entries_count].log_port   = port_config->logical;
            sx_list_entry[entries_count].port_match = SX_ACL_PORT_LIST_MATCH_NEGATIVE;
            entries_count++;
        }
    }

    sx_port_list_id = &acl_db_port_list(*port_list_index).sx_port_list_id;

    sx_status = sx_api_acl_port_list_set(gh_sdk, cmd, sx_list_entry, entries_count, sx_port_list_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to %s sx port list %s.\n", (SX_ACCESS_CMD_CREATE == cmd) ? "create" : "set",
                   SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    acl_db_port_list(*port_list_index).port_mask = port_mask;

out:
    if ((SAI_STATUS_SUCCESS != status) && (is_port_list_index_created)) {
        acl_db_port_list(*port_list_index).is_used = false;
        sai_acl_db->acl_settings_tbl->port_lists_count--;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_list_delete(_In_ uint32_t port_list_index)
{
    sx_status_t            sx_status;
    sx_acl_port_list_id_t *sx_port_list_id;

    assert(port_list_index != ACL_INVALID_DB_INDEX);
    assert(acl_db_port_list(port_list_index).is_used);

    sx_port_list_id = &acl_db_port_list(port_list_index).sx_port_list_id;

    sx_status = sx_api_acl_port_list_set(gh_sdk, SX_ACCESS_CMD_DESTROY, NULL, 0, sx_port_list_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to delete sx port list %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl_db_port_list(port_list_index).is_used = false;
    sai_acl_db->acl_settings_tbl->port_lists_count--;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_fetch_sx_port_list(_In_ uint32_t           port_list_index,
                                                _Out_ sx_port_log_id_t *ports,
                                                _Out_ uint32_t         *port_count)
{
    sx_status_t              sx_status;
    mlnx_port_config_t      *port;
    sx_acl_port_list_id_t    sx_port_list_id;
    sx_acl_port_list_entry_t sx_list_entry[MAX_PORTS];
    uint32_t                 sx_port_count, ii, jj, target_port_count;
    bool                     is_port_present;

    assert((ports != NULL) && (port_count != NULL));
    assert((port_list_index != ACL_INVALID_DB_INDEX) && (port_list_index < ACL_MAX_PORT_LISTS_COUNT));
    assert(acl_db_port_list(port_list_index).is_used);

    sx_port_list_id = acl_db_port_list(port_list_index).sx_port_list_id;

    sx_port_count = MAX_PORTS;
    sx_status     = sx_api_acl_port_list_get(gh_sdk, sx_port_list_id, sx_list_entry, &sx_port_count);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get sx port list %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    target_port_count = 0;
    mlnx_port_phy_foreach(port, ii) {
        is_port_present = false;
        for (jj = 0; jj < sx_port_count; jj++) {
            if (port->logical == sx_list_entry[jj].log_port) {
                is_port_present = true;
                break;
            }
        }

        if (false == is_port_present) {
            ports[target_port_count] = port->logical;
            target_port_count++;
        }
    }

    *port_count = target_port_count;

    return SAI_STATUS_SUCCESS;
}

static void mlnx_acl_port_mask_to_sx_list(_In_ uint64_t           mask,
                                          _Out_ sx_port_log_id_t *ports,
                                          _Inout_ uint32_t       *port_count)
{
    uint32_t port_db_index, port_out_index;

    assert((ports != NULL) && (port_count != NULL));
    assert(*port_count >= MAX_PORTS);

    port_db_index = port_out_index = 0;
    while (mask) {
        if (mask & 1) {
            ports[port_out_index] = g_sai_db_ptr->ports_db[port_db_index].logical;
            port_out_index++;
        }

        mask >>= 1;
        port_db_index++;
    }

    *port_count = port_out_index;
}

static sai_status_t mlnx_acl_sx_port_lists_update(_In_ sx_access_cmd_t cmd, _In_ sx_port_log_id_t sx_port)
{
    sx_status_t              sx_status;
    sx_acl_port_list_entry_t sx_port_list_entry[MAX_PORTS];
    sx_port_log_id_t         sx_ports[MAX_PORTS];
    uint64_t                 port_mask;
    uint32_t                 ii, jj, checked_count, port_lists_count, port_count;

    assert((SX_ACCESS_CMD_ADD_PORTS == cmd) || (SX_ACCESS_CMD_DELETE_PORTS == cmd));

    memset(&sx_port_list_entry, 0, sizeof(sx_port_list_entry));

    for (ii = 0; ii < MAX_PORTS; ii++) {
        if (g_sai_db_ptr->ports_db[ii].logical == sx_port) {
            break;
        }
    }

    assert(ii < MAX_PORTS);
    port_mask = UINT64_C(1) << ii;

    port_lists_count = sai_acl_db->acl_settings_tbl->port_lists_count;

    checked_count = 0;
    for (ii = 0; (ii < ACL_MAX_PORT_LISTS_COUNT) && (checked_count < port_lists_count); ii++) {
        if (acl_db_port_list(ii).is_used) {
            port_count = MAX_PORTS;

            mlnx_acl_port_mask_to_sx_list(acl_db_port_list(ii).port_mask, sx_ports, &port_count);
            assert((SX_ACCESS_CMD_DELETE_PORTS == cmd) || (port_count < MAX_PORTS));

            if (SX_ACCESS_CMD_ADD_PORTS == cmd) {
                sx_ports[port_count] = sx_port;
                port_count++;

                acl_db_port_list(ii).port_mask |= port_mask;
            } else { /* delete */
                if (acl_db_port_list(ii).port_mask & port_mask) {
                    for (jj = 0; jj < port_count; jj++) {
                        if (sx_ports[jj] == sx_port) {
                            break;
                        }
                    }
                    assert(jj != port_count);

                    sx_ports[jj] = sx_ports[port_count - 1];
                    port_count--;

                    acl_db_port_list(ii).port_mask &= ~port_mask;
                }
            }

            for (jj = 0; jj < port_count; jj++) {
                sx_port_list_entry[jj].port_match = SX_ACL_PORT_LIST_MATCH_NEGATIVE;
                sx_port_list_entry[jj].log_port   = sx_ports[jj];
            }

            sx_status = sx_api_acl_port_list_set(gh_sdk, SX_ACCESS_CMD_SET, sx_port_list_entry, port_count,
                                                 &acl_db_port_list(ii).sx_port_list_id);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to update sx port list[%d] %s.\n",  acl_db_port_list(ii).sx_port_list_id,
                           SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }

            checked_count++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_port_to_sx(_In_ sai_object_id_t sai_port, _Out_ sx_port_log_id_t *sx_port)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *port_config;
    uint32_t            ii;
    bool                port_exists;

    assert(sx_port != NULL);

    status = mlnx_object_to_type(sai_port, SAI_OBJECT_TYPE_PORT, sx_port, NULL);
    if (SAI_STATUS_SUCCESS != status) {
        return status;
    }

    port_exists = false;
    mlnx_port_phy_foreach(port_config, ii) {
        if (port_config->logical == *sx_port) {
            if (mlnx_port_is_lag_member(port_config)) {
                SX_LOG_ERR("Port [%x] is lag member\n", port_config->logical);
                status = SAI_STATUS_FAILURE;
            }

            port_exists = true;
            break;
        }
    }

    if (false == port_exists) {
        SX_LOG_NTC("Failed to find SAI port [%lx] in SAI DB\n", sai_port);
        status = SAI_STATUS_ITEM_NOT_FOUND;
    }

    return status;
}

static sai_status_t mlnx_sai_lag_to_sx(_In_ sai_object_id_t    sai_lag,
                                       _Out_ sx_port_log_id_t *sx_lag,
                                       _Out_ uint32_t         *lag_index)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *lag_config;
    uint32_t            ii;
    bool                lag_exists;

    assert(sx_lag != NULL);

    status = mlnx_object_to_type(sai_lag, SAI_OBJECT_TYPE_LAG, sx_lag, NULL);
    if (SAI_STATUS_SUCCESS != status) {
        return status;
    }

    lag_exists = false;
    mlnx_lag_foreach(lag_config, ii) {
        if (lag_config->logical == *sx_lag) {
            *lag_index = ii - MAX_PORTS; /* LAGs indexes are in the range [MAX_PORTS, MAX_PORTS * 2)*/
            lag_exists = true;
            break;
        }
    }

    if (false == lag_exists) {
        SX_LOG_NTC("Failed to find SAI lag [%lx] in SAI DB\n", sai_lag);
        status = SAI_STATUS_ITEM_NOT_FOUND;
    }

    return status;
}

static bool mlnx_sai_acl_redirect_action_attr_check(_In_ sai_object_id_t object_id)
{
    sai_object_type_t object_type;

    object_type = sai_object_type_query(object_id);

    switch (object_type) {
    case SAI_OBJECT_TYPE_PORT:
    case SAI_OBJECT_TYPE_LAG:
    case SAI_OBJECT_TYPE_NEXT_HOP:
    case SAI_OBJECT_TYPE_NEXT_HOP_GROUP:
        return true;

    default:
        SX_LOG_ERR("Bad object type %s for attribute ACTION_REDIRECT\n", SAI_TYPE_STR(object_type));
        return false;
    }
}

/*
 *   Routine Description:
 *       Create all entry data related to ACTION_REDIRECT
 *
 *      Arguments:
 *          object_id     - destination of ACTION_REDIRECT. May be PORT/LAG/NEXT_HOP/HEXT_HOP_GROUP
 *          res_refs      - represents the reference counters for ports/lags
 *          redirect_data - represents data related to ACTION_REDIRECT for some specific entry
 *          sx_action     - flex_action that will be filled with proper data according to object_id
 *
 *         Return Values:
 *             SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */

static sai_status_t mlnx_sai_acl_redirect_action_create(_In_ sai_object_id_t             object_id,
                                                        _Out_ acl_entry_res_refs_t      *res_refs,
                                                        _Out_ acl_entry_redirect_data_t *redirect_data,
                                                        _Out_ sx_flex_acl_flex_action_t *sx_action)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sai_object_type_t object_type;
    sx_port_log_id_t  sx_pbs_ports[MAX_PORTS] = {0};
    sx_port_log_id_t  sx_lag_id               = ACL_INVALID_LAG_ID;
    sx_ecmp_id_t      sx_ecmp_id;
    port_pbs_index_t  port_pbs_index = ACL_INVALID_PORT_PBS_INDEX;
    lag_pbs_index_t   lag_pbs_index  = ACL_INVALID_LAG_PBS_INDEX;
    uint32_t          sx_pbs_ports_number, lag_index;
    sx_acl_pbs_id_t   sx_pbs_id;

    assert((sx_action != NULL) && (res_refs != NULL) && (redirect_data != NULL));
    object_type = sai_object_type_query(object_id);

    switch (object_type) {
    case SAI_OBJECT_TYPE_PORT:
    case SAI_OBJECT_TYPE_LAG:
        if (SAI_OBJECT_TYPE_PORT == object_type) {
            status = mlnx_sai_port_to_sx(object_id, &sx_pbs_ports[0]);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            res_refs->is_pbs_ports_present = true;

            status = mlnx_acl_sx_port_list_to_mask(&sx_pbs_ports[0], 1, &res_refs->pbs_ports_mask);
            assert(SAI_STATUS_SUCCESS == status);

            sx_pbs_ports_number = 1;

            status = mlnx_acl_pbs_entry_create_or_get(sx_pbs_ports, sx_pbs_ports_number, &sx_pbs_id, &port_pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            redirect_data->port_pbs_index = port_pbs_index;
            redirect_data->pbs_type       = ACL_ENTRY_PBS_TYPE_PORT;
        } else {     /* LAG */
            status = mlnx_sai_lag_to_sx(object_id, &sx_lag_id, &lag_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            res_refs->is_lags_present = true;
            res_refs->lag_index       = lag_index;

            status = mlnx_acl_lag_pbs_create_or_get(sx_lag_id, &sx_pbs_id, &lag_pbs_index);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            redirect_data->lag_pbs_index = lag_pbs_index;
            redirect_data->pbs_type      = ACL_ENTRY_PBS_TYPE_LAG;
        }

        redirect_data->redirect_type        = ACL_ENTRY_REDIRECT_TYPE_REDIRECT;
        sx_action->type                     = SX_FLEX_ACL_ACTION_PBS;
        sx_action->fields.action_pbs.pbs_id = sx_pbs_id;
        break;

    case SAI_OBJECT_TYPE_NEXT_HOP:
    case SAI_OBJECT_TYPE_NEXT_HOP_GROUP:
        status = mlnx_object_to_type(object_id, object_type, &sx_ecmp_id, NULL);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        sx_action->type                                          = SX_FLEX_ACL_ACTION_UC_ROUTE;
        sx_action->fields.action_uc_route.uc_route_type          = SX_UC_ROUTE_TYPE_NEXT_HOP;
        sx_action->fields.action_uc_route.uc_route_param.ecmp_id = sx_ecmp_id;

        redirect_data->redirect_type = ACL_ENTRY_REDIRECT_TYPE_EMPTY;
        break;

    default:
        status = SAI_STATUS_INVALID_ATTR_VALUE_0;
        goto out;
    }

out:
    return status;
}

static const char* mlnx_acl_entry_redirect_type_to_str(acl_entry_redirect_type_t redirect_type)
{
    switch (redirect_type) {
    case ACL_ENTRY_REDIRECT_TYPE_REDIRECT:
        return "ACTION_REDIRECT";

    case ACL_ENTRY_REDIRECT_TYPE_REDIRECT_LIST:
        return "ACTION_REDIRECT_LIST";

    case ACL_ENTRY_REDIRECT_TYPE_FLOOD:
        return "ACTION_REDIRECT_FLOOD";

    default:
        assert(false);
        return "Unknown";
    }
}

static bool mlnx_acl_index_is_group(_In_ acl_index_t index)
{
    return SAI_OBJECT_TYPE_ACL_TABLE_GROUP == index.acl_object_type;
}

static bool mlnx_acl_indexes_is_equal(_In_ acl_index_t a, _In_ acl_index_t b)
{
    return ((a.acl_db_index == b.acl_db_index) && (a.acl_object_type == b.acl_object_type));
}

static bool mlnx_acl_bind_point_indexes_is_equal(_In_ acl_bind_point_index_t a, _In_ acl_bind_point_index_t b)
{
    return ((a.index == b.index) && (a.type == b.type));
}

static sai_status_t mlnx_acl_index_to_sai_object(_In_ acl_index_t acl_index, _Out_ sai_object_id_t *objet_id)
{
    assert(objet_id != NULL);

    return mlnx_create_object(acl_index.acl_object_type, acl_index.acl_db_index, NULL, objet_id);
}

static uint32_t mlnx_acl_group_capacity_get(_In_ uint32_t group_index)
{
    sai_acl_table_group_type_t group_type;

    assert(acl_group_index_check_range(group_index));

    group_type = sai_acl_db_group_ptr(group_index)->search_type;

    if (SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL == group_type) {
        return ACL_SEQ_GROUP_SIZE;
    } else {
        return ACL_PAR_GROUP_SIZE;
    }
}

static void mlnx_acl_group_db_bind_point_find(_In_ uint32_t               group_index,
                                              _In_ acl_bind_point_index_t bind_point_index,
                                              _In_ uint32_t              *index)
{
    acl_group_bound_to_t   *group_bound_to;
    acl_bind_point_index_t *indexes;
    uint32_t                ii;

    assert(index != NULL);

    group_bound_to = sai_acl_db_group_bount_to(group_index);
    indexes        = group_bound_to->indexes;

    for (ii = 0; ii < group_bound_to->count; ii++) {
        if (mlnx_acl_bind_point_indexes_is_equal(bind_point_index, indexes[ii])) {
            *index = ii;
            return;
        }
    }

    *index = ACL_INVALID_DB_INDEX;
}

static bool mlnx_acl_group_db_bind_point_is_present(_In_ uint32_t               group_index,
                                                    _In_ acl_bind_point_index_t bind_point_index)
{
    uint32_t index;

    mlnx_acl_group_db_bind_point_find(group_index, bind_point_index, &index);

    return index != ACL_INVALID_DB_INDEX;
}

static sai_status_t mlnx_acl_bind_point_type_list_validate_and_fetch(_In_ const sai_s32_list_t        *types,
                                                                     _In_ uint32_t                     attr_idnex,
                                                                     _Out_ acl_bind_point_type_list_t *list)
{
    sai_acl_bind_point_type_t type;
    bool                      is_rif_present, is_non_rif_present;
    bool                      present_types[SAI_ACL_BIND_POINT_TYPE_COUNT] = {false};
    uint32_t                  ii;

    assert(types != NULL);

    if (0 == types->count) {
        SX_LOG_ERR("Count of bind point types is 0\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idnex;
    }

    list->count    = 0;
    is_rif_present = is_non_rif_present = false;

    for (ii = 0; ii < types->count; ii++) {
        type = types->list[ii];

        if (type > SAI_ACL_BIND_POINT_TYPE_SWITCH) {
            SX_LOG_ERR("Invalid bind point type (%d) at index [%d] in the list\n", type, ii);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idnex;
        }

        if (SAI_ACL_BIND_POINT_TYPE_SWITCH == type) {
            SX_LOG_ERR("SAI_ACL_BIND_POINT_TYPE_SWITCH is not supported\n");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idnex;
        }

        if (SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF == type) {
            if (is_non_rif_present) {
                SX_LOG_ERR("Both RIF and PORT/LAG bind points for the same group/table is not supported\n");
                return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idnex;
            }

            is_rif_present = true;
        } else {
            if (is_rif_present) {
                SX_LOG_ERR("Both RIF and PORT/LAG bind points for the same group/table is not supported\n");
                return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idnex;
            }

            is_non_rif_present = true;
        }

        if (present_types[type]) {
            SX_LOG_ERR("Bind point type (%d) appears twice in the list", type);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idnex;
        }

        list->types[list->count] = type;
        list->count++;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_oid_fetch_data(_In_ sai_object_id_t oid,
                                                       _In_ uint32_t        attr_index,
                                                       _Out_ acl_index_t   *acl_index)
{
    sai_status_t               status;
    sai_object_type_t          object_type;
    uint32_t                   object_data, table_group_index;
    sai_acl_table_group_type_t table_group_type;

    assert(NULL != acl_index);

    object_type = sai_object_type_query(oid);
    if ((SAI_OBJECT_TYPE_ACL_TABLE != object_type) && (SAI_OBJECT_TYPE_ACL_TABLE_GROUP != object_type)) {
        SX_LOG_ERR("Expected object %s or %s got %s\n", SAI_TYPE_STR(SAI_OBJECT_TYPE_ACL_TABLE),
                   SAI_TYPE_STR(SAI_OBJECT_TYPE_ACL_TABLE_GROUP), SAI_TYPE_STR(object_type));
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_object_to_type(oid, object_type, &object_data, NULL);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Unexpected error - failed to fetch a data from object id [%lx]\n", oid);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if (SAI_OBJECT_TYPE_ACL_TABLE_GROUP == object_type) {
        if (false == sai_acl_db_group_ptr(object_data)->is_used) {
            SX_LOG_ERR("Group id [%lx] is invalid\n", oid);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }
    } else {
        if (false == acl_db_table(object_data).is_used) {
            SX_LOG_ERR("Table [%lx] is deleted\n", oid);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }

        table_group_index = acl_db_table(object_data).group_index;
        if (ACL_INVALID_DB_INDEX != table_group_index) {
            table_group_type = sai_acl_db_group_ptr(table_group_index)->search_type;
            if (SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL != table_group_type) {
                SX_LOG_ERR("The table [%lx] is a member of sequential group\n", oid);
                return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
            }
        }
    }

    acl_index->acl_db_index    = object_data;
    acl_index->acl_object_type = object_type;

    return SAI_STATUS_SUCCESS;
}

static const acl_bind_point_type_list_t* mlnx_acl_table_or_group_bind_point_list_fetch(_In_ acl_index_t acl_index)
{
    assert((SAI_OBJECT_TYPE_ACL_TABLE == acl_index.acl_object_type) ||
           (SAI_OBJECT_TYPE_ACL_TABLE_GROUP == acl_index.acl_object_type));

    if (mlnx_acl_index_is_group(acl_index)) {
        return &sai_acl_db_group_ptr(acl_index.acl_db_index)->bind_point_types;
    } else {
        return &acl_db_table(acl_index.acl_db_index).bind_point_types;
    }
}

static sai_acl_stage_t mlnx_acl_index_stage_get(_In_ acl_index_t acl_index)
{
    assert((SAI_OBJECT_TYPE_ACL_TABLE == acl_index.acl_object_type) ||
           (SAI_OBJECT_TYPE_ACL_TABLE_GROUP == acl_index.acl_object_type));

    if (mlnx_acl_index_is_group(acl_index)) {
        return sai_acl_db_group_ptr(acl_index.acl_db_index)->stage;
    } else {
        return acl_db_table(acl_index.acl_db_index).stage;
    }
}

sai_status_t mlnx_acl_bind_point_attrs_check_and_fetch(_In_ sai_object_id_t            acl_object_id,
                                                       _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                       _In_ uint32_t                   attr_index,
                                                       _Out_ acl_index_t              *acl_index)
{
    sai_status_t                      status;
    sai_acl_bind_point_type_t         sai_bind_point_type;
    sai_acl_stage_t                   bind_point_stage, acl_stage;
    const acl_bind_point_type_list_t *bind_point_types;
    uint32_t                          ii;
    bool                              bind_point_type_present;

    if (SAI_NULL_OBJECT_ID == acl_object_id) {
        acl_index->acl_db_index = ACL_INVALID_DB_INDEX;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_acl_bind_point_oid_fetch_data(acl_object_id, attr_index, acl_index);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_bind_point_type = mlnx_acl_bind_point_type_to_sai(bind_point_type);
    bind_point_types    = mlnx_acl_table_or_group_bind_point_list_fetch(*acl_index);
    bind_point_stage    = mlnx_acl_bind_point_type_to_sai_stage(bind_point_type);
    acl_stage           = mlnx_acl_index_stage_get(*acl_index);

    if (bind_point_stage != acl_stage) {
        SX_LOG_ERR("ACL stage (%d) is not the same as bind point stage (%d)\n", acl_stage, bind_point_stage);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    bind_point_type_present = false;
    for (ii = 0; ii < bind_point_types->count; ii++) {
        if (sai_bind_point_type == bind_point_types->types[ii]) {
            bind_point_type_present = true;
            break;
        }
    }

    if (false == bind_point_type_present) {
        SX_LOG_ERR("SAI ACL object id [%lx] doesn't support a bind point (%d)\n", acl_object_id, sai_bind_point_type);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sx_acl_direction_t mlnx_acl_sai_bind_point_type_to_sx_direction(_In_ sai_acl_bind_point_type_t bind_point_type,
                                                                       _In_ sai_acl_stage_t           stage)
{
    assert((SAI_ACL_STAGE_INGRESS == stage ||
            SAI_ACL_STAGE_EGRESS == stage));

    switch (bind_point_type) {
    case SAI_ACL_BIND_POINT_TYPE_SWITCH:
    case SAI_ACL_BIND_POINT_TYPE_PORT:
    case SAI_ACL_BIND_POINT_TYPE_LAG:
    case SAI_ACL_BIND_POINT_TYPE_VLAN:
        if (SAI_ACL_STAGE_INGRESS == stage) {
            return SX_ACL_DIRECTION_INGRESS;
        } else {
            return SX_ACL_DIRECTION_EGRESS;
        }

    case SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF:
        if (SAI_ACL_STAGE_INGRESS == stage) {
            return SX_ACL_DIRECTION_RIF_INGRESS;
        } else {
            return SX_ACL_DIRECTION_RIF_EGRESS;
        }

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", bind_point_type);
        assert(false);
        return SX_ACL_DIRECTION_INGRESS;
    }
}

static sx_acl_direction_t mlnx_acl_bind_point_type_to_sx_direction(_In_ mlnx_acl_bind_point_type_t bind_point_type)
{
    switch (bind_point_type) {
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_DEFAULT:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN:
        return SX_ACL_DIRECTION_INGRESS;

    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_DEFAULT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN:
        return SX_ACL_DIRECTION_EGRESS;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE:
        return SX_ACL_DIRECTION_RIF_INGRESS;

    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE:
        return SX_ACL_DIRECTION_RIF_EGRESS;

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", bind_point_type);
        assert(false);
        return SX_ACL_DIRECTION_INGRESS;
    }
}

static sai_acl_bind_point_type_t mlnx_acl_bind_point_type_to_sai(_In_ mlnx_acl_bind_point_type_t bind_point_type)
{
    switch (bind_point_type) {
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_DEFAULT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_DEFAULT:
        return SAI_ACL_BIND_POINT_TYPE_SWITCH;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT:
        return SAI_ACL_BIND_POINT_TYPE_PORT;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG:
        return SAI_ACL_BIND_POINT_TYPE_LAG;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE:
        return SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN:
        return SAI_ACL_BIND_POINT_TYPE_VLAN;

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", bind_point_type);
        assert(false);
        return SAI_ACL_BIND_POINT_TYPE_SWITCH;
    }
}

static sai_acl_stage_t mlnx_acl_bind_point_type_to_sai_stage(_In_ mlnx_acl_bind_point_type_t bind_point_type)
{
    switch (bind_point_type) {
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_DEFAULT:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE:
        return SAI_ACL_STAGE_INGRESS;

    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_DEFAULT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE:
        return SAI_ACL_STAGE_EGRESS;

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", bind_point_type);
        assert(false);
        return SAI_ACL_STAGE_INGRESS;
    }
}

sai_status_t mlnx_acl_rif_bind_point_clear(_In_ sai_object_id_t rif)
{
    sai_status_t status;
    acl_index_t  acl_index;

    acl_index = ACL_INDEX_INVALID;

    if (false == sai_acl_db->acl_settings_tbl->initialized) {
        return SAI_STATUS_SUCCESS;
    }

    acl_global_lock();

    status = mlnx_acl_port_lag_rif_bind_point_set(rif, MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE,
                                                  acl_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_port_lag_rif_bind_point_set(rif, MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE,
                                                  acl_index);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_global_unlock();
    return status;
}

sai_status_t mlnx_acl_vlan_bind_point_clear(_In_ sai_object_id_t vlan_oid)
{
    sai_status_t status;
    acl_index_t  acl_index;

    acl_index.acl_db_index = ACL_INVALID_DB_INDEX;

    if (false == sai_acl_db->acl_settings_tbl->initialized) {
        return SAI_STATUS_SUCCESS;
    }

    acl_global_lock();

    status = mlnx_acl_vlan_bind_point_set(vlan_oid, MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN, acl_index);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_global_unlock();
    return status;
}

static sai_status_t mlnx_acl_port_lag_bind_point_clear(_In_ const mlnx_port_config_t *port_config,
                                                       _In_ sai_acl_stage_t           sai_acl_stage)
{
    mlnx_acl_bind_point_type_t bind_point_type;
    acl_index_t                acl_index;

    if (mlnx_port_is_lag(port_config)) {
        if (SAI_ACL_STAGE_INGRESS == sai_acl_stage) {
            bind_point_type = MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG;
        } else {
            bind_point_type = MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG;
        }
    } else {
        if (SAI_ACL_STAGE_INGRESS == sai_acl_stage) {
            bind_point_type = MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT;
        } else {
            bind_point_type = MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT;
        }
    }

    acl_index.acl_db_index = ACL_INVALID_DB_INDEX;

    return mlnx_acl_port_lag_rif_bind_point_set(port_config->saiport, bind_point_type, acl_index);
}

static sai_status_t mlnx_acl_port_bind_refresh(_In_ const mlnx_port_config_t *port_config)
{
    sai_status_t           status;
    acl_bind_point_t      *bind_point_port_lag;
    acl_bind_point_data_t *ingress_data, *egress_data;
    uint32_t               port_index;

    assert(NULL != port_config);

    port_index = mlnx_port_idx_get(port_config);

    bind_point_port_lag = &sai_acl_db->acl_bind_points->ports_lags[port_index];
    ingress_data        = &bind_point_port_lag->ingress_data;
    egress_data         = &bind_point_port_lag->egress_data;

    status = mlnx_acl_bind_point_sx_update(ingress_data);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_bind_point_sx_update(egress_data);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    return status;
}

static void mlnx_acl_group_db_bind_point_remove(_In_ uint32_t               group_index,
                                                _In_ acl_bind_point_index_t bind_point_index)
{
    acl_group_bound_to_t *group_bound_to;
    uint32_t              index_to_delete, index_count;

    mlnx_acl_group_db_bind_point_find(group_index, bind_point_index, &index_to_delete);
    assert(index_to_delete != ACL_INVALID_DB_INDEX);

    group_bound_to = sai_acl_db_group_bount_to(group_index);
    index_count    = group_bound_to->count;

    assert(index_count > 0);

    group_bound_to->indexes[index_to_delete] = group_bound_to->indexes[index_count - 1];
    group_bound_to->count--;
}

static void mlnx_acl_group_db_bind_point_add(_In_ uint32_t group_index, _In_ acl_bind_point_index_t bind_point_index)
{
    acl_group_bound_to_t *group_bound_to;

    group_bound_to = sai_acl_db_group_bount_to(group_index);

    group_bound_to->indexes[group_bound_to->count] = bind_point_index;
    group_bound_to->count++;

    assert(group_bound_to->count <= SAI_ACL_MAX_BIND_POINT_BOUND);
}

static sai_status_t mlnx_acl_bind_point_sx_group_remove(_In_ acl_bind_point_data_t *bind_point_data)
{
    sai_status_t       status;
    sx_status_t        sx_status;
    sx_acl_direction_t sx_direction;
    sx_acl_id_t        sx_group;

    if (false == bind_point_data->is_sx_group_created) {
        status = SAI_STATUS_SUCCESS;
        goto out;
    }

    sx_direction = bind_point_data->target_data.sx_direction;
    sx_group     = bind_point_data->sx_group;

    status = mlnx_acl_bind_point_sx_bind_set(SX_ACCESS_CMD_UNBIND, bind_point_data);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, sx_direction, NULL, 0, &sx_group);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete sx group [%x]\n", bind_point_data->sx_group);
        status = sdk_to_sai(sx_status);
        goto out;
    }

    bind_point_data->is_sx_group_created = false;

out:
    return status;
}

static sai_status_t mlnx_acl_bind_point_group_sx_set(_In_ acl_bind_point_data_t *bind_point_data,
                                                     _In_ uint32_t               group_index)
{
    sai_status_t              status = SAI_STATUS_SUCCESS;
    sx_status_t               sx_status;
    sx_acl_id_t               sx_head_acl, *sx_acls = NULL;
    sx_acl_direction_t        sx_direction;
    const acl_group_db_t     *acl_group;
    const acl_group_member_t *group_members;
    uint32_t                  sx_acl_count, head_table_index, ii;

    acl_group    = sai_acl_db_group_ptr(group_index);
    sx_direction = bind_point_data->target_data.sx_direction;

    if (0 == acl_group->members_count) {
        status = mlnx_acl_bind_point_sx_group_remove(bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }

        /* if SAI Group is empty, and sx resources are not used - nothing to do*/
        status = SAI_STATUS_SUCCESS;
        goto out;
    } else {
        if (false == bind_point_data->is_sx_group_created) {
            sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_direction, NULL, 0,
                                             &bind_point_data->sx_group);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to create sx group\n");
                status = sdk_to_sai(sx_status);
                goto out;
            }

            bind_point_data->is_sx_group_created = true;

            status = mlnx_acl_bind_point_sx_bind_set(SX_ACCESS_CMD_BIND, bind_point_data);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        if (SAI_ACL_TABLE_GROUP_TYPE_PARALLEL == acl_group->search_type) {
            group_members = acl_group->members;
            sx_acl_count  = acl_group->members_count;

            sx_acls = calloc(sx_acl_count, sizeof(sx_acl_id_t));
            if (NULL == sx_acls) {
                SX_LOG_ERR("ERROR: unable to allocate memory for sx_acl_id[]\n");
                status = SAI_STATUS_NO_MEMORY;
                goto out;
            }

            for (ii = 0; ii < sx_acl_count; ii++) {
                sx_acls[ii] = acl_db_table(group_members[ii].table_index).table_id;
            }

            sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_direction,
                                             sx_acls, sx_acl_count, &bind_point_data->sx_group);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to update sx group (%x) - %s\n", bind_point_data->sx_group,
                           SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
        } else {
            head_table_index = acl_group->members[0].table_index;
            sx_head_acl      = acl_db_table(head_table_index).table_id;

            sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_direction,
                                             &sx_head_acl, 1, &bind_point_data->sx_group);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to update sx group (%x) - %s\n", bind_point_data->sx_group,
                           SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
        }
    }

out:
    free(sx_acls);
    return status;
}

static sai_status_t mlnx_acl_bind_point_table_sx_set(_In_ acl_bind_point_data_t *bind_point_data,
                                                     _In_ uint32_t               table_index)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_status_t        sx_status;
    sx_acl_id_t        sx_acl_id;
    sx_acl_direction_t sx_direction;

    assert(acl_db_table(table_index).is_used);

    sx_acl_id    = acl_db_table(table_index).table_id;
    sx_direction = bind_point_data->target_data.sx_direction;

    if (false == bind_point_data->is_sx_group_created) {
        sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_direction, NULL, 0,
                                         &bind_point_data->sx_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create sx group\n");
            status = sdk_to_sai(sx_status);
            goto out;
        }

        bind_point_data->is_sx_group_created = true;

        status = mlnx_acl_bind_point_sx_bind_set(SX_ACCESS_CMD_BIND, bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_direction,
                                     &sx_acl_id, 1, &bind_point_data->sx_group);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to update sx group (%x)\n", bind_point_data->sx_group);
        status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    return status;
}

static void mlnx_acl_bind_point_db_update(_In_ acl_bind_point_data_t *bind_point_data,
                                          _In_ acl_index_t            acl_index,
                                          _In_ acl_bind_point_index_t bind_point_index)
{
    if (is_acl_index_invalid(acl_index)) {
        if (mlnx_acl_index_is_group(bind_point_data->acl_index)) {
            mlnx_acl_group_db_bind_point_remove(bind_point_data->acl_index.acl_db_index, bind_point_index);
        }

        bind_point_data->is_object_set = false;
    } else {
        assert((SAI_OBJECT_TYPE_ACL_TABLE_GROUP == acl_index.acl_object_type) ||
               (SAI_OBJECT_TYPE_ACL_TABLE == acl_index.acl_object_type));

        if ((bind_point_data->is_object_set) &&
            mlnx_acl_index_is_group(bind_point_data->acl_index)) {
            mlnx_acl_group_db_bind_point_remove(bind_point_data->acl_index.acl_db_index, bind_point_index);
        }

        if (mlnx_acl_index_is_group(acl_index)) {
            mlnx_acl_group_db_bind_point_add(acl_index.acl_db_index, bind_point_index);
        }

        bind_point_data->is_object_set = true;
    }

    bind_point_data->acl_index = acl_index;
}

static sai_status_t mlnx_acl_bind_point_sx_update(_In_ acl_bind_point_data_t *bind_point_data)
{
    sai_status_t status;
    acl_index_t  acl_index;

    acl_index = bind_point_data->acl_index;

    if (false == bind_point_data->is_object_set) {
        status = mlnx_acl_bind_point_sx_group_remove(bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        assert((SAI_OBJECT_TYPE_ACL_TABLE_GROUP == acl_index.acl_object_type) ||
               (SAI_OBJECT_TYPE_ACL_TABLE == acl_index.acl_object_type));

        if (mlnx_acl_index_is_group(acl_index)) {
            status = mlnx_acl_bind_point_group_sx_set(bind_point_data, acl_index.acl_db_index);
            if (SAI_ERR(status)) {
                goto out;
            }
        } else {
            status = mlnx_acl_bind_point_table_sx_set(bind_point_data, acl_index.acl_db_index);
            if (SAI_ERR(status)) {
                goto out;
            }
        }
    }

out:
    return status;
}

static sai_status_t mlnx_acl_bind_point_sai_acl_apply(_In_ acl_bind_point_data_t *bind_point_data,
                                                      _In_ acl_index_t            acl_index,
                                                      _In_ acl_bind_point_index_t bind_point_index)
{
    sai_status_t status;

    assert((SAI_OBJECT_TYPE_ACL_TABLE_GROUP == acl_index.acl_object_type) ||
           (SAI_OBJECT_TYPE_ACL_TABLE == acl_index.acl_object_type));

    mlnx_acl_bind_point_db_update(bind_point_data, acl_index, bind_point_index);

    status = mlnx_acl_bind_point_sx_update(bind_point_data);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    return status;
}

static sai_status_t mlnx_acl_port_lag_db_index_validate_and_get(_In_ sai_object_id_t oid, _In_ uint32_t        *index)
{
    sai_status_t status;

    assert(index != NULL);

    status = mlnx_port_idx_by_obj_id(oid, index);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_port_lag_index_get(_In_ sai_object_id_t            oid,
                                                           _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                           _In_ acl_bind_point_index_t    *index)
{
    sai_status_t status;
    uint32_t     port_index;

    assert(index != NULL);

    status = mlnx_acl_port_lag_db_index_validate_and_get(oid, &port_index);
    if (SAI_ERR(status)) {
        return status;
    }

    index->type  = mlnx_acl_bind_point_type_to_sai(bind_point_type);
    index->index = port_index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_rif_index_get(_In_ sai_object_id_t oid, _In_ acl_bind_point_index_t *index)
{
    sai_status_t status;
    uint32_t     rif_id;

    assert(index != NULL);

    status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &rif_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    index->type  = SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF;
    index->index = rif_id;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_port_lag_rif_index_get(_In_ sai_object_id_t            oid,
                                                               _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                               _In_ acl_bind_point_index_t    *index)
{
    switch (bind_point_type) {
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG:
        return mlnx_acl_bind_point_port_lag_index_get(oid, bind_point_type, index);

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE:
        return mlnx_acl_bind_point_rif_index_get(oid, index);

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", bind_point_type);
        assert(false);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_port_lag_data_fetch(_In_ sai_object_id_t            oid,
                                                            _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                            _In_ acl_bind_point_data_t    **data)
{
    sai_status_t           status;
    uint32_t               index;
    acl_bind_point_data_t *bind_point_data;

    assert(data != NULL);

    status = mlnx_acl_port_lag_db_index_validate_and_get(oid, &index);
    if (SAI_ERR(status)) {
        return status;
    }

    assert(index < MAX_PORTS * 2);

    if ((MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT == bind_point_type) ||
        (MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG == bind_point_type)) {
        bind_point_data = &sai_acl_db->acl_bind_points->ports_lags[index].ingress_data;
    } else {
        bind_point_data = &sai_acl_db->acl_bind_points->ports_lags[index].egress_data;
    }

    if (false == bind_point_data->target_data.is_set) {
        bind_point_data->target_data.sai_bind_point_type = mlnx_acl_bind_point_type_to_sai(bind_point_type);
        bind_point_data->target_data.sx_direction        = mlnx_acl_bind_point_type_to_sx_direction(bind_point_type);
        bind_point_data->target_data.sx_port             = g_sai_db_ptr->ports_db[index].logical;
        bind_point_data->target_data.is_set              = true;
    }

    *data = bind_point_data;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_rif_data_get(_In_ sai_object_id_t            oid,
                                                     _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                     _Out_ acl_bind_point_data_t   **data)
{
    sai_status_t           status;
    uint32_t               rif_id;
    acl_bind_point_data_t *bind_point_data;

    assert(data != NULL);

    status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &rif_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    if (ACL_RIF_COUNT <= rif_id) {
        SX_LOG_ERR("rif id [%d] exceeds range (0, %d)", rif_id, ACL_RIF_COUNT);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE == bind_point_type) {
        bind_point_data = &sai_acl_db->acl_bind_points->rifs[rif_id].ingress_data;
    } else {
        bind_point_data = &sai_acl_db->acl_bind_points->rifs[rif_id].egress_data;
    }

    if (false == bind_point_data->target_data.is_set) {
        bind_point_data->target_data.sai_bind_point_type = mlnx_acl_bind_point_type_to_sai(bind_point_type);
        bind_point_data->target_data.sx_direction        = mlnx_acl_bind_point_type_to_sx_direction(bind_point_type);
        bind_point_data->target_data.rif                 = rif_id;
        bind_point_data->target_data.is_set              = true;
    }

    *data = bind_point_data;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_vlan_is_bound(_In_ sai_object_id_t            vlan_oid,
                                                      _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                      _Out_ bool                     *is_bound)
{
    sai_status_t  status;
    sai_vlan_id_t vlan_id;

    assert(is_bound != NULL);

    status = sai_object_to_vlan(vlan_oid, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    *is_bound = sai_acl_db->acl_bind_points->vlans[vlan_id].is_bound;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_vlan_data_get(_In_ sai_object_id_t            vlan_oid,
                                                      _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                      _Out_ acl_bind_point_data_t   **data)
{
    sai_status_t           status;
    sai_vlan_id_t          vlan_id;
    acl_bind_point_vlan_t *bind_point_vlan;
    uint32_t               vlan_group_index;

    status = sai_object_to_vlan(vlan_oid, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    bind_point_vlan = &sai_acl_db->acl_bind_points->vlans[vlan_id];

    assert(bind_point_vlan->is_bound);

    vlan_group_index = bind_point_vlan->vlan_group_index;
    assert(vlan_group_index < ACL_VLAN_GROUP_COUNT);

    *data = &acl_db_vlan_group(vlan_group_index).bind_data;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_port_lag_rif_data_get(_In_ sai_object_id_t            target,
                                                              _In_ mlnx_acl_bind_point_type_t type,
                                                              _Out_ acl_bind_point_data_t   **data)
{
    switch (type) {
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG:
        return mlnx_acl_bind_point_port_lag_data_fetch(target, type, data);

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE:
        return mlnx_acl_bind_point_rif_data_get(target, type, data);

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", type);
        assert(false);
        return SAI_STATUS_INVALID_PARAMETER;
    }
}

static sai_status_t mlnx_acl_port_lag_bind_point_check_and_get(_In_ sai_object_id_t            target,
                                                               _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                               _Out_ acl_bind_point_data_t   **bind_data)
{
    sai_status_t     status;
    sai_object_id_t  lag_oid;
    sx_port_log_id_t sx_lag_id;
    uint32_t         port_index, lag_index;

    assert(bind_data != NULL);

    status = mlnx_port_idx_by_obj_id(target, &port_index);
    if (SAI_ERR(status)) {
        return status;
    }

    if (mlnx_port_is_lag_member(&mlnx_ports_db[port_index])) {
        sx_lag_id = mlnx_ports_db[port_index].lag_id;

        status = mlnx_port_idx_by_log_id(sx_lag_id, &lag_index);
        if (SAI_ERR(status)) {
            return status;
        }

        lag_oid = mlnx_ports_db[lag_index].saiport;

        status = mlnx_acl_bind_point_port_lag_data_fetch(lag_oid, bind_point_type, bind_data);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = mlnx_acl_bind_point_port_lag_data_fetch(target, bind_point_type, bind_data);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_port_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                      _In_ acl_bind_point_data_t *bind_point_data)
{
    sx_status_t      sx_status;
    sx_port_log_id_t sx_port_id;
    sx_acl_id_t      sx_group_id;

    assert(bind_point_data->target_data.is_set);
    assert(bind_point_data->is_sx_group_created);

    sx_port_id  = bind_point_data->target_data.sx_port;
    sx_group_id = bind_point_data->sx_group;

    sx_status = sx_api_acl_port_bind_set(gh_sdk, sx_cmd, sx_port_id, sx_group_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s sx group [%x] on port [%x]\n", SX_ACCESS_CMD_STR(sx_cmd), sx_group_id, sx_port_id);
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_rif_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                     _In_ acl_bind_point_data_t *bind_point_data)
{
    sx_status_t sx_status;
    sx_rif_id_t sx_rif_id;
    sx_acl_id_t sx_group_id;

    assert(bind_point_data->target_data.is_set);
    assert(bind_point_data->is_sx_group_created);

    sx_rif_id   = bind_point_data->target_data.rif;
    sx_group_id = bind_point_data->sx_group;

    sx_status = sx_api_acl_rif_bind_set(gh_sdk, sx_cmd, sx_rif_id, sx_group_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s sx group [%x] on rif [%x]\n", SX_ACCESS_CMD_STR(sx_cmd), sx_group_id, sx_rif_id);
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_vlan_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                      _In_ acl_bind_point_data_t *bind_point_data)
{
    sx_status_t         sx_status;
    sx_acl_vlan_group_t sx_vlan_group;
    sx_acl_id_t         sx_group_id;

    assert(bind_point_data->target_data.is_set);
    assert(bind_point_data->is_sx_group_created);

    sx_vlan_group = bind_point_data->target_data.vlan_group;
    sx_group_id   = bind_point_data->sx_group;

    sx_status = sx_api_acl_vlan_group_bind_set(gh_sdk, sx_cmd, sx_vlan_group, sx_group_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s sx group [%x] on vlan group [%d]", SX_ACCESS_CMD_STR(
                       sx_cmd), sx_group_id, sx_vlan_group);
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_sx_bind_set(_In_ sx_access_cmd_t        sx_cmd,
                                                    _In_ acl_bind_point_data_t *bind_point_data)
{
    sai_status_t              status;
    sai_acl_bind_point_type_t type;

    assert((SX_ACCESS_CMD_BIND == sx_cmd) || (SX_ACCESS_CMD_UNBIND == sx_cmd));

    type = bind_point_data->target_data.sai_bind_point_type;

    switch (type) {
    case SAI_ACL_BIND_POINT_TYPE_PORT:
    case SAI_ACL_BIND_POINT_TYPE_LAG:
        status = mlnx_acl_bind_point_port_bind_set(sx_cmd, bind_point_data);
        break;

    case SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF:
        status = mlnx_acl_bind_point_rif_bind_set(sx_cmd, bind_point_data);
        break;

    case SAI_ACL_BIND_POINT_TYPE_VLAN:
        status = mlnx_acl_bind_point_vlan_bind_set(sx_cmd, bind_point_data);
        break;

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", type);
        assert(false);
    }

    return status;
}

static bool mlnx_acl_is_bind_point_lag_member(_In_ acl_bind_point_index_t bind_point_index)
{
    uint32_t port_index;

    if (SAI_ACL_BIND_POINT_TYPE_PORT != bind_point_index.type) {
        return false;
    }

    port_index = bind_point_index.index;

    if (mlnx_port_is_lag_member(&mlnx_ports_db[port_index])) {
        return true;
    }

    return false;
}

static sai_status_t mlnx_acl_lag_member_bind_set(_In_ acl_bind_point_index_t     lag_member_bind_point_index,
                                                 _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                 _In_ acl_index_t                acl_index)
{
    sai_status_t               status;
    sai_object_id_t            target_lag_oid;
    mlnx_acl_bind_point_type_t lag_bind_point_type;
    sx_port_log_id_t           sx_lag_id;
    uint32_t                   lag_member_index, lag_index;

    assert((MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT == bind_point_type) ||
           (MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT == bind_point_type));

    assert(SAI_ACL_BIND_POINT_TYPE_PORT == lag_member_bind_point_index.type);

    lag_member_index = lag_member_bind_point_index.index;

    assert(mlnx_port_is_lag_member(&mlnx_ports_db[lag_member_index]));

    sx_lag_id = mlnx_ports_db[lag_member_index].lag_id;

    status = mlnx_port_idx_by_log_id(sx_lag_id, &lag_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    target_lag_oid = mlnx_ports_db[lag_index].saiport;

    if (MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT == bind_point_type) {
        lag_bind_point_type = MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG;
    } else {
        lag_bind_point_type = MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG;
    }

    status = mlnx_acl_port_lag_rif_bind_point_set(target_lag_oid, lag_bind_point_type, acl_index);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    return status;
}

sai_status_t mlnx_acl_port_lag_rif_bind_point_set(_In_ sai_object_id_t            target,
                                                  _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                  _In_ acl_index_t                acl_index)
{
    sai_status_t           status = SAI_STATUS_SUCCESS;
    acl_bind_point_data_t *bind_point_data;
    acl_bind_point_index_t bind_point_index;
    bool                   unbind, is_already_bound;

    SX_LOG_ENTER();

    assert((MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT == bind_point_type) ||
           (MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT == bind_point_type) ||
           (MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG == bind_point_type) ||
           (MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG == bind_point_type) ||
           (MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE == bind_point_type) ||
           (MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE == bind_point_type));

    status = mlnx_acl_bind_point_port_lag_rif_data_get(target, bind_point_type, &bind_point_data);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_bind_point_port_lag_rif_index_get(target, bind_point_type, &bind_point_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    unbind = is_acl_index_invalid(acl_index);

    if (unbind && (false == bind_point_data->is_object_set)) {
        assert(false == bind_point_data->is_sx_group_created);
        status = SAI_STATUS_SUCCESS;
        goto out;
    } else {
        if (bind_point_data->is_object_set) {
            if (mlnx_acl_index_is_group(acl_index)) {
                is_already_bound = mlnx_acl_group_db_bind_point_is_present(acl_index.acl_db_index, bind_point_index);

                if (is_already_bound) {
                    status = SAI_STATUS_SUCCESS;
                    goto out;
                }
            }
        }
    }

    mlnx_acl_bind_point_db_update(bind_point_data, acl_index, bind_point_index);

    if (mlnx_acl_is_bind_point_lag_member(bind_point_index)) {
        status = mlnx_acl_lag_member_bind_set(bind_point_index, bind_point_type, acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        status = mlnx_acl_bind_point_sx_update(bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_vlan_group_create_or_get(_In_ sx_vlan_id_t       sx_vlan_id,
                                                      _In_ acl_index_t        acl_index,
                                                      _In_ sx_acl_direction_t sx_acl_direction,
                                                      _Out_ uint32_t         *vlan_group_index)
{
    sai_status_t           status = SAI_STATUS_SUCCESS;
    sx_status_t            sx_status;
    sx_swid_t              sx_swid_id = DEFAULT_ETH_SWID;
    acl_bind_point_index_t bind_point_index;
    uint32_t               index, free_index, ii;
    bool                   found;

    assert(vlan_group_index != NULL);

    found      = false;
    free_index = ACL_INVALID_DB_INDEX;
    for (ii = 0; ii < ACL_VLAN_GROUP_COUNT; ii++) {
        if (0 != acl_db_vlan_group(ii).vlan_count) {
            assert(acl_db_vlan_group(ii).bind_data.is_object_set);
            if (mlnx_acl_indexes_is_equal(acl_db_vlan_group(ii).bind_data.acl_index, acl_index)) {
                index = ii;
                found = true;
                break;
            }
        } else {
            if (ACL_INVALID_DB_INDEX == free_index) {
                free_index = ii;
            }
        }
    }

    if (false == found) {
        if (ACL_INVALID_DB_INDEX == free_index) {
            SX_LOG_ERR("Max number of vlan groups reached (%d)\n", ACL_VLAN_GROUP_COUNT);
            status = SAI_STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        } else {
            index = free_index;
        }
    }

    if (0 == acl_db_vlan_group(index).vlan_count) {
        assert(false == acl_db_vlan_group(index).bind_data.is_object_set);

        sx_status = sx_api_acl_vlan_group_map_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_swid_id, NULL, 0,
                                                  &acl_db_vlan_group(index).sx_vlan_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create sx vlan group - %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        acl_db_vlan_group(index).bind_data.target_data.is_set              = true;
        acl_db_vlan_group(index).bind_data.target_data.vlan_group          = acl_db_vlan_group(index).sx_vlan_group;
        acl_db_vlan_group(index).bind_data.target_data.sx_direction        = sx_acl_direction;
        acl_db_vlan_group(index).bind_data.target_data.sai_bind_point_type = SAI_ACL_BIND_POINT_TYPE_VLAN;

        bind_point_index.index = index;
        bind_point_index.type  = SAI_ACL_BIND_POINT_TYPE_VLAN;

        status = mlnx_acl_bind_point_sai_acl_apply(&acl_db_vlan_group(index).bind_data, acl_index, bind_point_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    sx_status = sx_api_acl_vlan_group_map_set(gh_sdk, SX_ACCESS_CMD_ADD, sx_swid_id, &sx_vlan_id, 1,
                                              &acl_db_vlan_group(index).sx_vlan_group);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to add vlan [%d] to vlan group [%d] - %s\n", sx_vlan_id,
                   acl_db_vlan_group(index).sx_vlan_group, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    acl_db_vlan_group(index).vlan_count++;
    *vlan_group_index = index;

out:
    return status;
}

static sai_status_t mlnx_acl_vlan_group_remove(_In_ sx_vlan_id_t sx_vlan_id, _In_ uint32_t vlan_group_index)
{
    sai_status_t           status = SAI_STATUS_SUCCESS;
    sx_status_t            sx_status;
    sx_acl_vlan_group_t    vlan_group;
    sx_swid_t              sx_swid_id = DEFAULT_ETH_SWID;
    acl_bind_point_data_t *bind_point_data;
    acl_bind_point_index_t bind_point_index;

    assert(vlan_group_index < ACL_VLAN_GROUP_COUNT);
    assert(acl_db_vlan_group(vlan_group_index).vlan_count > 0);

    vlan_group      = acl_db_vlan_group(vlan_group_index).sx_vlan_group;
    bind_point_data = &acl_db_vlan_group(vlan_group_index).bind_data;

    sx_status = sx_api_acl_vlan_group_map_set(gh_sdk, SX_ACCESS_CMD_DELETE, sx_swid_id, &sx_vlan_id, 1, &vlan_group);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove vlan [%d] from vlan group [%d] - %s\n", sx_vlan_id, vlan_group,
                   SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    acl_db_vlan_group(vlan_group_index).vlan_count--;

    if (0 == acl_db_vlan_group(vlan_group_index).vlan_count) {
        status = mlnx_acl_bind_point_sx_group_remove(bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }

        sx_status = sx_api_acl_vlan_group_map_set(gh_sdk, SX_ACCESS_CMD_DESTROY, sx_swid_id, NULL, 0,
                                                  &acl_db_vlan_group(vlan_group_index).sx_vlan_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to destroy sx vlan group - %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        bind_point_data->is_object_set = false;
    }

    if (mlnx_acl_index_is_group(bind_point_data->acl_index)) {
        bind_point_index.index = vlan_group_index;
        bind_point_index.type  = SAI_ACL_BIND_POINT_TYPE_VLAN;
        mlnx_acl_group_db_bind_point_remove(bind_point_data->acl_index.acl_db_index, bind_point_index);
    }

out:
    return status;
}

sai_status_t mlnx_acl_vlan_bind_point_set(_In_ sai_object_id_t            vlan_oid,
                                          _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                          _In_ acl_index_t                acl_index)
{
    sai_status_t           status = SAI_STATUS_SUCCESS;
    sx_acl_direction_t     sx_acl_direction;
    sx_vlan_id_t           sx_vlan_id;
    sai_vlan_id_t          vlan_id;
    acl_bind_point_vlan_t *bind_point;
    acl_bind_point_index_t bind_point_index;
    uint32_t               vlan_group_index = ACL_INVALID_DB_INDEX;
    bool                   unbind;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(vlan_oid, &vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_vlan_id       = vlan_id;
    bind_point       = &sai_acl_db->acl_bind_points->vlans[vlan_id];
    sx_acl_direction = mlnx_acl_bind_point_type_to_sx_direction(bind_point_type);
    unbind           = is_acl_index_invalid(acl_index);

    if (unbind) {
        if (false == bind_point->is_bound) {
            status = SAI_STATUS_SUCCESS;
            goto out;
        }

        status = mlnx_acl_vlan_group_remove(sx_vlan_id, bind_point->vlan_group_index);
        if (SAI_ERR(status)) {
            goto out;
        }

        bind_point->is_bound = false;
    } else {
        if (false == bind_point->is_bound) {
            status = mlnx_acl_vlan_group_create_or_get(sx_vlan_id, acl_index, sx_acl_direction, &vlan_group_index);
            if (SAI_ERR(status)) {
                goto out;
            }

            bind_point->vlan_group_index = vlan_group_index;
            bind_point->is_bound         = true;
        } else {
            vlan_group_index = bind_point->vlan_group_index;
            if (mlnx_acl_indexes_is_equal(acl_db_vlan_group(vlan_group_index).bind_data.acl_index, acl_index)) {
                status = SAI_STATUS_SUCCESS;
                goto out;
            }

            if (1 == acl_db_vlan_group(vlan_group_index).vlan_count) {
                bind_point_index.index = vlan_group_index;
                bind_point_index.type  = SAI_ACL_BIND_POINT_TYPE_VLAN;

                status = mlnx_acl_bind_point_sai_acl_apply(&acl_db_vlan_group(vlan_group_index).bind_data,
                                                           acl_index, bind_point_index);
                if (SAI_ERR(status)) {
                    goto out;
                }
            } else {
                status = mlnx_acl_vlan_group_remove(sx_vlan_id, bind_point->vlan_group_index);
                if (SAI_ERR(status)) {
                    goto out;
                }

                status = mlnx_acl_vlan_group_create_or_get(sx_vlan_id, acl_index, sx_acl_direction, &vlan_group_index);
                if (SAI_ERR(status)) {
                    goto out;
                }

                bind_point->vlan_group_index = vlan_group_index;
            }
        }
    }

out:
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_acl_bind_point_set(_In_ const sai_object_key_t      *key,
                                     _In_ const sai_attribute_value_t *value,
                                     void                             *arg)
{
    sai_status_t               status;
    mlnx_acl_bind_point_type_t bind_point_type;
    acl_index_t                acl_index = ACL_INDEX_INVALID;

    SX_LOG_ENTER();

    bind_point_type = (mlnx_acl_bind_point_type_t)arg;

    sai_db_read_lock();
    acl_global_lock();

    status = mlnx_acl_bind_point_attrs_check_and_fetch(value->oid, bind_point_type, 0, &acl_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_bind_point_set_impl(key->key.object_id, bind_point_type, acl_index);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_global_unlock();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_bind_point_set_impl(_In_ sai_object_id_t            target,
                                                 _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                 _In_ acl_index_t                acl_index)
{
    sai_status_t status;

    SX_LOG_ENTER();

    switch (bind_point_type) {
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE:
        status = mlnx_acl_port_lag_rif_bind_point_set(target, bind_point_type, acl_index);
        break;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN:
        status = mlnx_acl_vlan_bind_point_set(target, bind_point_type, acl_index);
        break;

    default:
        SX_LOG_ERR("Invalid type of bind point - %d\n", bind_point_type);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_acl_bind_point_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    sai_status_t               status;
    sai_object_id_t            target;
    mlnx_acl_bind_point_type_t bind_point_type;
    acl_bind_point_data_t     *bind_point_data = NULL;
    bool                       is_vlan_bound;
    sx_port_log_id_t           port_id;

    SX_LOG_ENTER();

    sai_db_read_lock();
    acl_global_lock();

    bind_point_type = (mlnx_acl_bind_point_type_t)arg;
    target          = key->key.object_id;

    switch (bind_point_type) {
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_PORT, &port_id, NULL))) {
            goto out;
        }

        if (mlnx_log_port_is_cpu(port_id)) {
            value->oid = SAI_NULL_OBJECT_ID;
            goto out;
        }

        status = mlnx_acl_port_lag_bind_point_check_and_get(target, bind_point_type, &bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG:
    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE:
        status = mlnx_acl_bind_point_port_lag_rif_data_get(target, bind_point_type, &bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    case MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN:
    case MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN:
        status = mlnx_acl_bind_point_vlan_is_bound(target, bind_point_type, &is_vlan_bound);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (is_vlan_bound) {
            status = mlnx_acl_bind_point_vlan_data_get(target, bind_point_type, &bind_point_data);
            if (SAI_ERR(status)) {
                goto out;
            }
        } else {
            status     = SAI_STATUS_SUCCESS;
            value->oid = SAI_NULL_OBJECT_ID;
            goto out;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported type of bind point - %d\n", bind_point_type);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    assert(bind_point_data);

    if (bind_point_data->is_object_set) {
        status = mlnx_acl_index_to_sai_object(bind_point_data->acl_index, &value->oid);
    } else {
        status     = SAI_STATUS_SUCCESS;
        value->oid = SAI_NULL_OBJECT_ID;
    }

out:
    acl_global_unlock();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_wrapping_group_create(_In_ uint32_t table_index)
{
    sx_status_t        sx_status;
    sx_acl_direction_t sx_acl_direction;
    sx_acl_id_t        sx_group_id;

    assert(acl_db_table(table_index).wrapping_group.created == false);

    sx_acl_direction = acl_sai_stage_to_sx_dir(acl_db_table(table_index).stage);

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_acl_direction, NULL, 0, &sx_group_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create sx wrapping group - %s", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl_db_table(table_index).wrapping_group.created     = true;
    acl_db_table(table_index).wrapping_group.sx_group_id = sx_group_id;

    SX_LOG_NTC("Created wrapping group sx_id[%u] for table[%u]\n", sx_group_id, table_index);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_wrapping_group_delete(_In_ uint32_t table_index)
{
    sx_status_t        sx_status;
    sx_acl_direction_t sx_acl_direction;
    sx_acl_id_t        sx_group_id;

    SX_LOG_NTC("Removing wrapping group sx_id[%u] for table[%u]\n", acl_db_table(
                   table_index).wrapping_group.sx_group_id,
               table_index);

    assert(acl_db_table(table_index).wrapping_group.created);

    sx_group_id      = acl_db_table(table_index).wrapping_group.sx_group_id;
    sx_acl_direction = acl_sai_stage_to_sx_dir(acl_db_table(table_index).stage);

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, sx_acl_direction, NULL, 0, &sx_group_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to remove sx wrapping group - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl_db_table(table_index).wrapping_group.created = false;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_set_def_rule(_In_ uint32_t src_table_index, _In_ uint32_t dst_table_index)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sx_status_t             sx_status;
    sx_acl_key_type_t       key_type;
    sx_acl_key_t            key;
    sx_flex_acl_flex_rule_t default_rule;
    sx_acl_rule_offset_t    rule_offset;
    sx_acl_region_id_t      region_id;
    sx_acl_id_t             sx_target_group_id;
    bool                    invalidate = false;

    assert(src_table_index != ACL_INVALID_DB_INDEX);

    if (ACL_INVALID_DB_INDEX == dst_table_index) {
        invalidate = true;
    }

    key_type    = acl_db_table(src_table_index).key_type;
    key         = acl_db_table(src_table_index).def_rule_key;
    rule_offset = acl_db_table(src_table_index).def_rules_offset;
    region_id   = acl_db_table(src_table_index).region_id;

    sx_status = sx_lib_flex_acl_rule_init(key_type, 1, &default_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to init default rule - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (invalidate) {
        default_rule.valid                     = false;
        default_rule.key_desc_count            = 1;
        default_rule.key_desc_list_p[0].key_id = key;
    } else {
        assert(acl_db_table(dst_table_index).wrapping_group.created);
        sx_target_group_id = acl_db_table(dst_table_index).wrapping_group.sx_group_id;

        default_rule.valid                     = true;
        default_rule.key_desc_count            = 1;
        default_rule.key_desc_list_p[0].key_id = key;
        memset(&default_rule.key_desc_list_p[0].key, 0, sizeof(default_rule.key_desc_list_p[0].key));
        memset(&default_rule.key_desc_list_p[0].mask, 0, sizeof(default_rule.key_desc_list_p[0].mask));

        default_rule.action_count                                        = 1;
        default_rule.action_list_p[0].type                               = SX_FLEX_ACL_ACTION_GOTO;
        default_rule.action_list_p[0].fields.action_goto.goto_action_cmd = SX_ACL_ACTION_GOTO_JUMP;
        default_rule.action_list_p[0].fields.action_goto.acl_group_id    = sx_target_group_id;
    }

    sx_status = sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, &rule_offset, &default_rule, 1);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    sx_status = sx_lib_flex_acl_rule_deinit(&default_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
    }

    return status;
}

static sai_status_t mlnx_acl_bind_point_index_to_data(_In_ acl_bind_point_index_t   index,
                                                      _In_ sai_acl_stage_t          stage,
                                                      _Out_ acl_bind_point_data_t **data)
{
    assert(data != NULL);

    switch (index.type) {
    case SAI_ACL_BIND_POINT_TYPE_LAG:
    case SAI_ACL_BIND_POINT_TYPE_PORT:
        assert(index.index < MAX_PORTS * 2);
        if (SAI_ACL_STAGE_INGRESS == stage) {
            *data = &sai_acl_db->acl_bind_points->ports_lags[index.index].ingress_data;
        } else {
            *data = &sai_acl_db->acl_bind_points->ports_lags[index.index].egress_data;
        }
        break;

    case SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF:
        assert(index.index < ACL_RIF_COUNT);
        if (SAI_ACL_STAGE_INGRESS == stage) {
            *data = &sai_acl_db->acl_bind_points->rifs[index.index].ingress_data;
        } else {
            *data = &sai_acl_db->acl_bind_points->rifs[index.index].egress_data;
        }
        break;

    case SAI_ACL_BIND_POINT_TYPE_VLAN:
        *data = &sai_acl_db->acl_vlan_groups_db[index.index].bind_data;
        break;

    default:
        SX_LOG_ERR("Unexpected type of bind point - %d\n", index.type);
        assert(false);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_group_bind_points_update(_In_ uint32_t group_index)
{
    sai_status_t                status = SAI_STATUS_SUCCESS;
    const acl_group_bound_to_t *group_bound_to;
    acl_bind_point_data_t      *bind_point_data;
    sai_acl_stage_t             stage;
    uint32_t                    index_count, ii;

    group_bound_to = sai_acl_db_group_bount_to(group_index);
    index_count    = group_bound_to->count;
    stage          = sai_acl_db_group_ptr(group_index)->stage;

    for (ii = 0; ii < index_count; ii++) {
        /* LAG members is not bound in SDK, so skip it */
        if (mlnx_acl_is_bind_point_lag_member(group_bound_to->indexes[ii])) {
            continue;
        }

        status = mlnx_acl_bind_point_index_to_data(group_bound_to->indexes[ii], stage, &bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_acl_bind_point_group_sx_set(bind_point_data, group_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    return status;
}


static bool mlnx_acl_table_bind_point_list_fits_group(_In_ uint32_t group_index, _In_ uint32_t table_index)
{
    sai_acl_bind_point_type_t *table_bind_point_types, *group_bind_point_types;
    uint32_t                   table_bind_point_type_count, group_bind_point_type_count, ii, jj;

    group_bind_point_type_count = sai_acl_db_group_ptr(group_index)->bind_point_types.count;
    group_bind_point_types      = sai_acl_db_group_ptr(group_index)->bind_point_types.types;
    table_bind_point_type_count = acl_db_table(table_index).bind_point_types.count;
    table_bind_point_types      = acl_db_table(table_index).bind_point_types.types;

    for (ii = 0; ii < table_bind_point_type_count; ii++) {
        for (jj = 0; jj < group_bind_point_type_count; jj++) {
            if (table_bind_point_types[ii] == group_bind_point_types[jj]) {
                break;
            }
        }

        if (jj == group_bind_point_type_count) {
            SX_LOG_ERR("Table's bind point type (%d) is not supported for group (%d)\n",
                       table_bind_point_types[ii], group_index);
            return false;
        }
    }

    return true;
}

static sai_status_t mlnx_acl_group_add_table(_In_ uint32_t group_index,
                                             _In_ uint32_t table_index,
                                             _In_ uint32_t table_priority)
{
    sai_status_t               status;
    sai_acl_table_group_type_t group_type;
    acl_group_member_t        *group_members;
    uint32_t                   group_members_count, ii, jj;
    uint32_t                   next_table_index, prev_table_index;

    assert(acl_group_index_check_range(group_index));
    assert(acl_table_index_check_range(table_index));

    group_type          = sai_acl_db_group_ptr(group_index)->search_type;
    group_members       = sai_acl_db_group_ptr(group_index)->members;
    group_members_count = sai_acl_db_group_ptr(group_index)->members_count;

    assert(ACL_INVALID_DB_INDEX == acl_db_table(table_index).group_index);

    if (SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL == group_type) {
        if (group_members_count > 0) {
            for (ii = 0; ii < group_members_count; ii++) {
                if (table_priority > group_members[ii].table_prio) {
                    break;
                }
            }

            for (jj = group_members_count; jj > ii; jj--) {
                group_members[jj] = group_members[jj - 1];
            }

            group_members[ii].table_index = table_index;
            group_members[ii].table_prio  = table_priority;
            sai_acl_db_group_ptr(group_index)->members_count++;

            next_table_index = prev_table_index = ACL_INVALID_DB_INDEX;

            if (0 == ii) {
                status = mlnx_acl_wrapping_group_create(group_members[1].table_index);
                if (SAI_ERR(status)) {
                    goto out;
                }
            } else {
                status = mlnx_acl_wrapping_group_create(table_index);
                if (SAI_ERR(status)) {
                    goto out;
                }

                prev_table_index = group_members[ii - 1].table_index;
            }

            if (ii != group_members_count) {
                next_table_index = group_members[ii + 1].table_index;
            }

            if (ACL_INVALID_DB_INDEX != next_table_index) {
                status = mlnx_acl_table_set_def_rule(table_index, next_table_index);
                if (SAI_ERR(status)) {
                    goto out;
                }
            }

            if (ACL_INVALID_DB_INDEX != prev_table_index) {
                status = mlnx_acl_table_set_def_rule(prev_table_index, table_index);
                if (SAI_ERR(status)) {
                    goto out;
                }
            }
        } else {
            group_members[0].table_index                     = table_index;
            group_members[0].table_prio                      = table_priority;
            sai_acl_db_group_ptr(group_index)->members_count = 1;
        }
    } else {
        group_members[group_members_count].table_index = table_index;
        sai_acl_db_group_ptr(group_index)->members_count++;
    }

    status = mlnx_acl_group_bind_points_update(group_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_db_table(table_index).group_index = group_index;

out:
    return status;
}

static sai_status_t mlnx_acl_group_del_table(_In_ uint32_t group_index, _In_ uint32_t table_index)
{
    sai_status_t               status = SAI_STATUS_SUCCESS;
    sai_acl_table_group_type_t group_type;
    acl_group_member_t        *group_members;
    uint32_t                   group_member_count, ii;
    uint32_t                   prev_table_index, next_table_index, new_head_table_index;

    group_member_count = sai_acl_db_group_ptr(group_index)->members_count;
    group_members      = sai_acl_db_group_ptr(group_index)->members;

    assert(group_member_count > 0);

    for (ii = 0; ii < group_member_count; ii++) {
        if (group_members[ii].table_index == table_index) {
            break;
        }
    }

    if (ii == group_member_count) {
        SX_LOG_ERR("Table [%d] is not a member of group [%d]\n", table_index, group_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    group_type = sai_acl_db_group_ptr(group_index)->search_type;

    if (SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL == group_type) {
        if (ii != 0) {
            prev_table_index = group_members[ii - 1].table_index;
            if (ii == group_member_count - 1) {
                next_table_index = ACL_INVALID_DB_INDEX;
            } else {
                next_table_index = group_members[ii + 1].table_index;
            }

            for (; ii < group_member_count - 1; ii++) {
                group_members[ii] = group_members[ii + 1];
            }

            sai_acl_db_group_ptr(group_index)->members_count--;

            status = mlnx_acl_table_set_def_rule(prev_table_index, next_table_index);
            if (SAI_ERR(status)) {
                goto out;
            }

            status = mlnx_acl_wrapping_group_delete(table_index);
            if (SAI_ERR(status)) {
                goto out;
            }

            status = mlnx_acl_table_set_def_rule(table_index, ACL_INVALID_DB_INDEX);
            if (SAI_ERR(status)) {
                goto out;
            }
        } else { /* Removing a table with the highest prio */
            for (ii = 0; ii < group_member_count - 1; ii++) {
                group_members[ii] = group_members[ii + 1];
            }

            sai_acl_db_group_ptr(group_index)->members_count--;

            status = mlnx_acl_group_bind_points_update(group_index);
            if (SAI_ERR(status)) {
                goto out;
            }

            status = mlnx_acl_table_set_def_rule(table_index, ACL_INVALID_DB_INDEX);
            if (SAI_ERR(status)) {
                goto out;
            }

            if (sai_acl_db_group_ptr(group_index)->members_count > 0) {
                /* Head table doesn't need a wrapping group,
                 *  because it's acl is inserted into bind point's sx group */
                new_head_table_index = group_members[0].table_index;
                status               = mlnx_acl_wrapping_group_delete(new_head_table_index);
                if (SAI_ERR(status)) {
                    goto out;
                }
            }
        }
    } else {
        group_members[ii] = group_members[group_member_count - 1];
        sai_acl_db_group_ptr(group_index)->members_count--;

        status = mlnx_acl_group_bind_points_update(group_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    acl_db_table(table_index).group_index = ACL_INVALID_DB_INDEX;

out:
    return status;
}

static sai_status_t mlnx_acl_group_member_oid_create(_Out_ sai_object_id_t *group_member_oid,
                                                     _In_ uint32_t          table_index,
                                                     _In_ uint32_t          group_index,
                                                     _In_ uint32_t          table_priority)
{
    uint32_t oid_data;
    uint8_t  oid_extra_data[EXTENDED_DATA_SIZE] = {0};

    oid_data          = table_index & 0xFFFF;
    oid_data         |= (group_index & 0xFFFF) << 16;
    oid_extra_data[0] = table_priority & 0xFF;
    oid_extra_data[1] = (table_priority & 0xFF00) >> 8;

    return mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, oid_data,
                              oid_extra_data, group_member_oid);
}

static sai_status_t mlnx_acl_group_member_data_fetch(_In_ sai_object_id_t group_member_oid,
                                                     _Out_ uint32_t      *table_index,
                                                     _Out_ uint32_t      *group_index,
                                                     _Out_ uint32_t      *table_priority)
{
    sai_status_t status;
    uint32_t     oid_data;
    uint8_t      oid_extra_data[EXTENDED_DATA_SIZE] = {0};

    assert((table_index != NULL) && (group_index != NULL));

    status = mlnx_object_to_type(group_member_oid, SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, &oid_data, oid_extra_data);
    if (SAI_ERR(status)) {
        return status;
    }

    *table_index = oid_data & 0xFFFF;
    *group_index = oid_data >> 16;

    if (table_priority) {
        *table_priority  = oid_extra_data[0];
        *table_priority |= oid_extra_data[1] << 8;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_group_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t               status;
    sai_acl_bind_point_type_t *bind_point_types;
    uint32_t                   group_index, bind_point_type_count, ii;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &group_index, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE:
        value->s32 = sai_acl_db_group_ptr(group_index)->stage;
        break;

    case SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST:
        bind_point_type_count = sai_acl_db_group_ptr(group_index)->bind_point_types.count;
        bind_point_types      = sai_acl_db_group_ptr(group_index)->bind_point_types.types;

        if (value->s32list.count < bind_point_type_count) {
            SX_LOG_ERR(" Re-allocate list size as list size is not large enough \n");
            value->s32list.count = bind_point_type_count;
            status               = SAI_STATUS_BUFFER_OVERFLOW;
            goto out;
        } else {
            for (ii = 0; ii < bind_point_type_count; ii++) {
                value->s32list.list[ii] = bind_point_types[ii];
            }

            value->s32list.count = bind_point_type_count;
        }
        break;

    case SAI_ACL_TABLE_GROUP_ATTR_TYPE:
        value->s32 = sai_acl_db_group_ptr(group_index)->search_type;
        break;

    default:
        SX_LOG_ERR("Unexpected type of arg (%ld)\n", (int64_t)arg);
        assert(false);
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_group_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     table_index, group_index, table_priority;

    SX_LOG_ENTER();

    status = mlnx_acl_group_member_data_fetch(key->key.object_id, &table_index, &group_index, &table_priority);
    if (SAI_ERR(status)) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID:
        status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, group_index, NULL, &value->oid);
        assert(SAI_STATUS_SUCCESS == status);
        break;

    case SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID:
        status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, table_index, NULL, &value->oid);
        assert(SAI_STATUS_SUCCESS == status);
        break;

    case SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY:
        value->u32 = table_priority;
        break;

    default:
        SX_LOG_ERR("Unexpected type of arg (%ld)\n", (int64_t)arg);
        assert(false);
    }

out:
    SX_LOG_EXIT();
    return status;
}

static bool mlnx_acl_range_type_list_is_unique(_In_ const sai_acl_range_type_t *range_types,
                                               _In_ uint32_t                    range_type_count)
{
    bool     range_type_present[SAI_ACL_RANGE_TYPE_COUNT] = {false};
    uint32_t ii;

    assert(NULL != range_types);

    for (ii = 0; ii < range_type_count; ii++) {
        if (range_type_present[range_types[ii]]) {
            SX_LOG_NTC("ACL Range type (%d) at index[%d] appears twice in range list\n", range_types[ii], ii);
            return false;
        }

        range_type_present[range_types[ii]] = true;
    }

    return true;
}

static sai_status_t mlnx_acl_range_validate_and_fetch(_In_ const sai_object_list_t   *range_list,
                                                      _Out_ sx_flex_acl_port_range_t *sx_acl_range,
                                                      _In_ uint32_t                   table_index)
{
    sai_status_t                status;
    sai_attribute_value_t       range_type_value;
    sai_acl_range_type_t        range_list_types[SAI_ACL_RANGE_TYPE_COUNT] = {0};
    sai_acl_range_type_t        range_type;
    const sai_acl_range_type_t *table_range_types;
    sx_acl_port_range_id_t      sx_port_range_id;
    uint32_t                    ii, jj, object_data, table_range_count;
    bool                        is_range_type_present, is_range_types_unique;

    if (range_list->count > ACL_RANGE_MAX_COUNT) {
        SX_LOG_ERR("Max number of ACL ranges for ACL Entry is [%d], passed [%d]\n",
                   ACL_RANGE_MAX_COUNT, range_list->count);
        return SAI_STATUS_FAILURE;
    }

    table_range_types = acl_db_table(table_index).range_types;
    table_range_count = acl_db_table(table_index).range_type_count;

    memset(sx_acl_range, 0, sizeof(*sx_acl_range));

    for (ii = 0; ii < range_list->count; ii++) {
        status = mlnx_acl_range_attr_get_by_oid(range_list->list[ii], SAI_ACL_RANGE_ATTR_TYPE, &range_type_value);
        if (SAI_ERR(status)) {
            return status;
        }

        range_type           = range_type_value.s32;
        range_list_types[ii] = range_type;

        assert(range_type <= SAI_ACL_RANGE_TYPE_PACKET_LENGTH);

        is_range_type_present = false;
        for (jj = 0; jj < table_range_count; jj++) {
            if (table_range_types[jj] == range_type) {
                is_range_type_present = true;
                break;
            }
        }

        if (false == is_range_type_present) {
            SX_LOG_NTC("ACL Range type (%d) at index[%d] is not enabled for this ACL Table\n", range_type, ii);
            return SAI_STATUS_FAILURE;
        }

        status = mlnx_object_to_type(range_list->list[ii], SAI_OBJECT_TYPE_ACL_RANGE, &object_data, NULL);
        if (SAI_ERR(status)) {
            return status;
        }

        sx_port_range_id                  = (sx_acl_port_range_id_t)object_data;
        sx_acl_range->port_range_list[ii] = sx_port_range_id;
    }

    is_range_types_unique = mlnx_acl_range_type_list_is_unique(range_list_types, range_list->count);
    if (false == is_range_types_unique) {
        return SAI_STATUS_FAILURE;
    }

    sx_acl_range->port_range_cnt = range_list->count;
    return SAI_STATUS_SUCCESS;
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
                                          _In_ sai_object_id_t        switch_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    sx_acl_port_range_id_t       sx_port_range_id;
    sx_acl_port_range_entry_t    sx_port_range_entry;
    const sai_attribute_value_t *range_type, *range_limit;
    uint32_t                     range_type_index, range_limit_index;
    uint32_t                     range_min, range_max;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == acl_range_id) {
        SX_LOG_ERR("NULL object id value\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list, acl_range_attribs,
                                    acl_range_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, acl_range_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Range, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_RANGE_ATTR_TYPE, &range_type, &range_type_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_RANGE_ATTR_LIMIT, &range_limit, &range_limit_index);
    assert(SAI_STATUS_SUCCESS == status);

    memset(&sx_port_range_entry, 0, sizeof(sx_port_range_entry));
    sx_port_range_entry.port_range_ip_length = false;
    sx_port_range_entry.port_range_ip_header = SX_ACL_PORT_RANGE_IP_HEADER_BOTH;

    switch (range_type->s32) {
    case SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE:
        sx_port_range_entry.port_range_direction = SX_ACL_PORT_DIRECTION_SOURCE;
        break;

    case SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE:
        sx_port_range_entry.port_range_direction = SX_ACL_PORT_DIRECTION_DESTINATION;
        break;

    /*
     *  case SAI_ACL_RANGE_TYPE_OUTER_VLAN:
     *   break;
     *
     *  case SAI_ACL_RANGE_TYPE_INNER_VLAN:
     *   break;
     */
    case SAI_ACL_RANGE_TYPE_PACKET_LENGTH:
        sx_port_range_entry.port_range_ip_length = true;
        break;

    default:
        SX_LOG_ERR("Range type is not supported\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    range_min = range_limit->u32range.min;
    range_max = range_limit->u32range.max;

    if (range_min > range_max) {
        SX_LOG_ERR("Invalid range value - min[%d] > max[%d]\n", range_min, range_max);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + range_limit_index;
        goto out;
    }

    sx_port_range_entry.port_range_min = range_min;
    sx_port_range_entry.port_range_max = range_max;

    sx_status = sx_api_acl_l4_port_range_set(gh_sdk, SX_ACCESS_CMD_ADD, &sx_port_range_entry, &sx_port_range_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create range %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    /* make sure that sx_port_range_id won't get truncated */
    assert(sizeof(sx_port_range_id) <= sizeof(uint32_t));

    status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_RANGE, sx_port_range_id, NULL, acl_range_id);
    assert(SAI_STATUS_SUCCESS == status);

    acl_range_key_to_str(*acl_range_id, key_str);
    SX_LOG_NTC("Created acl range %s\n", key_str);

out:
    SX_LOG_EXIT();
    return status;
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
    sai_status_t              status;
    sx_status_t               sx_status;
    uint32_t                  object_range_id;
    sx_acl_port_range_id_t    sx_port_range_id;
    sx_acl_port_range_entry_t sx_port_range_entry;
    char                      key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_range_key_to_str(acl_range_id, key_str);
    SX_LOG_NTC("Delete ACL Range %s\n", key_str);

    status = mlnx_object_to_type(acl_range_id, SAI_OBJECT_TYPE_ACL_RANGE, &object_range_id, NULL);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    sx_port_range_id = object_range_id;

    memset(&sx_port_range_entry, 0, sizeof(sx_port_range_entry));

    sx_status = sx_api_acl_l4_port_range_set(gh_sdk, SX_ACCESS_CMD_DELETE, &sx_port_range_entry, &sx_port_range_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to delete range %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
    }

out:
    SX_LOG_EXIT();
    return status;
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
    const sai_object_key_t key = { .key.object_id = acl_range_id };
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
    const sai_object_key_t key = { .key.object_id = acl_range_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_range_key_to_str(acl_range_id, key_str);
    return sai_get_attributes(&key, key_str, acl_range_attribs, acl_range_vendor_attribs, attr_count, attr_list);
}


/**
 * @brief Create an ACL Table Group
 *
 * @param[out] acl_table_group_id The ACL group id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_acl_table_group(_Out_ sai_object_id_t      *acl_table_group_id,
                                                _In_ sai_object_id_t        switch_id,
                                                _In_ uint32_t               attr_count,
                                                _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *group_attr_type, *group_attr_bind_point_list;
    const sai_attribute_value_t *group_attr_stage;
    sai_acl_table_group_type_t   group_type;
    sai_acl_stage_t              group_stage;
    acl_group_bound_to_t        *group_bound_to;
    acl_bind_point_type_list_t   group_bind_point_types;
    uint32_t                     group_index = 0, attr_index;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];

    SX_LOG_ENTER();

    acl_global_lock();

    if (NULL == acl_table_group_id) {
        SX_LOG_ERR("NULL object id value\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list, acl_group_attribs,
                                    acl_group_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, acl_group_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Group, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_GROUP_ATTR_TYPE, &group_attr_type, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    group_type = group_attr_type->s32;
    if (group_type > SAI_ACL_TABLE_GROUP_TYPE_PARALLEL) {
        SX_LOG_ERR("Invalid attribute value (%d) for SAI_ACL_TABLE_GROUP_ATTR_TYPE\n", group_type);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE,
                                 &group_attr_stage,
                                 &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    group_stage = group_attr_stage->s32;
    if (group_stage > SAI_ACL_STAGE_EGRESS) {
        SX_LOG_ERR("Invalid attribute value (%d) for SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE\n", group_stage);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST,
                                 &group_attr_bind_point_list, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_acl_bind_point_type_list_validate_and_fetch(&group_attr_bind_point_list->s32list,
                                                                  attr_index,
                                                                  &group_bind_point_types);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        group_bind_point_types = default_bind_point_type_list;
    }

    status = acl_db_find_group_free_index(&group_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    sai_acl_db_group_ptr(group_index)->members_count    = 0;
    sai_acl_db_group_ptr(group_index)->search_type      = group_type;
    sai_acl_db_group_ptr(group_index)->stage            = group_stage;
    sai_acl_db_group_ptr(group_index)->bind_point_types = group_bind_point_types;

    group_bound_to        = sai_acl_db_group_bount_to(group_index);
    group_bound_to->count = 0;

    status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, group_index, NULL, acl_table_group_id);
    assert(SAI_STATUS_SUCCESS == status);

    acl_group_key_to_str(*acl_table_group_id, key_str);
    SX_LOG_NTC("Created acl group %s\n", key_str);

out:
    acl_global_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Delete an ACL Group
 *
 * @param[in] acl_table_group_id The ACL group id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_acl_table_group(_In_ sai_object_id_t acl_table_group_id)
{
    sai_status_t status;
    uint32_t     group_index;
    char         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_global_lock();

    acl_group_key_to_str(acl_table_group_id, key_str);
    SX_LOG_NTC("Delete ACL Group %s\n", key_str);

    status = mlnx_object_to_type(acl_table_group_id, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &group_index, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (sai_acl_db_group_bount_to(group_index)->count > 0) {
        SX_LOG_ERR("Group [%lx] is bound\n", acl_table_group_id);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    sai_acl_db_group_ptr(group_index)->is_used = false;

out:
    acl_global_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set ACL table group attribute
 *
 * @param[in] acl_table_group_id The ACL table group id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_acl_table_group_attribute(_In_ sai_object_id_t        acl_table_group_id,
                                                       _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = acl_table_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_group_key_to_str(acl_table_group_id, key_str);
    return sai_set_attribute(&key, key_str, acl_group_attribs, acl_group_vendor_attribs, attr);
}

/**
 * @brief Get ACL table group attribute
 *
 * @param[in] acl_table_group_id ACL table group id
 * @param[in] attr_count Number of attributes
 * @param[out] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_acl_table_group_attribute(_In_ sai_object_id_t   acl_table_group_id,
                                                       _In_ uint32_t          attr_count,
                                                       _Out_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_table_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_group_key_to_str(acl_table_group_id, key_str);
    return sai_get_attributes(&key, key_str, acl_group_attribs, acl_group_vendor_attribs, attr_count, attr_list);
}

/**
 * @brief Create an ACL Table Group Member
 *
 * @param[out] acl_table_group_member_id The ACL table group member id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_acl_table_group_member(_Out_ sai_object_id_t      *acl_table_group_member_id,
                                                       _In_ sai_object_id_t        switch_id,
                                                       _In_ uint32_t               attr_count,
                                                       _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status = SAI_STATUS_SUCCESS;
    const sai_attribute_value_t *group_id, *table_id, *priority;
    sai_acl_table_group_type_t   group_type;
    sai_acl_stage_t              table_stage, group_stage;
    uint32_t                     attr_index, group_index, table_index, group_capacity;
    uint32_t                     table_priority = 0;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == acl_table_group_member_id) {
        SX_LOG_ERR("NULL object id value\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list, acl_group_member_attribs,
                                    acl_group_member_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, acl_group_member_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Group member, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID,
                                 &group_id, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_object_to_type(group_id->oid, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &group_index, NULL);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    if (false == acl_group_index_check_range(group_index)) {
        SX_LOG_ERR("Invalid acl group object id (%lx)\n", group_id->oid);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID,
                                 &table_id, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_object_to_type(table_id->oid, SAI_OBJECT_TYPE_ACL_TABLE, &table_index, NULL);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    acl_table_write_lock(table_index);
    acl_global_lock();

    if (ACL_INVALID_DB_INDEX != acl_db_table(table_index).group_index) {
        SX_LOG_ERR("Table [%d] is a member of group [%d]\n", table_index, group_index);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out_unlock;
    }

    if (false == acl_table_index_check_range(table_index)) {
        SX_LOG_ERR("Invalid acl group object id (%lx)\n", table_id->oid);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out_unlock;
    }

    group_type = sai_acl_db_group_ptr(group_index)->search_type;

    if (SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL == group_type) {
        status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY,
                                     &priority, &attr_index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing mandatory attribute PRIORITY (group [%lx] type is sequential)\n", group_id->oid);
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out_unlock;
        }

        table_priority = priority->u32;

        if (ACL_GROUP_MEMBER_PRIO_MAX < table_priority) {
            SX_LOG_ERR("Group member priority (%d) is out of range [%d:%d]\n", table_priority,
                       ACL_GROUP_MEMBER_PRIO_MIN, ACL_GROUP_MEMBER_PRIO_MAX);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
            goto out_unlock;
        }
    }

    group_capacity = mlnx_acl_group_capacity_get(group_index);

    if (sai_acl_db_group_ptr(group_index)->members_count + 1 > group_capacity) {
        SX_LOG_ERR("Group [%lx] has a max number of members - (%d)\n", group_id->oid, group_capacity);
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out_unlock;
    }

    table_stage = acl_db_table(table_index).stage;
    group_stage = sai_acl_db_group_ptr(group_index)->stage;

    if (table_stage != group_stage) {
        SX_LOG_ERR("ACL Group stage (%d) is not equal to ACl Table stage (%d)\n", group_stage, table_stage);
        status = SAI_STATUS_FAILURE;
        goto out_unlock;
    }

    if (false == mlnx_acl_table_bind_point_list_fits_group(group_index, table_index)) {
        status = SAI_STATUS_FAILURE;
        goto out_unlock;
    }

    status = mlnx_acl_group_add_table(group_index, table_index, table_priority);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    status = mlnx_acl_group_member_oid_create(acl_table_group_member_id, table_index, group_index, table_priority);
    assert(SAI_STATUS_SUCCESS == status);

    acl_group_member_key_to_str(*acl_table_group_member_id, key_str);
    SX_LOG_NTC("Created acl group member %s\n", key_str);

out_unlock:
    acl_global_unlock();
    acl_table_unlock(table_index);
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Delete an ACL Group Member
 *
 * @param[in] acl_table_group_member_id The ACL table group member id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_acl_table_group_member(_In_ sai_object_id_t acl_table_group_member_id)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     table_index, group_index;
    char         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_group_member_key_to_str(acl_table_group_member_id, key_str);
    SX_LOG_NTC("Delete ACL Group Member %s\n", key_str);

    status = mlnx_acl_group_member_data_fetch(acl_table_group_member_id, &table_index, &group_index, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_table_write_lock(table_index);
    acl_global_lock();

    if (group_index != acl_db_table(table_index).group_index) {
        SX_LOG_ERR("Table [%d] is not a member of group [%d]\n", table_index, group_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out_unlock;
    }

    status = mlnx_acl_group_del_table(group_index, table_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    acl_db_table(table_index).group_index = ACL_INVALID_DB_INDEX;

out_unlock:
    acl_global_unlock();
    acl_table_unlock(table_index);
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set ACL table group member attribute
 *
 * @param[in] acl_table_group_member_id The ACL table group member id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_acl_table_group_member_attribute(_In_ sai_object_id_t        acl_table_group_member_id,
                                                              _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = acl_table_group_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_group_member_key_to_str(acl_table_group_member_id, key_str);
    return sai_set_attribute(&key, key_str, acl_group_member_attribs, acl_group_member_vendor_attribs, attr);
}

/**
 * @brief Get ACL table group member attribute
 *
 * @param[in] acl_table_group_id ACL table group member id
 * @param[in] attr_count Number of attributes
 * @param[out] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_acl_table_group_member_attribute(_In_ sai_object_id_t   acl_table_group_member_id,
                                                              _In_ uint32_t          attr_count,
                                                              _Out_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_table_group_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_group_member_key_to_str(acl_table_group_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              acl_group_member_attribs,
                              acl_group_member_vendor_attribs,
                              attr_count,
                              attr_list);
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
    mlnx_get_acl_range_attribute,
    mlnx_create_acl_table_group,
    mlnx_remove_acl_table_group,
    mlnx_set_acl_table_group_attribute,
    mlnx_get_acl_table_group_attribute,
    mlnx_create_acl_table_group_member,
    mlnx_remove_acl_table_group_member,
    mlnx_set_acl_table_group_member_attribute,
    mlnx_get_acl_table_group_member_attribute
};
