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
#include <sx/sdk/sx_api_rm.h>
#include "meta/saimetadata.h"

#undef  __MODULE__
#define __MODULE__ SAI_ACL

/* Priority.
 * 0 is not allowed on sp2 since it makes region work in legacy mode
 * 1 is reserved for default goto rule
 * SAI range is [0, 16k/200k - 2]
 * SDK range is [2, UINT32_MAX]
 */
#define ACL_SX_RULE_PRIO_MAX_SPC   (16000)
#define ACL_SX_RULE_PRIO_MAX_SPC2  (FLEX_ACL_RULE_PRIORITY_MAX)
#define ACL_SX_RULE_PRIO_MAX       (mlnx_chip_is_spc2or3() ? ACL_SX_RULE_PRIO_MAX_SPC2 : ACL_SX_RULE_PRIO_MAX_SPC)
#define ACL_SX_RULE_PRIO_GOTO_RULE (FLEX_ACL_RULE_PRIORITY_MIN)
#define ACL_SX_RULE_PRIO_MIN       (FLEX_ACL_RULE_PRIORITY_MIN + 1)

#define ACL_SAI_ENTRY_PRIO_TO_SX(prio) (prio + 2)
#define ACL_SX_RULE_PRIO_TO_SAI(prio)  (prio - 2)

#define ACL_SAI_ENTRY_MAX_PRIO ACL_SX_RULE_PRIO_TO_SAI(ACL_SX_RULE_PRIO_MAX)
#define ACL_SAI_ENTRY_MIN_PRIO ACL_SX_RULE_PRIO_TO_SAI(ACL_SX_RULE_PRIO_MIN)
#define ACL_SAI_ENTRY_DEF_PRIO ACL_SAI_ENTRY_MIN_PRIO
#define ACL_SAI_ENTRY_PRIO_CHECK_RANGE(prio) ((prio <= (uint32_t)ACL_SAI_ENTRY_MAX_PRIO))

#define ACL_PSORT_TABLE_MIN_PRIO ACL_SX_RULE_PRIO_GOTO_RULE
#define ACL_PSORT_TABLE_MAX_PRIO ACL_SX_RULE_PRIO_MAX

#define SX_FLEX_ACL_MAX_FIELDS_IN_KEY RM_API_ACL_MAX_FIELDS_IN_KEY
#define ACL_MAX_NUM_OF_ACTIONS        20
#define ACL_TABLE_SIZE_INC_PERCENT    0.2
#define ACL_TABLE_SIZE_MIN_DELTA      16

/* Region contains 'default' rule */
#define ACL_SX_REG_SIZE_TO_TABLE_SIZE(size) ((size) - 1)
#define ACL_TABLE_SIZE_TO_SX_REG_SIZE(size) ((size) + 1)
#define ACL_DEFAULT_TABLE_SIZE 14

#define PSORT_ALMOST_FULL_PERC_STATIC  100
#define PSORT_ALMOST_EMPTY_PERC_STATIC 0
#define PSORT_ALMOST_FULL_PERC_DYN     90
#define PSORT_ALMOST_EMPTY_PERC_DYN    33

#define ACL_QUEUE_INVALID_HANDLE   ((mqd_t)-1)
#define ACL_QUEUE_NAME             "/sai_acl_queue"
#define ACL_QUEUE_TIMEOUT          2
#define ACL_QUEUE_SIZE             3
#define ACL_QUEUE_MSG_SIZE         sizeof(uint32_t)
#define ACL_QUEUE_DEF_MSG_PRIO     0
#define ACL_QUEUE_UNBLOCK_MSG_PRIO 31
#define ACL_PSORT_OPT_MAX_TIME_MS  2000
#define ACL_QUEUE_UNBLOCK_MSG      0xFFFFFFFF
#define ACL_MAX_FLEX_KEY_COUNT     (SAI_ACL_ENTRY_ATTR_FIELD_END - SAI_ACL_ENTRY_ATTR_FIELD_START + 1)
#define ACL_MAX_ACTIONS_COUNT      (SAI_ACL_ENTRY_ATTR_ACTION_END - SAI_ACL_ENTRY_ATTR_ACTION_START + 1)

#define ACL_PBS_MAP_FLOOD_INDEX 64
#define ACL_PBS_MAP_EMPTY_KEY   0

#define ACL_RANGE_INVALID_TYPE (sai_acl_range_type_t)(-1)
#define ACL_RANGE_MAX_COUNT    (RM_API_ACL_PORT_RANGES_MAX)

#define ACL_RPC_SV_SOCKET_ADDR "/tmp/sai_acl_rpc_socket"

#define ACL_INVALID_LAG_ID 0

#define ACL_IP_IDENT_FIELD_START_OFFSET 4

#define sai_acl_db (g_sai_acl_db_ptr)

#define acl_sai_stage_to_sx_dir(stage)  \
    ((stage == SAI_ACL_STAGE_INGRESS) ? \
     SX_ACL_DIRECTION_INGRESS :         \
     SX_ACL_DIRECTION_EGRESS)

#define acl_table_index_check_range(table_index)     ((table_index < ACL_TABLE_DB_SIZE) ? true : false)
#define acl_entry_index_check_range(entry_index)     ((entry_index < ACL_ENTRY_DB_SIZE) ? true : false)
#define acl_counter_index_check_range(counter_index) ((counter_index < ACL_MAX_COUNTER_NUM) ? true : false)
#define acl_group_index_check_range(group_index) \
    ((group_index <                              \
      (ACL_GROUP_NUMBER / g_sai_db_ptr->acl_divider)) ? true : false)
#define is_acl_index_invalid(acl_index) (ACL_INVALID_DB_INDEX == acl_index.acl_db_index)

#define acl_db_table(table_index) sai_acl_db->acl_table_db[(table_index)]
#define acl_db_entry(entry_index) sai_acl_db->acl_entry_db[(entry_index)]

#define MLNX_ACL_DB_TABLE_TO_IDX(table_ptr) ((uint32_t)((table_ptr) - sai_acl_db->acl_table_db))

#define acl_db_pbs_map(index) (sai_acl_db->acl_pbs_map_db[index])
#define acl_db_flood_pbs()    (acl_db_pbs_map(ACL_PBS_MAP_FLOOD_PBS_INDEX).entry)

#define acl_pbs_port_idx_to_pbs_map_idx(port_idx) (port_idx)
#define acl_pbs_map_idx_to_port_idx(pbs_idx)      (pbs_idx)

#define acl_db_vlan_group(index) (sai_acl_db->acl_vlan_groups_db[index])

#define acl_cond_mutex sai_acl_db->acl_settings_tbl->cond_mutex
#define acl_cond_mutex_lock()                            \
    do { if (pthread_mutex_lock(&acl_cond_mutex) != 0) { \
             SX_LOG_ERR("Failed to lock ACL mutex\n"); } \
    } while (0)

#define acl_cond_mutex_unlock()                            \
    do { if (pthread_mutex_unlock(&acl_cond_mutex) != 0) { \
             SX_LOG_ERR("Failed to unlock ACL mutex\n"); } \
    } while (0)

#define acl_table_write_lock(table_id) cl_plock_excl_acquire(&acl_db_table(table_id).lock)
#define acl_table_read_lock(table_id)  cl_plock_acquire(&acl_db_table(table_id).lock)
#define acl_table_unlock(table_id)     cl_plock_release(&acl_db_table(table_id).lock)

#define MLNX_ACL_SX_SPAN_SESSION_INVALID ((uint8_t)-1)
#define MLNX_ACL_SX_SPAN_SESSION_IS_VALID(s) ((s) != MLNX_ACL_SX_SPAN_SESSION_INVALID)

#define MLNX_ACL_SX_FLEX_RULE_EMPTY {.key_desc_list_p = NULL, .action_list_p = NULL}
#define MLNX_ACL_SX_FLEX_RULE_IS_EMPTY(rule) ((NULL == (rule)->key_desc_list_p) && (NULL == (rule)->action_list_p))

#define MLNX_SAI_STRUCT_MEMBER_SIZE(type, member) sizeof(((type*)0)->member)
#define MLNX_ACL_FIELD_INFO_DEFINE_WITH_STAGE(sx_key_id, sx_key_type, type, stage, chip) \
    {.key_id = sx_key_id,                                                                \
     .key_size = MLNX_SAI_STRUCT_MEMBER_SIZE(sx_acl_key_fields_t, sx_key_type),          \
     .field_type = type,                                                                 \
     .supported_stage = stage,                                                           \
     .supported_chip = chip }

#define MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE_WITH_STAGE(sx_key_id, sx_key_type, type, MLNX_ACL_SUPPORTED_STAGE_BOTH, supported_chip)

#define MLNX_ACL_FIELD_INFO_DEFINE_INGRESS(sx_key_id, sx_key_type, type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE_WITH_STAGE(sx_key_id,                                     \
                                          sx_key_type,                                   \
                                          type,                                          \
                                          MLNX_ACL_SUPPORTED_STAGE_INGRESS,              \
                                          supported_chip)

#define MLNX_ACL_ENTRY_KEY_LIST(...) {__VA_ARGS__}
#define MLNX_ACL_MULTI_KEY_FIELD_INFO(sx_key_count, sx_key_list, type, chip) \
    {.key_count = sx_key_count,                                              \
     .key_list = (sx_acl_key_t[sx_key_count])sx_key_list,                    \
     .field_type = type,                                                     \
     .supported_chip = chip }

#define MLNX_ACL_FIELD_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_EMPTY, supported_chip)
#define MLNX_ACL_FIELD_L2_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_EMPTY, supported_chip)
#define MLNX_ACL_FIELD_L2_DEFINE_INGRESS(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE_INGRESS(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_EMPTY, supported_chip)
#define MLNX_ACL_FIELD_INNER_VLAN_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID, supported_chip)
#define MLNX_ACL_FIELD_IP_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_IP, supported_chip)
#define MLNX_ACL_FIELD_IPV4_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_IPV4, supported_chip)
#define MLNX_ACL_FIELD_IPV6_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_IPV6, supported_chip)
#define MLNX_ACL_FIELD_TCP_UDP_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_TCP_UDP, supported_chip)
#define MLNX_ACL_FIELD_TCP_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_TCP, supported_chip)
#define MLNX_ACL_FIELD_ICMPV4_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_ICMPV4, supported_chip)
#define MLNX_ACL_FIELD_ICMPV6_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_ICMPV6, supported_chip)
#define MLNX_ACL_FIELD_TCP_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_TCP, supported_chip)
#define MLNX_ACL_FIELD_INNER_IP_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_IP, supported_chip)
#define MLNX_ACL_FIELD_INNER_IPV4_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_IPV4, supported_chip)
#define MLNX_ACL_FIELD_INNER_IPV6_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_IPV6, supported_chip)
#define MLNX_ACL_FIELD_INNER_L4_DEFINE(sx_key_id, sx_key_type, supported_chip) \
    MLNX_ACL_FIELD_INFO_DEFINE(sx_key_id, sx_key_type, MLNX_ACL_FIELD_TYPE_INNER_L4, supported_chip)

#define MLNX_ACL_SX_ACTION_TYPE_INVALID (SX_FLEX_ACL_FLEX_ACTION_TYPE_MAX + 1)
#define MLNX_ACL_ACTION_INFO_UNDEFINED(info) ((info->convert_to_sx == NULL) && (info->field_size == 0))
#define MLNX_ACL_ACTION_CTX_EMPTY                                   \
    {                                                               \
        .pbs_info = MLNX_ACL_PBS_INFO_INVALID,                      \
        .sx_mc_container_egress_block = SX_MC_CONTAINER_ID_INVALID, \
        .sx_counter_id = SX_FLOW_COUNTER_ID_INVALID,                \
        .sx_span_session = MLNX_ACL_SX_SPAN_SESSION_INVALID}

#define MLNX_ACL_ACTION_INFO_DEFINE(type, size, stages, chip, to_sx, to_sai) \
    {                                                                        \
        .sx_type = type,                                                     \
        .field_size = size,                                                  \
        .supported_stage = stages,                                           \
        .supported_chip = chip,                                              \
        .convert_to_sx = to_sx,                                              \
        .convert_to_sai = to_sai}

#define MLNX_ACL_ACTION_INFO_DEFINE_DEFAULT(type, size, to_sx, to_sai) \
    MLNX_ACL_ACTION_INFO_DEFINE(type, size, MLNX_ACL_SUPPORTED_STAGE_BOTH, MLNX_ACL_SUPPORTED_CHIP_ANY, to_sx, to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_SPC2_3(type, size, to_sx, to_sai)                        \
    MLNX_ACL_ACTION_INFO_DEFINE(type,                                                        \
                                size,                                                        \
                                MLNX_ACL_SUPPORTED_STAGE_BOTH,                               \
                                MLNX_ACL_SUPPORTED_CHIP_SPC2 | MLNX_ACL_SUPPORTED_CHIP_SPC3, \
                                to_sx,                                                       \
                                to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_INGRESS(type, size, to_sx, to_sai) \
    MLNX_ACL_ACTION_INFO_DEFINE(type,                                  \
                                size,                                  \
                                MLNX_ACL_SUPPORTED_STAGE_INGRESS,      \
                                MLNX_ACL_SUPPORTED_CHIP_ANY,           \
                                to_sx,                                 \
                                to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_EGRESS(type, size, to_sx, to_sai)                                            \
    MLNX_ACL_ACTION_INFO_DEFINE(type, size, MLNX_ACL_SUPPORTED_STAGE_EGRESS, MLNX_ACL_SUPPORTED_CHIP_ANY, to_sx, \
                                to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(to_sx, to_sai) \
    MLNX_ACL_ACTION_INFO_DEFINE_DEFAULT(MLNX_ACL_SX_ACTION_TYPE_INVALID, 0, to_sx, to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS_SPC2_3(to_sx, to_sai) \
    MLNX_ACL_ACTION_INFO_DEFINE_SPC2_3(MLNX_ACL_SX_ACTION_TYPE_INVALID, 0, to_sx, to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_INGRESS_WITH_FNS(to_sx, to_sai) \
    MLNX_ACL_ACTION_INFO_DEFINE_INGRESS(MLNX_ACL_SX_ACTION_TYPE_INVALID, 0, to_sx, to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_EGRESS_WITH_FNS(to_sx, to_sai) \
    MLNX_ACL_ACTION_INFO_DEFINE_EGRESS(MLNX_ACL_SX_ACTION_TYPE_INVALID, 0, to_sx, to_sai)

#define MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(type, field)                                           \
    MLNX_ACL_ACTION_INFO_DEFINE_DEFAULT(type,                                                         \
                                        MLNX_SAI_STRUCT_MEMBER_SIZE(sx_flex_acl_flex_action_fields_t, \
                                                                    field), NULL, NULL)

#define MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD_SPC2(type, field)                                     \
    MLNX_ACL_ACTION_INFO_DEFINE_SPC2_3(type,                                                         \
                                       MLNX_SAI_STRUCT_MEMBER_SIZE(sx_flex_acl_flex_action_fields_t, \
                                                                   field), NULL, NULL)

#define MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(index)             \
    { SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN + index, \
      { true, false, false, true },                            \
      { true, false, false, true },                            \
      mlnx_acl_table_udf_attrib_get, (void*)index,             \
      NULL, NULL }

#define MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(index)                                               \
    { SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN + index,                                   \
      { true, false, true, true },                                                               \
      { true, false, true, true },                                                               \
      mlnx_acl_entry_udf_get, (void*)(SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN + index),  \
      mlnx_acl_entry_udf_set, (void*)(SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN + index) } \

typedef enum _mlnx_acl_supported_stage_t {
    MLNX_ACL_SUPPORTED_STAGE_INGRESS = SAI_ACL_STAGE_INGRESS,
    MLNX_ACL_SUPPORTED_STAGE_EGRESS  = SAI_ACL_STAGE_EGRESS,
    MLNX_ACL_SUPPORTED_STAGE_BOTH    = SAI_ACL_STAGE_EGRESS + 1,
    MLNX_ACL_SUPPORTED_STAGE_MAX     = MLNX_ACL_SUPPORTED_STAGE_BOTH
} mlnx_acl_supported_stage_t;
#define MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(type) (1 << (type))
typedef enum _mlnx_acl_supported_chip_t {
    MLNX_ACL_SUPPORTED_CHIP_SPC1 = MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(SX_CHIP_TYPE_SPECTRUM) |
                                   MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(SX_CHIP_TYPE_SPECTRUM_A1),
    MLNX_ACL_SUPPORTED_CHIP_SPC2 = MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(SX_CHIP_TYPE_SPECTRUM2),
    MLNX_ACL_SUPPORTED_CHIP_SPC3 = MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(SX_CHIP_TYPE_SPECTRUM3),
    MLNX_ACL_SUPPORTED_CHIP_ANY  = MLNX_ACL_SUPPORTED_CHIP_SPC1 | MLNX_ACL_SUPPORTED_CHIP_SPC2 |
                                   MLNX_ACL_SUPPORTED_CHIP_SPC3,
} mlnx_acl_supported_chip_t;
typedef struct _mlnx_acl_sai_single_key_field_info_t {
    sx_acl_key_t               key_id;
    uint32_t                   key_size;
    mlnx_acl_field_type_t      field_type;
    mlnx_acl_supported_stage_t supported_stage;
    mlnx_acl_supported_chip_t  supported_chip;
} mlnx_acl_single_key_field_info_t;
typedef struct _mlnx_acl_sai_multiple_key_field_info_t {
    uint32_t                  key_count;
    sx_acl_key_t             *key_list;
    mlnx_acl_field_type_t     field_type;
    mlnx_acl_supported_chip_t supported_chip;
} mlnx_acl_multi_key_field_info_t;
typedef struct _mlnx_acl_action_ctx_t {
    sx_mc_container_id_t sx_mc_container_egress_block;
    bool                 is_redirect_action_present;
    bool                 is_redirect_endpoint_needed;
    bool                 is_redirect_endpoint_set;
    uint32_t             redirect_action_idx;
    mlnx_acl_pbs_info_t  pbs_info;
    bool                 counter_byte_flag;
    bool                 counter_packet_flag;
    sx_flow_counter_id_t sx_counter_id;
    sx_span_session_id_t sx_span_session;
    bool                 is_policer_action_present;
} mlnx_acl_action_ctx_t;
typedef sai_status_t (*mlnx_acl_action_to_sx_fn)(_In_ sai_acl_entry_attr_t action,
                                                 _In_ const sai_acl_action_data_t *action_data,
                                                 _In_ uint32_t attr_index, _In_ const acl_table_db_t        *table,
                                                 _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                 _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                 _Inout_ uint32_t                 *sx_action_count);
typedef sai_status_t (*mlnx_acl_action_to_sai_fn)(_In_ sai_acl_entry_attr_t action,
                                                  _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                  _In_ const acl_entry_db_t *entry, _In_ const acl_table_db_t *table,
                                                  _In_ uint32_t attr_index,
                                                  _Out_ sai_acl_action_data_t        *action_data);
typedef struct _mlnx_acl_action_info_t {
    sx_flex_acl_flex_action_type_t sx_type;
    uint32_t                       field_size;
    mlnx_acl_supported_stage_t     supported_stage;
    mlnx_acl_supported_chip_t      supported_chip;
    mlnx_acl_action_to_sx_fn       convert_to_sx;
    mlnx_acl_action_to_sai_fn      convert_to_sai;
} mlnx_acl_action_info_t;
typedef enum acl_rpc_type_t {
    ACL_RPC_TERMINATE_THREAD,
    ACL_RPC_TABLE_INIT,
    ACL_RPC_TABLE_DELETE,
    ACL_RPC_ENTRY_OFFSET_GET,
    ACL_RPC_ENTRY_OFFSET_DEL
} acl_rpc_type_t;
PACKED(struct _acl_rpc_args_t {
    bool table_is_dynamic;
    uint32_t table_id;
    uint32_t size;
    uint32_t entry_id;
    uint32_t entry_prio;
    sx_acl_rule_offset_t entry_offset;
}, );
typedef struct _acl_rpc_args_t acl_rpc_args_t;
PACKED(struct _acl_rpc_info_t {
    acl_rpc_type_t type;
    acl_rpc_args_t args;
    sai_status_t status;
}, );
typedef struct _acl_rpc_info_t acl_rpc_info_t;
typedef uint32_t mlnx_acl_port_db_refs_t[MAX_PORTS_DB * 2];

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
static pthread_key_t      pthread_sx_handle_key;
static mqd_t              psort_opt_queue_client = ACL_QUEUE_INVALID_HANDLE;
static struct sockaddr_un rpc_sv_sockaddr;
#endif
static int  rpc_cl_socket = -1;
static bool is_init_process = false;

#define MLNX_ACL_FIELD_IS_PRESENT(filed, field_group)     (((field_group) & (filed)) == (filed))
#define MLNX_ACL_FIELD_IS_NOT_PRESENT(field, field_group) ((field) & (~(field_group)))

static const mlnx_acl_field_type_t mlnx_acl_invalid_field_sets[] = {
    MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID | MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID,
    MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_NON_IP,
    MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_ARP,
    MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_NON_IPV4,
    MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_IPV6,
    MLNX_ACL_FIELD_TYPE_IPV6 | MLNX_ACL_FIELD_TYPE_ARP,
    MLNX_ACL_FIELD_TYPE_INNER_IPV4 | MLNX_ACL_FIELD_TYPE_INNER_IPV6,
    MLNX_ACL_FIELD_TYPE_TCP_UDP | MLNX_ACL_FIELD_TYPE_ICMP,
    MLNX_ACL_FIELD_TYPE_ICMPV4 | MLNX_ACL_FIELD_TYPE_ICMPV6,
};
static const uint32_t              mlnx_acl_invalid_field_sets_size = ARRAY_SIZE(mlnx_acl_invalid_field_sets);
const char* const                  mlnx_acl_invalid_field_sets_names[] = {
    "INNER VLAN INVALID + VALID",
    "IP + NON IP",
    "IP + ARP",
    "IPv4 + NON IPv4",
    "IPv4 + IPv6",
    "IPv6 + ARP",
    "INNER IPv4 + INNER IPv6",
    "TCP_UDP + ICMP",
    "ICMPv4 + ICMPv6"
};
#define SAI_ACL_FIELD_SET_CHECK_RANGE(set) (set < mlnx_acl_invalid_field_sets_size)
#define SAI_ACL_FIELD_SET_STR(set) \
    SAI_ACL_FIELD_SET_CHECK_RANGE(set) ? mlnx_acl_invalid_field_sets_names[set] : "Unknown set"

typedef struct mlnx_acl_field_extra_keys {
    mlnx_acl_field_type_t  field_type;
    sx_flex_acl_key_desc_t sx_key_desc;
} mlnx_acl_field_extra_keys_t;

#define MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(field, sx_key, sx_key_type, sx_value) \
    {                                                                         \
        .field_type = field,                                                  \
        .sx_key_desc = {                                                      \
            .key_id = sx_key,                                                 \
            .key = {                                                          \
                .sx_key_type = sx_value                                       \
            },                                                                \
            .mask = {                                                         \
                .sx_key_type = true                                           \
            }                                                                 \
        }                                                                     \
    }

static const mlnx_acl_field_extra_keys_t mlnx_acl_field_extra_keys_map[] = {
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID,
        FLEX_ACL_KEY_INNER_VLAN_VALID,
        inner_vlan_valid,
        true),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID,
        FLEX_ACL_KEY_INNER_VLAN_VALID,
        inner_vlan_valid,
        false),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_IP,
        FLEX_ACL_KEY_IP_OK,
        ip_ok,
        true),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_NON_IP,
        FLEX_ACL_KEY_IP_OK,
        ip_ok,
        false),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_IPV4,
        FLEX_ACL_KEY_L3_TYPE,
        l3_type,
        SX_ACL_L3_TYPE_IPV4),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_NON_IPV4,
        FLEX_ACL_KEY_IS_IP_V4,
        is_ip_v4,
        false),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_IPV6,
        FLEX_ACL_KEY_L3_TYPE,
        l3_type,
        SX_ACL_L3_TYPE_IPV6),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_ARP,
        FLEX_ACL_KEY_L3_TYPE,
        l3_type,
        SX_ACL_L3_TYPE_ARP),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_INNER_IPV4,
        FLEX_ACL_KEY_INNER_L3_TYPE,
        inner_l3_type,
        SX_ACL_L3_TYPE_IPV4),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_INNER_IPV6,
        FLEX_ACL_KEY_INNER_L3_TYPE,
        inner_l3_type,
        SX_ACL_L3_TYPE_IPV6),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_TCP_UDP,
        FLEX_ACL_KEY_L4_OK,
        l4_ok,
        true),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_TCP,
        FLEX_ACL_KEY_L4_TYPE,
        l4_type,
        SX_ACL_L4_TYPE_TCP),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_ICMP,
        FLEX_ACL_KEY_L4_TYPE_EXTENDED,
        l4_type_extended,
        SX_ACL_L4_TYPE_EXTENDED_ICMP),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_INNER_IP,
        FLEX_ACL_KEY_INNER_IP_OK,
        inner_ip_ok,
        true),
    MLNX_ACL_FIELD_EXTRA_KEY_DEFINE(
        MLNX_ACL_FIELD_TYPE_INNER_L4,
        FLEX_ACL_KEY_INNER_L4_OK,
        inner_l4_ok,
        true)
};
static const uint32_t                    mlnx_acl_field_extra_keys_map_size =
    ARRAY_SIZE(mlnx_acl_field_extra_keys_map);

typedef sai_status_t (*mlnx_acl_entry_iter_fn)(_In_ uint32_t table_idx, _In_ uint32_t entry_idx,
                                               _In_ void     *opaque);
typedef sai_status_t (*mlnx_acl_table_init_f)(_In_ uint32_t table_db_idx, _In_ bool is_table_dynamic,
                                              _In_ uint32_t size);
typedef sai_status_t (*mlnx_acl_table_deinit_f)(_In_ uint32_t table_db_idx);
typedef sai_status_t (*mlnx_acl_entry_offset_get_f)(_In_ uint32_t table_db_idx, _In_ uint32_t entry_db_idx,
                                                    _In_ uint32_t priority, _Out_ sx_acl_rule_offset_t *sx_offset);
typedef sai_status_t (*mlnx_acl_entry_offset_del_f)(_In_ uint32_t table_db_idx, _In_ uint32_t priority,
                                                    _In_ sx_acl_rule_offset_t offset);
typedef sai_status_t (*mlnx_acl_entry_prio_set_f)(_In_ uint32_t table_db_idx, _In_ uint32_t entry_db_idx,
                                                  _In_ uint32_t sx_prio);
typedef sai_status_t (*mlnx_acl_sx_rule_prio_set_f)(_In_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t sx_prio);
typedef sai_status_t (*mlnx_acl_init_f)(void);
typedef sai_status_t (*mlnx_acl_lazy_init_f)(void);
typedef sai_status_t (*mlnx_acl_deinit_f)(void);
typedef sai_status_t (*mlnx_acl_table_size_set_f)(_In_ uint32_t table_db_idx, _In_ uint32_t size);
typedef sai_status_t (*mlnx_acl_table_optimize_f)(_In_ uint32_t table_db_idx);
typedef sai_status_t (*mlnx_acl_range_create_f)(_In_ sai_acl_range_type_t type, _In_ const sai_u32_range_t   *range,
                                                _Out_ sx_acl_port_range_id_t *sx_range_id);
typedef sai_status_t (*mlnx_acl_range_remove_f)(_In_ sx_acl_port_range_id_t sx_range_id);
typedef sai_status_t (*mlnx_acl_range_attr_get_f)(_In_ sx_acl_port_range_id_t sx_range_id, _In_ sai_attr_id_t attr_id,
                                                  _Out_ sai_attribute_value_t *value);
typedef struct _mlnx_acl_cb_list_t {
    mlnx_acl_table_init_f       table_init;
    mlnx_acl_table_deinit_f     table_deinit;
    mlnx_acl_entry_offset_get_f entry_offset_get;
    mlnx_acl_entry_offset_del_f entry_offset_del;
    mlnx_acl_entry_prio_set_f   entry_prio_set;
    mlnx_acl_init_f             init;
    mlnx_acl_lazy_init_f        lazy_init;
    mlnx_acl_deinit_f           deinit;
    mlnx_acl_table_size_set_f   table_size_set;
    mlnx_acl_table_optimize_f   table_optimize;
    mlnx_acl_sx_rule_prio_set_f rule_prio_set;
    mlnx_acl_range_create_f     range_create;
    mlnx_acl_range_remove_f     range_remove;
    mlnx_acl_range_attr_get_f   range_attr_get;
} mlnx_acl_cb_list_t;
typedef struct _mlnx_acl_sp2_reg_offset_t {
    uint32_t next_free_offset_idx;
} mlnx_acl_sp2_reg_offset_t;
typedef struct _mlnx_acl_sp2_table_t {
    bool                       is_inited;
    uint32_t                   size;
    uint32_t                   allocated;
    uint32_t                   next_free_index;
    mlnx_acl_sp2_reg_offset_t *offsets;
} mlnx_acl_sp2_table_t;
typedef struct _mlnx_acl_sp2_table_db_t {
    mlnx_acl_sp2_table_t *tables; /* ACL_TABLE_DB_SIZE */
    bool                  is_inited;
} mlnx_acl_sp2_table_db_t;

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
static sai_status_t mlnx_acl_table_udf_attrib_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_acl_table_entry_list_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_acl_table_available_entries_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg);
static sai_status_t mlnx_acl_table_available_counters_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_acl_entry_udf_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_acl_entry_udf_set(_In_ const sai_object_key_t      *key,
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
static sai_status_t mlnx_acl_entry_action_ip_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_acl_entry_action_l4port_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_acl_counter_attr_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_acl_counter_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_acl_entry_ip_flags_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_acl_entry_port_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
static sai_status_t mlnx_acl_entry_action_trivial_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg);
static sai_status_t mlnx_acl_entry_ports_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg);
static sai_status_t mlnx_acl_entry_port_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);
static sai_status_t mlnx_acl_entry_action_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_acl_entry_action_egress_block_port_set(_In_ const sai_object_key_t      *key,
                                                                _In_ const sai_attribute_value_t *value,
                                                                void                             *arg);
static sai_status_t mlnx_acl_entry_action_redirect_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg);
static sai_status_t mlnx_acl_entry_action_endpoint_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg);
static sai_status_t mlnx_acl_entry_action_vlan_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg);
static sai_status_t mlnx_acl_packet_actions_handler(_In_ sai_packet_action_t           packet_action_type,
                                                    _In_ uint16_t                      trap_id,
                                                    _Inout_ sx_flex_acl_flex_action_t *flex_actions,
                                                    _Inout_ uint32_t                  *flex_action_index);
static sai_status_t mlnx_acl_ip_ident_key_create_or_get(_Out_ sx_acl_key_t *keys);
static sai_status_t mlnx_acl_ip_ident_key_ref_remove(void);
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
static sai_status_t mlnx_acl_group_member_list_get(_In_ const sai_object_key_t   *key,
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
static sai_status_t mlnx_acl_flex_rule_free(_In_ sx_flex_acl_flex_rule_t *rule);
static void mlnx_acl_flex_rule_key_find(_In_ const sx_flex_acl_flex_rule_t *rule,
                                        _In_ sx_acl_key_t                   key,
                                        _Out_ uint32_t                     *key_index,
                                        _Out_ bool                         *is_key_present);
static void mlnx_acl_flex_rule_action_find(_In_ const sx_flex_acl_flex_rule_t *rule,
                                           _In_ sx_flex_acl_flex_action_type_t action_type,
                                           _Out_ uint32_t                     *action_index,
                                           _Out_ bool                         *is_action_present);
static void mlnx_acl_sx_key_list_find_key(_In_ const sx_acl_key_t *sx_keys,
                                          _In_ uint32_t            sx_key_count,
                                          _In_ sx_acl_key_t        sx_key,
                                          _Out_ bool              *is_present,
                                          _Out_ uint32_t          *key_idx);
static void mlnx_acl_sx_key_list_add_key(_Inout_ sx_acl_key_t    *sx_keys,
                                         _Inout_ uint32_t        *sx_key_count,
                                         _In_ const sx_acl_key_t *sx_new_keys,
                                         _In_ uint32_t            sx_new_keys_count);
static sai_status_t mlnx_acl_entry_sx_acl_rule_get(_In_ uint32_t                    acl_table_index,
                                                   _In_ uint32_t                    acl_entry_index,
                                                   _Inout_ sx_flex_acl_flex_rule_t *flex_acl_rule_p);
static sai_status_t mlnx_acl_entry_sx_acl_rule_set(_In_ uint32_t                       acl_table_index,
                                                   _In_ uint32_t                       acl_entry_index,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_flex_rule);
static sai_status_t mlnx_acl_flex_rule_delete(_In_ uint32_t                 acl_table_index,
                                              _In_ sx_flex_acl_flex_rule_t *sx_rule,
                                              _In_ sx_acl_rule_offset_t     sx_acl_rule_offset);
static sai_status_t mlnx_acl_sx_rule_mc_containers_remove(_In_ sx_flex_acl_flex_rule_t *sx_rule);
static sai_status_t mlnx_delete_acl_entry_data(_In_ uint32_t table_index, _In_ uint32_t entry_index);
static sx_utils_status_t psort_notification_func(_In_ psort_notification_type_e notif_type,
                                                 _In_ void                     *data,
                                                 _In_ void                     *cookie);
static sai_status_t create_rpc_server(_Inout_ int *s);
static sai_status_t create_rpc_client(_Inout_ int *s, _Inout_ struct sockaddr_un *sv_sockaddr);
static sai_status_t create_rpc_socket(_Inout_ int *s, _Inout_opt_ struct sockaddr_un *sockaddr, _In_ bool is_server);
static sai_status_t mlnx_acl_rpc_call(_Inout_ acl_rpc_info_t *rpc_info);
static sai_status_t mlnx_acl_lazy_init(void);
static sai_status_t acl_psort_background_close(void);
static sai_status_t mlnx_acl_rpc_thread_close(void);
static sai_status_t mlnx_acl_rpc_client_close(void);
static sai_status_t mlnx_acl_psort_opt_queue_create(void);
static sai_status_t mlnx_acl_psort_opt_queue_client_create(void);
static sai_status_t mlnx_acl_psort_opt_queue_client_close(void);
static sai_status_t mlnx_acl_psort_thread_wake(void);
static void mlnx_acl_table_locks_deinit(void);
static void psort_background_thread(void *arg);
static void mlnx_acl_rpc_thread(void *arg);
static sai_status_t mlnx_acl_sx_rule_offset_update(_In_ const psort_shift_param_t *shift_param,
                                                   _In_ uint32_t                   acl_table_index);
static sai_status_t mlnx_acl_table_init(_In_ uint32_t table_db_idx, _In_ bool is_table_dynamic, _In_ uint32_t size);
static sai_status_t mlnx_acl_table_deinit(_In_ uint32_t table_db_idx);
static sai_status_t mlnx_acl_entry_offset_get(_In_ uint32_t                 table_db_idx,
                                              _In_ uint32_t                 entry_db_idx,
                                              _In_ uint32_t                 sx_prio,
                                              _Inout_ sx_acl_rule_offset_t *offset);
static sai_status_t mlnx_acl_entry_offset_del(_In_ uint32_t             table_db_idx,
                                              _In_ uint32_t             sx_prio,
                                              _In_ sx_acl_rule_offset_t offset);
static sai_status_t mlnx_acl_entry_prio_set(_In_ uint32_t table_db_idx,
                                            _In_ uint32_t entry_db_idx,
                                            _In_ uint32_t sx_prio);
static sai_status_t mlnx_acl_sx_rule_prio_set(_In_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t sx_prio);
static sai_status_t mlnx_acl_table_check_size_increase(_In_ uint32_t table_db_idx);
static sai_status_t mlnx_acl_table_optimize(_In_ uint32_t table_db_idx);
static sai_status_t mlnx_acl_table_size_increase(_In_ uint32_t table_index);
static sai_status_t mlnx_acl_table_size_decrease(_In_ uint32_t table_index);
static sai_status_t mlnx_acl_table_size_delta_get(_In_ uint32_t acl_table_index, _Out_ uint32_t *delta);
static sx_acl_direction_t mlnx_acl_table_sx_direction_get(_In_ const acl_table_db_t *table);
static void acl_psort_optimize_table(_In_ uint32_t table_index);
static sai_status_t acl_db_find_entry_free_index(_Out_ uint32_t *free_index);
static sai_status_t acl_db_find_table_free_index(_Out_ uint32_t *free_index);
static sai_status_t acl_db_find_group_free_index(_Out_ uint32_t *free_index);
static sai_status_t mlnx_acl_db_entry_delete(_In_ uint32_t entry_index);
static sai_status_t mlnx_acl_db_entry_add_to_table(_In_ uint32_t table_index, _In_ uint32_t entry_index);
static sai_status_t mlnx_acl_db_entry_remove_from_table(_In_ uint32_t table_index, _In_ uint32_t entry_index);
static sai_status_t mlnx_acl_db_entries_foreach(_In_ mlnx_acl_entry_iter_fn fn, void *opaque);
static sai_status_t extract_acl_table_index_and_entry_index(_In_ sai_object_id_t entry_object_id,
                                                            _Out_ uint32_t      *acl_table_index,
                                                            _Out_ uint32_t      *acl_entry_index);
static sai_status_t extract_acl_table_index(_In_ sai_object_id_t table_object_id,
                                            _Out_ uint32_t      *acl_table_index);
static sai_status_t mlnx_acl_counter_oid_create(_In_ sx_flow_counter_id_t sx_counter_id,
                                                _In_ bool                 byte_counter_flag,
                                                _In_ bool                 packet_counter_flag,
                                                _In_ uint32_t             table_db_idx,
                                                _Out_ sai_object_id_t    *counter_oid);
static sai_status_t mlnx_acl_counter_oid_to_sx(_In_ sai_object_id_t        counter_oid,
                                               _Out_ sx_flow_counter_id_t *sx_counter_id);
static sai_status_t mlnx_acl_counter_oid_data_get(_In_ sai_object_id_t        counter_oid,
                                                  _Out_ sx_flow_counter_id_t *sx_counter_id,
                                                  _Out_ bool                 *byte_counter_flag,
                                                  _Out_ bool                 *packet_counter_flag,
                                                  _Out_ uint32_t             *table_db_index);
static sai_status_t acl_create_entry_object_id(_Out_ sai_object_id_t *entry_oid,
                                               _In_ uint32_t          entry_index,
                                               _In_ uint16_t          table_index);
static sai_status_t mlnx_acl_sx_rule_mc_containers_get(_In_ const sx_flex_acl_flex_rule_t *rule,
                                                       _Out_ sx_mc_container_id_t         *rx_list,
                                                       _Out_ sx_mc_container_id_t         *tx_list,
                                                       _Out_ sx_mc_container_id_t         *egr_block);
static sai_status_t mlnx_acl_entry_sx_rule_port_refs_get(_In_ const sx_flex_acl_flex_rule_t *rule,
                                                         _Out_ mlnx_acl_port_db_refs_t       refs);
static sai_status_t mlnx_acl_entry_port_refs_set(_In_ mlnx_acl_port_db_refs_t refs);
static sai_status_t mlnx_acl_entry_port_refs_clear(_In_ mlnx_acl_port_db_refs_t refs);
static sai_status_t mlnx_acl_entry_port_refs_update(_In_ mlnx_acl_port_db_refs_t old_refs,
                                                    _In_ mlnx_acl_port_db_refs_t new_refs);
static sai_status_t mlnx_acl_pbs_ports_to_map_key(_In_ const sai_object_id_t *ports,
                                                  _In_ uint32_t               ports_count,
                                                  _Out_ acl_pbs_map_key_t    *map_key);
static mlnx_acl_pbs_map_idx_t mlnx_acl_pbs_map_key_to_index(_In_ const acl_pbs_map_key_t *key, _In_ uint32_t step);
static bool mlnx_acl_pbs_map_key_is_equal(_In_ const acl_pbs_map_key_t *key1, _In_ const acl_pbs_map_key_t *key2);
static sai_status_t mlnx_acl_pbs_ports_create_or_get(_In_ const sai_object_id_t *ports,
                                                     _In_ uint32_t               ports_count,
                                                     _Out_ sx_acl_pbs_id_t      *sx_pbs_id,
                                                     _Out_ mlnx_acl_pbs_info_t  *pbs_info);
static sai_status_t mlnx_acl_flood_pbs_create_or_get(_Out_ sx_acl_pbs_id_t     *sx_pbs_id,
                                                     _Out_ mlnx_acl_pbs_info_t *pbs_info);
static sai_status_t mlnx_acl_pbs_info_delete(_In_ mlnx_acl_pbs_info_t pbs_info);
static sai_status_t mlnx_acl_pbs_info_port_refs_get(_In_ mlnx_acl_pbs_info_t      pbs_info,
                                                    _Out_ mlnx_acl_port_db_refs_t refs);
static sai_status_t mlnx_acl_pbs_map_sai_ports_get(_In_ mlnx_acl_pbs_map_idx_t pbs_map_idx,
                                                   _Out_ sai_object_id_t      *ports,
                                                   _Out_ uint32_t             *ports_count);
static sai_status_t mlnx_acl_pbs_info_to_sai_oid(_In_ mlnx_acl_pbs_info_t pbs_info, _Out_ sai_object_id_t     *oid);
static sai_status_t mlnx_acl_pbs_info_sai_ports_get(_In_ mlnx_acl_pbs_info_t pbs_info,
                                                    _Out_ sai_object_id_t   *ports,
                                                    _Out_ uint32_t          *ports_count);
static sai_status_t mlnx_acl_range_attr_get_by_oid(_In_ sai_object_id_t           acl_range_oid,
                                                   _In_ sai_attr_id_t             attr_id,
                                                   _Inout_ sai_attribute_value_t *value);
static sai_status_t mlnx_acl_field_port_to_sx(_In_ sai_object_id_t sai_port, _Out_ sx_port_log_id_t *sx_port);
static sai_status_t mlnx_sai_acl_redirect_action_create(_In_ sai_object_id_t             object_id,
                                                        _In_ uint32_t                    attr_index,
                                                        _Out_ mlnx_acl_pbs_info_t       *pbs_info,
                                                        _Out_ sx_flex_acl_flex_action_t *sx_action);
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
static sai_status_t mlnx_acl_sx_mc_container_set_impl(_In_ sx_access_cmd_t          sx_cmd,
                                                      _In_ const sai_object_list_t *port_obj_list,
                                                      _Out_ sx_mc_container_id_t   *sx_mc_container_id);
static sai_status_t mlnx_acl_sx_mc_container_create(_In_ const sai_object_list_t *port_obj_list,
                                                    _Out_ sx_mc_container_id_t   *sx_mc_container_id);
static sai_status_t mlnx_acl_sx_mc_container_update(_In_ const sai_object_list_t *port_obj_list,
                                                    _Inout_ sx_mc_container_id_t  sx_mc_container_id);
static sai_status_t mlnx_acl_sx_mc_container_sx_ports_get(_In_ sx_mc_container_id_t sx_mc_container_id,
                                                          _Out_ sx_port_log_id_t   *sx_ports,
                                                          _Inout_ uint32_t         *sx_ports_count);
static sai_status_t mlnx_acl_sx_mc_container_sai_ports_get(_In_ sx_mc_container_id_t sx_mc_container_id,
                                                           _Out_ sai_object_id_t    *ports,
                                                           _Inout_ uint32_t         *ports_count);
static sai_status_t mlnx_acl_sx_mc_container_remove(_In_ sx_mc_container_id_t sx_mc_container_id);
static sai_status_t mlnx_acl_table_udf_attrs_parse(_In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list,
                                                   _Out_ sx_acl_key_t         *sx_keys,
                                                   _Inout_ uint32_t           *sx_key_count,
                                                   _Out_ acl_udf_group_list_t  udf_group_list);
static sai_status_t mlnx_acl_entry_udf_attrs_parse(_In_ _In_ uint32_t            attr_count,
                                                   _In_ const sai_attribute_t   *attr_list,
                                                   _In_ uint32_t                 acl_table_index,
                                                   _Out_ sx_flex_acl_key_desc_t *key_desc,
                                                   _Inout_ uint32_t             *key_desc_count);
static sai_status_t mlnx_acl_entry_udf_attrs_validate_and_fetch(_In_ const sai_attribute_value_t *udf_attr,
                                                                _In_ sai_acl_entry_attr_t         udf_attr_id,
                                                                _In_ uint32_t                     attr_index,
                                                                _In_ uint32_t                     acl_table_index,
                                                                _Out_ sx_acl_key_t               *custom_byte_keys,
                                                                _Inout_ uint32_t                 *custom_byte_count);
static bool mlnx_acl_field_is_not_trivial(sai_attr_id_t attr_id);
static const mlnx_acl_single_key_field_info_t* mlnx_acl_single_key_field_info_fetch(_In_ sai_attr_id_t attr_id);
static const mlnx_acl_multi_key_field_info_t* mlnx_acl_multi_key_field_info_fetch(_In_ sai_attr_id_t attr_id);
static sai_status_t mlnx_acl_non_trivial_field_to_sx_key(_In_ sai_acl_entry_attr_t attr_id,
                                                         _Out_ sx_acl_key_t       *sx_keys,
                                                         _Out_ uint32_t           *sx_key_count);
static sai_status_t mlnx_acl_table_is_entry_field_supported(_In_ uint32_t             acl_table_index,
                                                            _In_ sai_acl_entry_attr_t attr_id,
                                                            _Out_ bool               *is_supported);
static sai_status_t mlnx_acl_field_info_data_fetch(_In_ sai_attr_id_t                attr_id,
                                                   _Out_opt_ mlnx_acl_field_type_t  *fields_types,
                                                   _Out_opt_ sx_acl_key_t           *sx_keys,
                                                   _Inout_opt_ uint32_t             *sx_key_count,
                                                   _Out_ mlnx_acl_supported_stage_t *supported_stage,
                                                   _Out_ mlnx_acl_supported_chip_t  *supported_chip);
static sai_status_t mlnx_acl_table_fields_to_sx(_In_ const sai_attribute_t  *attr_list,
                                                _In_ uint32_t                attr_count,
                                                _In_ sai_acl_stage_t         table_stage,
                                                _Out_ mlnx_acl_field_type_t *table_fields_types,
                                                _Out_ sx_acl_key_t          *sx_keys,
                                                _Inout_ uint32_t            *sx_key_count);
static sai_status_t mlnx_acl_entry_fields_to_sx(_In_ const sai_attribute_t   *attr_list,
                                                _In_ uint32_t                 attr_count,
                                                _In_ uint32_t                 table_index,
                                                _Out_ sx_flex_acl_key_desc_t *sx_keys,
                                                _Inout_ uint32_t             *sx_key_count);
static sai_status_t mlnx_acl_field_types_check(_In_ mlnx_acl_field_type_t field_type);
static sai_status_t mlnx_acl_sx_keys_to_field_type(_In_ const sx_flex_acl_key_desc_t *sx_descs,
                                                   _In_ uint32_t                      sx_descs_count,
                                                   _Out_ mlnx_acl_field_type_t       *fields_types);
static sai_status_t mlnx_acl_field_types_to_extra_sx_keys(_In_ mlnx_acl_field_type_t fields_types,
                                                          _Out_ sx_acl_key_t        *sx_keys,
                                                          _Inout_ uint32_t          *sx_key_count) __attribute__((
                                                                                                                     unused));
static sai_status_t mlnx_acl_extra_key_descs_merge(_Inout_ sx_flex_acl_flex_rule_t   *rule,
                                                   _In_ const sx_flex_acl_key_desc_t *key_descs,
                                                   _In_ uint32_t                      key_desc_count);
static sai_status_t mlnx_acl_field_types_to_extra_sx_key_descs(_In_ mlnx_acl_field_type_t    fields_types,
                                                               _Out_ sx_flex_acl_key_desc_t *sx_keys,
                                                               _Inout_ uint32_t             *sx_key_count);
static sai_status_t mlnx_acl_entry_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                               _In_ const sai_attribute_value_t *value,
                                               _In_ uint32_t                     attr_index,
                                               _In_ uint32_t                     table_index,
                                               _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                               _Inout_ uint32_t                 *sx_key_count,
                                               _Inout_ mlnx_acl_field_type_t    *field_type);
static sai_status_t mlnx_acl_entry_field_to_sx_update(_In_ sai_acl_entry_attr_t          attr_id,
                                                      _In_ const sai_attribute_value_t  *value,
                                                      _In_ uint32_t                      attr_index,
                                                      _In_ uint32_t                      table_index,
                                                      _Out_ sx_flex_acl_key_desc_t      *sx_keys,
                                                      _Inout_ uint32_t                  *sx_key_count,
                                                      _Inout_ mlnx_acl_field_type_t     *field_type,
                                                      _In_ const sx_flex_acl_key_desc_t *prev_sx_keys,
                                                      _In_ uint32_t                      prev_sx_keys_count);
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
static sai_status_t mlnx_acl_ip_flags_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
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
static sai_status_t mlnx_acl_icmp_field_to_sx(_In_ sai_acl_entry_attr_t          attr_id,
                                              _In_ const sai_attribute_value_t  *value,
                                              _In_ uint32_t                      attr_index,
                                              _In_ uint32_t                      table_index,
                                              _Out_ sx_flex_acl_key_desc_t      *sx_keys,
                                              _Inout_ uint32_t                  *sx_key_count,
                                              _Inout_ mlnx_acl_field_type_t     *field_type,
                                              _In_ const sx_flex_acl_key_desc_t *prev_sx_keys,
                                              _In_ uint32_t                      prev_sx_keys_count);
static sai_status_t mlnx_acl_table_init_sp(_In_ uint32_t table_db_idx, _In_ bool is_table_dynamic, _In_ uint32_t size);
static sai_status_t mlnx_acl_table_deinit_sp(_In_ uint32_t table_db_idx);
static sai_status_t mlnx_acl_entry_offset_get_sp(_In_ uint32_t               table_db_idx,
                                                 _In_ uint32_t               entry_db_idx,
                                                 _In_ uint32_t               priority,
                                                 _Out_ sx_acl_rule_offset_t *sx_offset);
static sai_status_t mlnx_acl_entry_offset_del_sp(_In_ uint32_t             table_db_idx,
                                                 _In_ uint32_t             priority,
                                                 _In_ sx_acl_rule_offset_t offset);
static sai_status_t mlnx_acl_entry_prio_set_sp(_In_ uint32_t table_db_idx,
                                               _In_ uint32_t entry_db_idx,
                                               _In_ uint32_t sx_prio);
static sai_status_t mlnx_acl_init_sp(void);
static sai_status_t mlnx_acl_lazy_init_sp(void);
static sai_status_t mlnx_acl_deinit_sp(void);
static sai_status_t mlnx_acl_table_size_set_sp(_In_ uint32_t table_db_idx, _In_ uint32_t size);
static sai_status_t mlnx_acl_table_optimize_sp(_In_ uint32_t table_db_idx);
static sai_status_t mlnx_acl_sx_rule_prio_set_sp(_In_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t sx_prio);
static sai_status_t mlnx_acl_range_create_spc(_In_ sai_acl_range_type_t     type,
                                              _In_ const sai_u32_range_t   *range,
                                              _Out_ sx_acl_port_range_id_t *sx_range_id);
static sai_status_t mlnx_acl_range_remove_spc(_In_ sx_acl_port_range_id_t sx_range_id);
static sai_status_t mlnx_acl_range_attr_get_spc(_In_ sx_acl_port_range_id_t  sx_range_id,
                                                _In_ sai_attr_id_t           attr_id,
                                                _Out_ sai_attribute_value_t *value);
static sai_status_t mlnx_acl_table_init_sp2(_In_ uint32_t table_db_idx, _In_ bool is_table_dynamic,
                                            _In_ uint32_t size);
static sai_status_t mlnx_acl_table_deinit_sp2(_In_ uint32_t table_db_idx);
static sai_status_t mlnx_acl_entry_offset_get_sp2(_In_ uint32_t               table_db_idx,
                                                  _In_ uint32_t               entry_db_idx,
                                                  _In_ uint32_t               priority,
                                                  _Out_ sx_acl_rule_offset_t *sx_offset);
static sai_status_t mlnx_acl_entry_offset_del_sp2(_In_ uint32_t             table_db_idx,
                                                  _In_ uint32_t             priority,
                                                  _In_ sx_acl_rule_offset_t offset);
static sai_status_t mlnx_acl_entry_prio_set_sp2(_In_ uint32_t table_db_idx,
                                                _In_ uint32_t entry_db_idx,
                                                _In_ uint32_t sx_prio);
static sai_status_t mlnx_acl_init_sp2(void);
static sai_status_t mlnx_acl_deinit_sp2(void);
static sai_status_t mlnx_acl_table_size_set_sp2(_In_ uint32_t table_db_idx, _In_ uint32_t size);
static sai_status_t mlnx_acl_sx_rule_prio_set_sp2(_In_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t sx_prio);
static sai_status_t mlnx_acl_range_create_spc2(_In_ sai_acl_range_type_t     type,
                                               _In_ const sai_u32_range_t   *range,
                                               _Out_ sx_acl_port_range_id_t *sx_range_id);
static sai_status_t mlnx_acl_range_remove_spc2(_In_ sx_acl_port_range_id_t sx_range_id);
static sai_status_t mlnx_acl_range_attr_get_spc2(_In_ sx_acl_port_range_id_t  sx_range_id,
                                                 _In_ sai_attr_id_t           attr_id,
                                                 _Out_ sai_attribute_value_t *value);
static const mlnx_acl_cb_list_t               mlnx_acl_cb_sp = {
    mlnx_acl_table_init_sp,
    mlnx_acl_table_deinit_sp,
    mlnx_acl_entry_offset_get_sp,
    mlnx_acl_entry_offset_del_sp,
    mlnx_acl_entry_prio_set_sp,
    mlnx_acl_init_sp,
    mlnx_acl_lazy_init_sp,
    mlnx_acl_deinit_sp,
    mlnx_acl_table_size_set_sp,
    mlnx_acl_table_optimize_sp,
    mlnx_acl_sx_rule_prio_set_sp,
    mlnx_acl_range_create_spc,
    mlnx_acl_range_remove_spc,
    mlnx_acl_range_attr_get_spc,
};
static const mlnx_acl_cb_list_t               mlnx_acl_cb_sp2 = {
    mlnx_acl_table_init_sp2,
    mlnx_acl_table_deinit_sp2,
    mlnx_acl_entry_offset_get_sp2,
    mlnx_acl_entry_offset_del_sp2,
    mlnx_acl_entry_prio_set_sp2,
    mlnx_acl_init_sp2,
    NULL, /* mlnx_acl_lazy_init_f */
    mlnx_acl_deinit_sp2,
    mlnx_acl_table_size_set_sp2,
    NULL, /* mlnx_acl_table_optimize_f */
    mlnx_acl_sx_rule_prio_set_sp2,
    mlnx_acl_range_create_spc2,
    mlnx_acl_range_remove_spc2,
    mlnx_acl_range_attr_get_spc2,
};
static mlnx_acl_sp2_table_db_t                acl_sp2_table_db = {.tables = NULL, .is_inited = false};
static const mlnx_acl_cb_list_t              *mlnx_acl_cb = NULL;
static const mlnx_acl_single_key_field_info_t mlnx_acl_single_key_fields_info[] = {
    /* L2 */
    [SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_SMAC,
                                                                  smac,
                                                                  MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_DMAC,
                                                                  dmac,
                                                                  MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_ETHERTYPE,
                                                                     ethertype,
                                                                     MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_ETHER_TYPE] = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_INNER_ETHERTYPE,
                                                                        inner_ethertype,
                                                                        MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_VLAN_ID,
                                                                        vlan_id,
                                                                        MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_PCP,
                                                                         pcp,
                                                                         MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI] = MLNX_ACL_FIELD_L2_DEFINE(FLEX_ACL_KEY_DEI,
                                                                         dei,
                                                                         MLNX_ACL_SUPPORTED_CHIP_ANY),
    /* [SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID] = MLNX_ACL_FIELD_INNER_VLAN_DEFINE(FLEX_ACL_KEY_INNER_VLAN_ID, inner_vlan_id), */
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI] = MLNX_ACL_FIELD_INNER_VLAN_DEFINE(FLEX_ACL_KEY_INNER_PCP,
                                                                                 inner_pcp,
                                                                                 MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI] = MLNX_ACL_FIELD_INNER_VLAN_DEFINE(FLEX_ACL_KEY_INNER_DEI,
                                                                                 inner_dei,
                                                                                 MLNX_ACL_SUPPORTED_CHIP_ANY),

    /* L3 */
    [SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] =
        MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_SIP, sip, MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] =
        MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_DIP, dip, MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = MLNX_ACL_FIELD_IPV6_DEFINE(FLEX_ACL_KEY_SIPV6,
                                                                     sipv6,
                                                                     MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = MLNX_ACL_FIELD_IPV6_DEFINE(FLEX_ACL_KEY_DIPV6,
                                                                     dipv6,
                                                                     MLNX_ACL_SUPPORTED_CHIP_ANY),

    [SAI_ACL_ENTRY_ATTR_FIELD_TTL] = MLNX_ACL_FIELD_IP_DEFINE(FLEX_ACL_KEY_TTL,
                                                              ttl,
                                                              MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL] = MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_IP_PROTO,
                                                                        ip_proto,
                                                                        MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER] = MLNX_ACL_FIELD_IPV6_DEFINE(FLEX_ACL_KEY_IP_PROTO,
                                                                             ip_proto,
                                                                             MLNX_ACL_SUPPORTED_CHIP_ANY),

    [SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = MLNX_ACL_FIELD_IP_DEFINE(FLEX_ACL_KEY_DSCP, dscp, MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ECN] = MLNX_ACL_FIELD_IPV4_DEFINE(FLEX_ACL_KEY_ECN, ecn, MLNX_ACL_SUPPORTED_CHIP_ANY),
    /* [SAI_ACL_ENTRY_ATTR_FIELD_TOS] */

    /* Inner L3 */
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL] = MLNX_ACL_FIELD_INNER_IP_DEFINE(FLEX_ACL_KEY_INNER_IP_PROTO,
                                                                                  inner_ip_proto,
                                                                                  MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP] = MLNX_ACL_FIELD_INNER_IPV4_DEFINE(FLEX_ACL_KEY_INNER_SIP,
                                                                               inner_sip,
                                                                               MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP] = MLNX_ACL_FIELD_INNER_IPV4_DEFINE(FLEX_ACL_KEY_INNER_DIP,
                                                                               inner_dip,
                                                                               MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6] =
        MLNX_ACL_FIELD_INNER_IPV6_DEFINE(FLEX_ACL_KEY_INNER_SIPV6, inner_sipv6, MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6] =
        MLNX_ACL_FIELD_INNER_IPV6_DEFINE(FLEX_ACL_KEY_INNER_DIPV6, inner_dipv6, MLNX_ACL_SUPPORTED_CHIP_ANY),

    /* L4 */
    [SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] =
        MLNX_ACL_FIELD_TCP_UDP_DEFINE(FLEX_ACL_KEY_L4_SOURCE_PORT, l4_source_port, MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT] = MLNX_ACL_FIELD_TCP_UDP_DEFINE(FLEX_ACL_KEY_L4_DESTINATION_PORT,
                                                                           l4_destination_port,
                                                                           MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS] = MLNX_ACL_FIELD_TCP_DEFINE(FLEX_ACL_KEY_TCP_CONTROL,
                                                                     tcp_control,
                                                                     MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE] = MLNX_ACL_FIELD_ICMPV4_DEFINE(FLEX_ACL_KEY_L4_SOURCE_PORT,
                                                                        l4_source_port,
                                                                        MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE] = MLNX_ACL_FIELD_ICMPV4_DEFINE(FLEX_ACL_KEY_L4_SOURCE_PORT,
                                                                        l4_source_port,
                                                                        MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE] = MLNX_ACL_FIELD_ICMPV6_DEFINE(FLEX_ACL_KEY_L4_SOURCE_PORT,
                                                                          l4_source_port,
                                                                          MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE] = MLNX_ACL_FIELD_ICMPV6_DEFINE(FLEX_ACL_KEY_L4_SOURCE_PORT,
                                                                          l4_source_port,
                                                                          MLNX_ACL_SUPPORTED_CHIP_ANY),

    /* RoCE group */
    [SAI_ACL_ENTRY_ATTR_FIELD_BTH_OPCODE] = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_ROCE_BTH_OPCODE,
                                                                  bth_opcode,
                                                                  MLNX_ACL_SUPPORTED_CHIP_ANY),

    /* Inner L4 */
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT] =
        MLNX_ACL_FIELD_INNER_L4_DEFINE(FLEX_ACL_KEY_INNER_L4_SOURCE_PORT,
                                       inner_l4_source_port,
                                       MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT] =
        MLNX_ACL_FIELD_INNER_L4_DEFINE(FLEX_ACL_KEY_INNER_L4_DESTINATION_PORT,
                                       inner_l4_destination_port,
                                       MLNX_ACL_SUPPORTED_CHIP_ANY),

    /* Other */
    [SAI_ACL_ENTRY_ATTR_FIELD_TC] = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_SWITCH_PRIO,
                                                          switch_prio,
                                                          MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META] = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_USER_TOKEN,
                                                                     user_token,
                                                                     MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE] = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_L4_PORT_RANGE,
                                                                      l4_port_range,
                                                                      MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI] = MLNX_ACL_FIELD_DEFINE(FLEX_ACL_KEY_VNI_KEY,
                                                                  vni_key,
                                                                  MLNX_ACL_SUPPORTED_CHIP_ANY),
};
static const size_t                           mlnx_acl_single_key_field_max_id = ARRAY_SIZE(
    mlnx_acl_single_key_fields_info);
static const mlnx_acl_multi_key_field_info_t mlnx_acl_multi_key_fields_info[] = {
    [SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_VLAN_TAGGED, FLEX_ACL_KEY_INNER_VLAN_VALID),
        MLNX_ACL_FIELD_TYPE_EMPTY,
        MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_TOS] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_DSCP, FLEX_ACL_KEY_ECN),
        MLNX_ACL_FIELD_TYPE_IPV4,
        MLNX_ACL_SUPPORTED_CHIP_ANY),
#ifndef MLNX_ACL_L3_TYPE_REDUCED
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        3,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_IP_OK,
                                FLEX_ACL_KEY_IS_IP_V4,
                                FLEX_ACL_KEY_L3_TYPE),
        MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_IPV6 | MLNX_ACL_FIELD_TYPE_ARP,
        MLNX_ACL_SUPPORTED_CHIP_ANY),
#else /* MLNX_ACL_L3_TYPE_REDUCED */
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_IP_OK,
                                FLEX_ACL_KEY_L3_TYPE),
        MLNX_ACL_FIELD_TYPE_IP | MLNX_ACL_FIELD_TYPE_IPV4 | MLNX_ACL_FIELD_TYPE_IPV6 | MLNX_ACL_FIELD_TYPE_ARP,
        MLNX_ACL_SUPPORTED_CHIP_ANY),
#endif /* MLNX_ACL_L3_TYPE_REDUCED */
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_IP_FRAGMENTED, FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST),
        MLNX_ACL_FIELD_TYPE_IPV4,
        MLNX_ACL_SUPPORTED_CHIP_ANY),
    [SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS] = MLNX_ACL_MULTI_KEY_FIELD_INFO(
        2,
        MLNX_ACL_ENTRY_KEY_LIST(FLEX_ACL_KEY_IP_DONT_FRAGMENT, FLEX_ACL_KEY_IP_MORE_FRAGMENTS),
        MLNX_ACL_FIELD_TYPE_IPV4,
        MLNX_ACL_SUPPORTED_CHIP_SPC2 | MLNX_ACL_SUPPORTED_CHIP_SPC3),
};
static const size_t                          mlnx_acl_multi_key_field_max_id = ARRAY_SIZE(
    mlnx_acl_multi_key_fields_info);
static const sai_attr_id_t mlnx_acl_non_trivial_fields[] = {
    SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
    SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
    SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
    SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
    SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION,
};
static const size_t        mlnx_acl_non_trivial_field_count =
    ARRAY_SIZE(mlnx_acl_non_trivial_fields);
static sai_status_t mlnx_acl_action_eg_block_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                   _In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ const acl_table_db_t        *table,
                                                   _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_eg_block_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                    _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                    _In_ const acl_entry_db_t          *entry,
                                                    _In_ const acl_table_db_t          *table,
                                                    _In_ uint32_t                       attr_index,
                                                    _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_redirect_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                   _In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ const acl_table_db_t        *table,
                                                   _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_redirect_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                    _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                    _In_ const acl_entry_db_t          *entry,
                                                    _In_ const acl_table_db_t          *table,
                                                    _In_ uint32_t                       attr_index,
                                                    _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_redirect_list_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                        _In_ const sai_acl_action_data_t *action_data,
                                                        _In_ uint32_t                     attr_index,
                                                        _In_ const acl_table_db_t        *table,
                                                        _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                        _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                        _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_endpoint_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                   _In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ const acl_table_db_t        *table,
                                                   _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_endpoint_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                    _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                    _In_ const acl_entry_db_t          *entry,
                                                    _In_ const acl_table_db_t          *table,
                                                    _In_ uint32_t                       attr_index,
                                                    _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_flood_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                _In_ const sai_acl_action_data_t *action_data,
                                                _In_ uint32_t                     attr_index,
                                                _In_ const acl_table_db_t        *table,
                                                _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_flood_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                 _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                 _In_ const acl_entry_db_t          *entry,
                                                 _In_ const acl_table_db_t          *table,
                                                 _In_ uint32_t                       attr_index,
                                                 _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_pkt_act_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_pkt_act_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_counter_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_counter_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_mirror_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                 _In_ const sai_acl_action_data_t *action_data,
                                                 _In_ uint32_t                     attr_index,
                                                 _In_ const acl_table_db_t        *table,
                                                 _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                 _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                 _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_policer_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_policer_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_mirror_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                  _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                  _In_ const acl_entry_db_t          *entry,
                                                  _In_ const acl_table_db_t          *table,
                                                  _In_ uint32_t                       attr_index,
                                                  _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_dec_ttl_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_dec_ttl_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_vlan_prio_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                    _In_ const sai_acl_action_data_t *action_data,
                                                    _In_ uint32_t                     attr_index,
                                                    _In_ const acl_table_db_t        *table,
                                                    _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                    _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                    _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_vlan_prio_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                     _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                     _In_ const acl_entry_db_t          *entry,
                                                     _In_ const acl_table_db_t          *table,
                                                     _In_ uint32_t                       attr_index,
                                                     _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_meta_to_sx(_In_ sai_acl_entry_attr_t         action,
                                               _In_ const sai_acl_action_data_t *action_data,
                                               _In_ uint32_t                     attr_index,
                                               _In_ const acl_table_db_t        *table,
                                               _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                               _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                               _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_meta_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                _In_ const acl_entry_db_t          *entry,
                                                _In_ const acl_table_db_t          *table,
                                                _In_ uint32_t                       attr_index,
                                                _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_action_ip_to_sx(_In_ sai_acl_entry_attr_t         action,
                                             _In_ const sai_acl_action_data_t *action_data,
                                             _In_ uint32_t                     attr_index,
                                             _In_ const acl_table_db_t        *table,
                                             _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                             _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                             _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_action_ip_to_sai(_In_ sai_acl_entry_attr_t           action,
                                              _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                              _In_ const acl_entry_db_t          *entry,
                                              _In_ const acl_table_db_t          *table,
                                              _In_ uint32_t                       attr_index,
                                              _Out_ sai_acl_action_data_t        *action_data);
static sai_status_t mlnx_acl_redirect_endpoint_set(_In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ bool                         is_redirect_endpoint_needed,
                                                   _Inout_ uint32_t                  redirect_action_idx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count);
static sai_status_t mlnx_acl_entry_action_fn_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static mlnx_acl_action_info_t mlnx_acl_action_info[] = {
    [SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_BLOCK_PORT_LIST] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_eg_block_to_sx, mlnx_acl_action_eg_block_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT] =
        MLNX_ACL_ACTION_INFO_DEFINE_INGRESS_WITH_FNS(mlnx_acl_action_redirect_to_sx, mlnx_acl_action_redirect_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_ENDPOINT_IP] =
        MLNX_ACL_ACTION_INFO_DEFINE_INGRESS_WITH_FNS(mlnx_acl_action_endpoint_to_sx, mlnx_acl_action_endpoint_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST] =
        MLNX_ACL_ACTION_INFO_DEFINE_INGRESS_WITH_FNS(mlnx_acl_action_redirect_list_to_sx,
                                                     mlnx_acl_action_redirect_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_pkt_act_to_sx, mlnx_acl_action_pkt_act_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_FLOOD] =
        MLNX_ACL_ACTION_INFO_DEFINE_INGRESS_WITH_FNS(mlnx_acl_action_flood_to_sx, mlnx_acl_action_flood_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_counter_to_sx, mlnx_acl_action_counter_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_mirror_to_sx, mlnx_acl_action_mirror_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS] =
        MLNX_ACL_ACTION_INFO_DEFINE_EGRESS_WITH_FNS(mlnx_acl_action_mirror_to_sx, mlnx_acl_action_mirror_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_policer_to_sx, mlnx_acl_action_policer_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_PRIO, action_set_prio),
    [SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_dec_ttl_to_sx, mlnx_acl_action_dec_ttl_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_COLOR, action_set_color),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_INNER_VLAN_ID, action_set_inner_vlan_id),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_vlan_prio_to_sx, mlnx_acl_action_vlan_prio_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_ID, action_set_outer_vlan_id),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_vlan_prio_to_sx, mlnx_acl_action_vlan_prio_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_SRC_MAC, action_set_src_mac),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_DST_MAC, action_set_dst_mac),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_DSCP, action_set_dscp),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD(SX_FLEX_ACL_ACTION_SET_ECN, action_set_ecn),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS(mlnx_acl_action_meta_to_sx, mlnx_acl_action_meta_to_sai),

    [SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS_SPC2_3(mlnx_acl_action_ip_to_sx, mlnx_acl_action_ip_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS_SPC2_3(mlnx_acl_action_ip_to_sx, mlnx_acl_action_ip_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS_SPC2_3(mlnx_acl_action_ip_to_sx, mlnx_acl_action_ip_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FNS_SPC2_3(mlnx_acl_action_ip_to_sx, mlnx_acl_action_ip_to_sai),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD_SPC2(SX_FLEX_ACL_ACTION_SET_L4_SRC_PORT, action_set_l4_src_port),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT] =
        MLNX_ACL_ACTION_INFO_DEFINE_WITH_FIELD_SPC2(SX_FLEX_ACL_ACTION_SET_L4_DST_PORT, action_set_l4_dst_port),
};
static const size_t           mlnx_acl_action_info_count = ARRAY_SIZE(mlnx_acl_action_info);
const mlnx_acl_action_info_t* mlnx_acl_action_info_get(_In_ sai_acl_entry_attr_t action_id)
{
    const mlnx_acl_action_info_t *info;

    assert((SAI_ACL_ENTRY_ATTR_ACTION_START <= action_id) && (action_id <= SAI_ACL_ENTRY_ATTR_ACTION_END));

    if (mlnx_acl_action_info_count <= action_id) {
        return NULL;
    }

    info = &mlnx_acl_action_info[action_id];

    /* Either sx_type or convert_fn should be defined for action */
    if (MLNX_ACL_ACTION_INFO_UNDEFINED(info)) {
        return NULL;
    }

    return info;
}

static sai_status_t mlnx_acl_action_info_find(_In_ sai_acl_entry_attr_t            action_id,
                                              _In_ uint32_t                        attr_index,
                                              _Out_ const mlnx_acl_action_info_t **action_info)
{
    const mlnx_acl_action_info_t *info;
    const char                   *action_name = "Invalid";

    assert((SAI_ACL_ENTRY_ATTR_ACTION_START <= action_id) && (action_id <= SAI_ACL_ENTRY_ATTR_ACTION_END));

    info = mlnx_acl_action_info_get(action_id);
    if (!info) {
        sai_attribute_short_name_fetch(SAI_OBJECT_TYPE_ACL_ENTRY, action_id, &action_name);
        SX_LOG_ERR("Failed to find action info for action %s (%d)\n", action_name, action_id);
        *action_info = NULL;
        return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + attr_index;
    }

    *action_info = info;

    return SAI_STATUS_SUCCESS;
}

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
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_table_attrib_get, (void*)SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST,
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
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_ETHER_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_ETHER_TYPE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_INNER_IP_PROTOCOL,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_INNER_IP_PROTOCOL,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT,
      NULL, NULL },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT,
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
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
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
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE,
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
    { SAI_ACL_TABLE_ATTR_FIELD_BTH_OPCODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_TABLE_ATTR_FIELD_BTH_OPCODE,
      NULL, NULL },
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(0),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(1),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(2),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(3),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(4),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(5),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(6),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(7),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(8),
    MLNX_ACL_TABLE_UDF_ATTR_VENDOR_DATA(9),
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
    { SAI_ACL_TABLE_ATTR_FIELD_TUNNEL_VNI,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_acl_table_fields_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_ENTRY_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_acl_table_entry_list_get, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_acl_table_available_entries_get, NULL,
      NULL, NULL },
    { SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_COUNTER,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_acl_table_available_counters_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static const mlnx_attr_enum_info_t        acl_table_enum_info[] = {
    [SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST] = ATTR_ENUM_VALUES_ALL(),
    [SAI_ACL_TABLE_ATTR_ACL_STAGE] = ATTR_ENUM_VALUES_LIST(
        SAI_ACL_STAGE_INGRESS,
        SAI_ACL_STAGE_EGRESS
        ),
    [SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = ATTR_ENUM_VALUES_LIST(
        SAI_ACL_BIND_POINT_TYPE_PORT,
        SAI_ACL_BIND_POINT_TYPE_LAG,
        SAI_ACL_BIND_POINT_TYPE_VLAN,
        SAI_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE
        ),
    [SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE,
        SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE,
        SAI_ACL_RANGE_TYPE_PACKET_LENGTH
        ),
};
const mlnx_obj_type_attrs_info_t          mlnx_acl_table_obj_type_info =
{ acl_table_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(acl_table_enum_info)};

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
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_ETHER_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_ETHER_TYPE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_ETHER_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT },
    { SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT },
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
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_ip_flags_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS, },
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
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE },
    { SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE },
    { SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN,
      { true, false, true, true },
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
    { SAI_ACL_ENTRY_ATTR_FIELD_BTH_OPCODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_BTH_OPCODE,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_BTH_OPCODE },
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
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(0),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(1),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(2),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(3),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(4),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(5),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(6),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(7),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(8),
    MLNX_ACL_ENTRY_UDF_ATTR_VENDOR_DATA(9),
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
    { SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_single_key_field_get, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI,
      mlnx_acl_entry_field_set, (void*)SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
      mlnx_acl_entry_action_redirect_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT },
    { SAI_ACL_ENTRY_ATTR_ACTION_ENDPOINT_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_ENDPOINT_IP,
      mlnx_acl_entry_action_endpoint_set, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST,
      mlnx_acl_entry_action_redirect_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST },
    { SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,
      mlnx_acl_entry_packet_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION },
    { SAI_ACL_ENTRY_ATTR_ACTION_FLOOD,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_FLOOD,
      mlnx_acl_entry_action_redirect_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_FLOOD },
    { SAI_ACL_ENTRY_ATTR_ACTION_COUNTER,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_COUNTER,
      mlnx_acl_entry_action_counter_set, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS,
      mlnx_acl_entry_action_mirror_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS },
    {  SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS,
       { true, false, true, true },
       { true, false, true, true },
       mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS,
       mlnx_acl_entry_action_mirror_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER },
    { SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_TC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_TC,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_TC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_ID },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI,
      mlnx_acl_entry_action_vlan_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC,
      mlnx_acl_entry_action_mac_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC,
      mlnx_acl_entry_action_mac_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP,
      mlnx_acl_entry_action_ip_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP,
      mlnx_acl_entry_action_ip_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6,
      mlnx_acl_entry_action_ip_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6,
      mlnx_acl_entry_action_ip_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6 },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT,
      mlnx_acl_entry_action_l4port_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_entry_action_trivial_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT,
      mlnx_acl_entry_action_l4port_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT },
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
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA,
      { true, false, true, true},
      { true, false, true, true},
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA,
      mlnx_acl_entry_action_set, (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA },
    { SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_BLOCK_PORT_LIST,
      { true, false, true, true},
      { true, false, true, true},
      mlnx_acl_entry_action_fn_get, (void*)SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_BLOCK_PORT_LIST,
      mlnx_acl_entry_action_egress_block_port_set, NULL },
    { SAI_ACL_ENTRY_ATTR_ACTION_SET_USER_TRAP_ID,
      { false, false, false, false},
      { true, false, true, true},
      NULL, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static const mlnx_attr_enum_info_t        acl_entry_enum_info[] = {
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_ACL_IP_TYPE_ANY,
        SAI_ACL_IP_TYPE_IP,
        SAI_ACL_IP_TYPE_NON_IP,
        SAI_ACL_IP_TYPE_IPV4ANY,
        SAI_ACL_IP_TYPE_NON_IPV4,
        SAI_ACL_IP_TYPE_IPV6ANY,
        SAI_ACL_IP_TYPE_ARP,
        ),
    [SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG] = ATTR_ENUM_VALUES_ALL(),
    [SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN] = ATTR_ENUM_VALUES_ALL(),
    [SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR] = ATTR_ENUM_VALUES_ALL(),
    [SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_acl_entry_obj_type_info =
{ acl_entry_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(acl_entry_enum_info)};
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
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static const mlnx_attr_enum_info_t        acl_range_enum_info[] = {
    [SAI_ACL_RANGE_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_ACL_RANGE_TYPE_PACKET_LENGTH,
        SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE,
        SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE
        ),
};
const mlnx_obj_type_attrs_info_t          mlnx_acl_range_obj_type_info =
{ acl_range_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(acl_range_enum_info)};
static const sai_vendor_attribute_entry_t acl_counter_vendor_attribs[] = {
    { SAI_ACL_COUNTER_ATTR_TABLE_ID,
      {true, true, false, true },
      {true, true, false, true },
      mlnx_acl_counter_attr_get, (void*)SAI_ACL_COUNTER_ATTR_TABLE_ID,
      NULL, NULL },
    { SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_counter_attr_get, (void*)SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
      NULL, NULL },
    { SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_acl_counter_attr_get, (void*)SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
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
      mlnx_acl_counter_set, (void*)SAI_ACL_COUNTER_ATTR_BYTES },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
const mlnx_obj_type_attrs_info_t          mlnx_acl_counter_obj_type_info =
{ acl_counter_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY()};
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
      NULL, NULL },
    { SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_acl_group_member_list_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static const mlnx_attr_enum_info_t        acl_table_group_enum_info[] = {
    [SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST] = ATTR_ENUM_VALUES_LIST(
        SAI_ACL_BIND_POINT_TYPE_PORT,
        SAI_ACL_BIND_POINT_TYPE_LAG,
        SAI_ACL_BIND_POINT_TYPE_VLAN,
        SAI_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE
        ),
    [SAI_ACL_TABLE_GROUP_ATTR_TYPE] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_acl_table_group_obj_type_info =
{ acl_group_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(acl_table_group_enum_info)};
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
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
const mlnx_obj_type_attrs_info_t          mlnx_acl_table_group_mem_obj_type_info =
{ acl_group_member_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY()};
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

sai_status_t mlnx_acl_deinit(void)
{
    sai_status_t status;

    SX_LOG_ENTER();

    status = mlnx_acl_rpc_thread_close();
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to close ACL RPC thread\n");
        return status;
    }

    status = mlnx_acl_rpc_client_close();
    if (SAI_ERR(status)) {
        return status;
    }

    if (mlnx_acl_cb->deinit) {
        status = mlnx_acl_cb->deinit();
        if (SAI_ERR(status)) {
            return status;
        }
    }

    mlnx_acl_table_locks_deinit();

#ifndef _WIN32
    if (0 != pthread_mutex_destroy(&sai_acl_db->acl_settings_tbl->cond_mutex)) {
        SX_LOG_ERR("Failed to destroy cond_mutex\n");
        return SAI_STATUS_FAILURE;
    }

    if (0 != pthread_key_delete(pthread_sx_handle_key)) {
        SX_LOG_ERR("Failed to delete pthread_key\n");
        return SAI_STATUS_FAILURE;
    }
#endif /* _WIN32 */

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_acl_disconnect(void)
{
    sai_status_t status;

    SX_LOG_DBG("Deinitializing ACL on swictch disconnect\n");

    status = mlnx_acl_psort_opt_queue_client_close();
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_rpc_client_close();
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_lazy_init(void)
{
    sai_status_t status;

    if (sai_acl_db->acl_settings_tbl->lazy_initialized) {
        return SAI_STATUS_SUCCESS;
    }

    if (mlnx_acl_cb->lazy_init) {
        status = mlnx_acl_cb->lazy_init();
        if (SAI_ERR(status)) {
            return status;
        }
    }

#ifndef _WIN32
    /* Wake up RPC thread */
    acl_cond_mutex_lock();
    sai_acl_db->acl_settings_tbl->rpc_thread_start_flag = true;
    if (0 != pthread_cond_signal(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond)) {
        SX_LOG_ERR("Failed to signal condition variable to wake up ACL RPC thread\n");
        acl_cond_mutex_unlock();
        return SAI_STATUS_FAILURE;
    }
    acl_cond_mutex_unlock();
#endif /* _WIN32 */

    sai_acl_db->acl_settings_tbl->lazy_initialized = true;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_psort_thread_unblock(void)
{
    sai_status_t   status;
    const uint32_t unblock_msg = ACL_QUEUE_UNBLOCK_MSG;

    status = mlnx_acl_psort_opt_queue_client_create();
    if (SAI_ERR(status)) {
        return status;
    }

#ifndef _WIN32
    if (-1 ==
        mq_send(psort_opt_queue_client, (const char*)&unblock_msg, sizeof(unblock_msg), ACL_QUEUE_UNBLOCK_MSG_PRIO)) {
        if (EAGAIN == errno) {
            /* Not an issue. If queue is full it's going to get unblocked anyway */
            SX_LOG_NTC("Failed to send unblock message to pSort queue - queue is full\n");
            return SAI_STATUS_SUCCESS;
        }

        SX_LOG_ERR("Failed to send unblock msg to pSort queue - %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
#endif /* _WIN32 */

    return SAI_STATUS_SUCCESS;
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

static sai_status_t acl_psort_background_close(void)
{
#ifndef _WIN32
    sai_status_t status;

    sai_acl_db->acl_settings_tbl->psort_thread_stop_flag = true;

    if (sai_acl_db->acl_settings_tbl->psort_thread_start_flag) {
        status = mlnx_acl_psort_thread_unblock();
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = mlnx_acl_psort_thread_wake();
        if (SAI_ERR(status)) {
            return status;
        }
    }

    cl_thread_destroy(&psort_thread);

    if (0 != pthread_cond_destroy(&sai_acl_db->acl_settings_tbl->psort_thread_init_cond)) {
        SX_LOG_ERR("Failed to destroy cond variable\n");
        return SAI_STATUS_FAILURE;
    }
#endif

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_rpc_thread_close(void)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    acl_rpc_info_t rpc_info;

    if (false == sai_acl_db->acl_settings_tbl->rpc_thread_start_flag) {
        sai_acl_db->acl_settings_tbl->rpc_thread_stop_flag = true;
        acl_cond_mutex_lock();
        sai_acl_db->acl_settings_tbl->rpc_thread_start_flag = true;
        if (0 != pthread_cond_signal(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond)) {
            SX_LOG_ERR("Failed to signal condition var to wake up RPC thread\n");
            status = SAI_STATUS_FAILURE;
        }
        acl_cond_mutex_unlock();
    } else {
        rpc_info.type = ACL_RPC_TERMINATE_THREAD;
        status = mlnx_acl_rpc_call(&rpc_info);
    }

    cl_thread_destroy(&rpc_thread);

    if (0 != pthread_cond_destroy(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond)) {
        SX_LOG_ERR("Failed to destroy cond variable\n");
        status = SAI_STATUS_FAILURE;
    }
#endif

    return status;
}

static sai_status_t mlnx_acl_rpc_client_close(void)
{
#ifndef _WIN32
    int st;

    if (-1 != rpc_cl_socket) {
        st = close(rpc_cl_socket);
        if (0 != st) {
            SX_LOG_ERR("Failed to close ACL RPC socket - %s\n", strerror(errno));
            return SAI_STATUS_FAILURE;
        }
    }
#endif

    return SAI_STATUS_SUCCESS;
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

static void mlnx_acl_table_locks_deinit(void)
{
    uint32_t ii;

    for (ii = 0; ii < ACL_TABLE_DB_SIZE; ii++) {
        if (acl_db_table(ii).is_lock_inited) {
            cl_plock_destroy(&acl_db_table(ii).lock);
        }
    }
}

static sai_acl_action_type_t mlnx_acl_entry_action_attr_to_action_type(_In_ sai_acl_entry_attr_t action)
{
    assert((SAI_ACL_ENTRY_ATTR_ACTION_START <= action) && (action <= SAI_ACL_ENTRY_ATTR_ACTION_END));

    return (sai_acl_action_type_t)action - SAI_ACL_ENTRY_ATTR_ACTION_START;
}

static sai_status_t mlnx_acl_stage_action_types_get(_In_ mlnx_acl_supported_stage_t stage,
                                                    _Out_ int32_t                  *action_types,
                                                    _Inout_ uint32_t               *count)
{
    sai_acl_entry_attr_t          action_attr;
    const mlnx_acl_action_info_t *action_info;
    uint32_t                      action_types_count;

    assert(stage <= MLNX_ACL_SUPPORTED_STAGE_MAX);
    assert(count);
    assert(!action_types || (*count == ACL_MAX_ACTIONS_COUNT));

    action_types_count = 0;
    for (action_attr = SAI_ACL_ENTRY_ATTR_ACTION_START; action_attr <= SAI_ACL_ENTRY_ATTR_ACTION_END; action_attr++) {
        action_info = mlnx_acl_action_info_get(action_attr);
        if (!action_info) {
            continue;
        }

        if (!(action_info->supported_chip & MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(g_sai_db_ptr->sx_chip_type))) {
            continue;
        }

        /* SDK allows ingress mirror on egress rif stage but we don't expose it to capability since it's only for rif */
        if ((action_attr == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS) && (stage == MLNX_ACL_SUPPORTED_STAGE_EGRESS)) {
            continue;
        }

        if ((stage == MLNX_ACL_SUPPORTED_STAGE_BOTH) ||
            (action_info->supported_stage == MLNX_ACL_SUPPORTED_STAGE_BOTH) ||
            (stage == action_info->supported_stage)) {
            if (action_types) {
                action_types[action_types_count] = mlnx_acl_entry_action_attr_to_action_type(action_attr);
            }
            action_types_count++;
        }
    }

    *count = action_types_count;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_acl_stage_action_types_list_get(_In_ sai_acl_stage_t stage, _Out_ sai_s32_list_t *list)
{
    sai_status_t status;
    int32_t      action_types[ACL_MAX_ACTIONS_COUNT] = {0};
    uint32_t     action_types_count;

    assert((stage == SAI_ACL_STAGE_INGRESS) || (stage == SAI_ACL_STAGE_EGRESS));
    assert(list);

    action_types_count = ARRAY_SIZE(action_types);
    status = mlnx_acl_stage_action_types_get((mlnx_acl_supported_stage_t)stage,
                                             action_types,
                                             &action_types_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return mlnx_fill_s32list(action_types, action_types_count, list);
}

uint32_t mlnx_acl_action_types_count_get(void)
{
    sai_status_t status;
    uint32_t     action_types_count;

    status = mlnx_acl_stage_action_types_get(MLNX_ACL_SUPPORTED_STAGE_BOTH, NULL, &action_types_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return action_types_count;
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
    sai_status_t   status;
    uint32_t       acl_table_index, bind_point_type_count;
    const int32_t *bind_point_types;

    SX_LOG_ENTER();

    assert((SAI_ACL_TABLE_ATTR_ACL_STAGE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_SIZE == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN == (int64_t)arg) ||
           (SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST == (int64_t)arg));

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
        value->u32 = ACL_SX_REG_SIZE_TO_TABLE_SIZE(acl_db_table(acl_table_index).region_size);
        break;

    case SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST:
        bind_point_type_count = acl_db_table(acl_table_index).bind_point_types.count;
        bind_point_types = (const int32_t*)acl_db_table(acl_table_index).bind_point_types.types;
        status = mlnx_fill_s32list(bind_point_types, bind_point_type_count, &value->s32list);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    case SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION:
        value->booldata = acl_db_table(acl_table_index).is_ip_ident_used;
        break;

    case SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST:
        status = mlnx_acl_stage_action_types_list_get(acl_db_table(acl_table_index).stage, &value->s32list);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;
    }

out:
    acl_table_unlock(acl_table_index);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_udf_attrib_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t  status = SAI_STATUS_SUCCESS;
    sai_attr_id_t attr_id;
    uint32_t      acl_table_index, udf_group_index;

    SX_LOG_ENTER();

    attr_id = (int32_t)(int64_t)arg;

    assert(attr_id <= MLNX_UDF_ACL_ATTR_MAX_ID);

    status = extract_acl_table_index(key->key.object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    udf_group_index = attr_id;

    acl_table_read_lock(acl_table_index);

    if (acl_db_table(acl_table_index).udf_group_list[udf_group_index].is_set) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_UDF_GROUP,
                                    acl_db_table(acl_table_index).udf_group_list[udf_group_index].udf_group_db_index,
                                    NULL, &value->oid);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        value->oid = SAI_NULL_OBJECT_ID;
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
    uint32_t     acl_table_index;

    SX_LOG_ENTER();

    assert(SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE == (int64_t)arg);

    status = extract_acl_table_index(key->key.object_id, &acl_table_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_fill_s32list((int32_t*)acl_db_table(acl_table_index).range_types,
                               acl_db_table(acl_table_index).range_type_count,
                               &value->s32list);

    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_entry_list_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t     status;
    sai_object_id_t *entry_list = NULL;
    uint32_t         table_index, entries_count, entry_index;

    SX_LOG_ENTER();

    status = extract_acl_table_index(key->key.object_id, &table_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_global_lock();

    entry_list = calloc(acl_db_table(table_index).created_entry_count, sizeof(sai_object_id_t));
    if (!entry_list) {
        SX_LOG_ERR("Failed to allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    entries_count = 0;
    entry_index = acl_db_table(table_index).head_entry_index;

    while (entry_index != ACL_INVALID_DB_INDEX) {
        if (!acl_db_entry(entry_index).is_used) {
            SX_LOG_ERR("Invalid ACL DB state - entry (%d) that belongs to table %lx marked as not used\n",
                       entry_index,
                       key->key.object_id);
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        status = acl_create_entry_object_id(&entry_list[entries_count], entry_index, table_index);
        if (SAI_ERR(status)) {
            goto out;
        }

        entries_count++;
        entry_index = acl_db_entry(entry_index).next_entry_index;
    }

    status = mlnx_fill_objlist(entry_list, entries_count, &value->objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_global_unlock();
    free(entry_list);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_dynamic_table_max_entries_get(_In_ uint32_t acl_table_id, _Out_ uint32_t *entries)
{
    sx_status_t            sx_status;
    rm_sdk_table_type_e    table_type;
    sx_acl_flex_key_attr_t key_attr;

    assert(entries);

    memset(&key_attr, 0, sizeof(key_attr));

    sx_status = sx_api_acl_flex_key_attr_get(gh_sdk, acl_db_table(acl_table_id).key_type, &key_attr);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ACL key attr - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    switch (key_attr.key_width) {
    case SX_ACL_FLEX_KEY_WIDTH_9_E:
    case SX_ACL_FLEX_KEY_WIDTH_18_E:
        table_type = RM_SDK_TABLE_TYPE_ACL_RULES_TWO_KEY_BLOCK_E;
        break;

    case SX_ACL_FLEX_KEY_WIDTH_36_E:
        table_type = RM_SDK_TABLE_TYPE_ACL_RULES_FOUR_KEY_BLOCK_E;
        break;

    case SX_ACL_FLEX_KEY_WIDTH_54_E:
        table_type = RM_SDK_TABLE_TYPE_ACL_RULES_SIX_KEY_BLOCK_E;
        break;

    default:
        SX_LOG_ERR("Unexpected ACL key width - %d\n", key_attr.key_width);
        return SAI_STATUS_FAILURE;
    }

    sx_status = sx_api_rm_free_entries_by_type_get(gh_sdk, table_type, entries);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get a number of free entries for ACL Table [%d] - %s\n",
                   acl_table_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_available_entries_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg)
{
    sai_status_t          status = SAI_STATUS_SUCCESS;
    const acl_table_db_t *acl_table;
    uint32_t              table_index, free_entries, db_limit;

    SX_LOG_ENTER();

    status = extract_acl_table_index(key->key.object_id, &table_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(table_index);

    acl_table = &acl_db_table(table_index);

    if (acl_table->is_dynamic_sized) {
        status = mlnx_acl_dynamic_table_max_entries_get(table_index, &free_entries);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        free_entries = ACL_SX_REG_SIZE_TO_TABLE_SIZE(acl_table->region_size) - acl_table->created_entry_count;
    }

    db_limit = ACL_ENTRY_DB_SIZE - sai_acl_db->acl_settings_tbl->entry_db_indexes_allocated;

    value->u32 = MIN(db_limit, free_entries);

out:
    acl_table_unlock(table_index);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_available_counters_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg)
{
    sai_status_t status;
    sx_status_t  sx_status;
    uint32_t     table_index;
    uint32_t     free_counters;

    SX_LOG_ENTER();

    status = extract_acl_table_index(key->key.object_id, &table_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sx_status = sx_api_rm_free_entries_by_type_get(gh_sdk, RM_SDK_TABLE_TYPE_FLOW_COUNTER_E, &free_counters);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get a number of free flow counters for ACL Table [%d] - %s\n",
                   table_index, SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }

    value->u32 = MIN(free_counters, ACL_MAX_SX_COUNTER_BYTE_NUM + ACL_MAX_SX_COUNTER_PACKET_NUM);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_list_validate(_In_ const sai_s32_list_t *action_list,
                                                  _In_ sai_acl_stage_t       stage,
                                                  _In_ uint32_t              attr_index)
{
    sai_status_t status;
    int32_t      action_types[ACL_MAX_ACTIONS_COUNT] = {0};
    uint32_t     action_types_count, ii, jj;
    bool         is_action_present;

    assert((SAI_ACL_STAGE_INGRESS == stage) || (SAI_ACL_STAGE_EGRESS == stage));

    action_types_count = ARRAY_SIZE(action_types);
    status = mlnx_acl_stage_action_types_get(stage, action_types, &action_types_count);
    if (SAI_ERR(status)) {
        return status;
    }

    for (ii = 0; ii < action_list->count; ii++) {
        is_action_present = false;

        for (jj = 0; jj < action_types_count; jj++) {
            if (action_types[jj] == action_list->list[ii]) {
                is_action_present = true;
                break;
            }
        }

        if (!is_action_present) {
            SX_LOG_ERR("Invalid action id (%d)\n", action_list->list[ii]);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_mc_container_set_impl(_In_ sx_access_cmd_t          sx_cmd,
                                                      _In_ const sai_object_list_t *port_obj_list,
                                                      _Out_ sx_mc_container_id_t   *sx_mc_container_id)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    sx_mc_container_attributes_t sx_mc_container_attributes;
    sx_mc_next_hop_t            *sx_mc_next_hops = NULL;
    uint32_t                     ii;

    assert(NULL != port_obj_list);
    assert(NULL != sx_mc_container_id);

    memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));

    if (0 == port_obj_list->count) {
        SX_LOG_ERR("Failed to %s sx_mc_container - object list is empty\n", SX_ACCESS_CMD_STR(sx_cmd));
        return SAI_STATUS_FAILURE;
    }

    if (MAX_PORTS < port_obj_list->count) {
        SX_LOG_ERR("Failed to %s sx_mc_container - invalid port count (%d), max allowed (%d)",
                   SX_ACCESS_CMD_STR(sx_cmd), port_obj_list->count, MAX_PORTS);
        return SAI_STATUS_FAILURE;
    }

    sx_mc_next_hops = calloc(MAX_PORTS, sizeof(*sx_mc_next_hops));
    if (!sx_mc_next_hops) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    for (ii = 0; ii < port_obj_list->count; ii++) {
        sx_mc_next_hops[ii].type = SX_MC_NEXT_HOP_TYPE_LOG_PORT;
        status = mlnx_acl_field_port_to_sx(port_obj_list->list[ii],
                                           &sx_mc_next_hops[ii].data.log_port);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    sx_mc_container_attributes.type = SX_MC_CONTAINER_TYPE_PORT;

    sx_status = sx_api_mc_container_set(gh_sdk, sx_cmd, sx_mc_container_id,
                                        sx_mc_next_hops, port_obj_list->count, &sx_mc_container_attributes);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Faield to %s sx_mc_container - %s\n", SX_ACCESS_CMD_STR(sx_cmd), SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    free(sx_mc_next_hops);
    return status;
}

static sai_status_t mlnx_acl_sx_mc_container_create(_In_ const sai_object_list_t *port_obj_list,
                                                    _Out_ sx_mc_container_id_t   *sx_mc_container_id)
{
    sai_status_t         status;
    sx_mc_container_id_t sx_mc_container_id_tmp = SX_MC_CONTAINER_ID_INVALID;

    assert(NULL != port_obj_list);
    assert(NULL != sx_mc_container_id);

    status = mlnx_acl_sx_mc_container_set_impl(SX_ACCESS_CMD_CREATE, port_obj_list, &sx_mc_container_id_tmp);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create sx_mc_container\n");
        return status;
    }

    SX_LOG_DBG("Created sx_mc_container (%d)\n", sx_mc_container_id_tmp);

    *sx_mc_container_id = sx_mc_container_id_tmp;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_mc_container_sx_ports_get(_In_ sx_mc_container_id_t sx_mc_container_id,
                                                          _Out_ sx_port_log_id_t   *sx_ports,
                                                          _Inout_ uint32_t         *sx_ports_count)
{
    sai_status_t                 status = SAI_STATUS_SUCCESS;
    sx_status_t                  sx_status;
    sx_mc_container_attributes_t sx_mc_container_attributes;
    sx_mc_next_hop_t            *sx_mc_next_hops = NULL;
    uint32_t                     sx_mc_hext_hop_count = MAX_PORTS;
    uint32_t                     ii;

    assert(sx_ports);
    assert(sx_ports_count && (*sx_ports_count >= MAX_PORTS));

    if (false == SX_MC_CONTAINER_ID_CHECK_RANGE(sx_mc_container_id)) {
        *sx_ports_count = 0;
        return SAI_STATUS_SUCCESS;
    }

    memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));

    sx_mc_next_hops = calloc(MAX_PORTS, sizeof(*sx_mc_next_hops));
    if (!sx_mc_next_hops) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    sx_status = sx_api_mc_container_get(gh_sdk, SX_ACCESS_CMD_GET, sx_mc_container_id,
                                        sx_mc_next_hops, &sx_mc_hext_hop_count, &sx_mc_container_attributes);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get sx_mc_container (%d) next hops -%s\n", sx_mc_container_id, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    if (*sx_ports_count < sx_mc_hext_hop_count) {
        SX_LOG_ERR("sx port objects array is to small (%d), needed (%d)\n", *sx_ports_count, sx_mc_hext_hop_count);
        status = SAI_STATUS_BUFFER_OVERFLOW;
        goto out;
    }

    *sx_ports_count = sx_mc_hext_hop_count;

    for (ii = 0; ii < sx_mc_hext_hop_count; ii++) {
        if (SX_MC_NEXT_HOP_TYPE_LOG_PORT != sx_mc_next_hops[ii].type) {
            SX_LOG_ERR("Invalid next hop type - %d in sx_mc_container (%d)\n",
                       sx_mc_next_hops[ii].type, sx_mc_container_id);
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        sx_ports[ii] = sx_mc_next_hops[ii].data.log_port;
    }

out:
    free(sx_mc_next_hops);
    return status;
}

static sai_status_t mlnx_acl_sx_mc_container_sai_ports_get(_In_ sx_mc_container_id_t sx_mc_container_id,
                                                           _Out_ sai_object_id_t    *ports,
                                                           _Inout_ uint32_t         *ports_count)
{
    sai_status_t        status;
    sx_port_log_id_t    sx_ports[MAX_PORTS_DB * 2] = {0};
    mlnx_port_config_t *port_config;
    uint32_t            sx_ports_count = MAX_PORTS_DB * 2, ii;

    assert(ports);
    assert(ports_count && (*ports_count >= MAX_PORTS));

    if (!SX_MC_CONTAINER_ID_CHECK_RANGE(sx_mc_container_id)) {
        *ports_count = 0;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_acl_sx_mc_container_sx_ports_get(sx_mc_container_id, sx_ports, &sx_ports_count);
    if (SAI_ERR(status)) {
        return status;
    }

    for (ii = 0; ii < sx_ports_count; ii++) {
        status = mlnx_port_by_log_id(sx_ports[ii], &port_config);
        if (SAI_ERR(status)) {
            return status;
        }

        ports[ii] = port_config->saiport;
    }

    *ports_count = sx_ports_count;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_mc_container_update(_In_ const sai_object_list_t *port_obj_list,
                                                    _In_ sx_mc_container_id_t     sx_mc_container_id)
{
    sai_status_t status;

    assert(NULL != port_obj_list);

    if (false == SX_MC_CONTAINER_ID_CHECK_RANGE(sx_mc_container_id)) {
        SX_LOG_ERR("Failed to update sx_mc_container - invalid sx_mc_container_id\n");
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_acl_sx_mc_container_set_impl(SX_ACCESS_CMD_SET, port_obj_list, &sx_mc_container_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update sx_mc_container (%d)\n", sx_mc_container_id);
        return status;
    }

    SX_LOG_DBG("Updated sx_mc_container (%d)\n", sx_mc_container_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_mc_container_remove(_In_ sx_mc_container_id_t sx_mc_container_id)
{
    sx_status_t sx_status;

    if (false == SX_MC_CONTAINER_ID_CHECK_RANGE(sx_mc_container_id)) {
        return SAI_STATUS_SUCCESS;
    }

    sx_status = sx_api_mc_container_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sx_mc_container_id, NULL, 0, NULL);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Faield to destroy sx_mc_container - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_DBG("Removed sx_mc_container (%d)\n", sx_mc_container_id);

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
        sx_keys[*sx_key_count] = FLEX_ACL_KEY_RX_PORT_LIST;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
        sx_keys[*sx_key_count] = FLEX_ACL_KEY_TX_PORT_LIST;
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

static sai_status_t mlnx_acl_stage_is_supported(_In_ sai_acl_stage_t            table_stage,
                                                _In_ mlnx_acl_supported_stage_t supported_stage,
                                                _Out_ bool                     *is_supported)
{
    assert((table_stage == SAI_ACL_STAGE_INGRESS) || (table_stage == SAI_ACL_STAGE_EGRESS));
    assert(supported_stage <= MLNX_ACL_SUPPORTED_STAGE_MAX);
    assert(is_supported);

    if (supported_stage == MLNX_ACL_SUPPORTED_STAGE_BOTH) {
        *is_supported = true;
        return SAI_STATUS_SUCCESS;
    }

    if (table_stage == (sai_acl_stage_t)supported_stage) {
        *is_supported = true;
    } else {
        SX_LOG_ERR("Supported stage %s and table's stage %s doesn't match\n",
                   sai_metadata_get_acl_stage_name((sai_acl_stage_t)supported_stage),
                   sai_metadata_get_acl_stage_name(table_stage));
        *is_supported = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_key_is_supported(_In_ mlnx_acl_supported_chip_t supported_chip, _Out_ bool *is_supported)
{
    assert(is_supported);

    if (supported_chip & MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(g_sai_db_ptr->sx_chip_type)) {
        *is_supported = true;
    } else {
        SX_LOG_ERR("Key is not supported for chip\n");
        *is_supported = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_is_entry_field_supported(_In_ uint32_t             acl_table_index,
                                                            _In_ sai_acl_entry_attr_t attr_id,
                                                            _Out_ bool               *is_supported)
{
    sx_status_t                sx_status;
    sai_status_t               status;
    sai_acl_stage_t            table_stage;
    sx_acl_key_t               table_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    sx_acl_key_t               field_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    sx_acl_key_type_t          key_handle;
    mlnx_acl_field_type_t      table_fields_type, field_type;
    mlnx_acl_supported_stage_t field_stage;
    mlnx_acl_supported_chip_t  field_chip;
    uint32_t                   table_key_count, field_key_count;
    uint32_t                   field_key_index;
    bool                       is_key_present;

    assert(NULL != is_supported);

    table_stage = acl_db_table(acl_table_index).stage;
    table_fields_type = acl_db_table(acl_table_index).table_fields_types;

    field_key_count = 0;

    if (mlnx_acl_field_is_not_trivial(attr_id)) {
        status = mlnx_acl_non_trivial_field_to_sx_key(attr_id, field_keys, &field_key_count);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = mlnx_acl_field_info_data_fetch(attr_id,
                                                &field_type,
                                                field_keys,
                                                &field_key_count,
                                                &field_stage,
                                                &field_chip);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_acl_stage_is_supported(table_stage, field_stage, is_supported);
        if (SAI_ERR(status)) {
            return status;
        }

        if (!*is_supported) {
            return SAI_STATUS_SUCCESS;
        }

        status = mlnx_acl_key_is_supported(field_chip, is_supported);
        if (SAI_ERR(status)) {
            return status;
        }

        if (!*is_supported) {
            return SAI_STATUS_SUCCESS;
        }

        if (MLNX_ACL_FIELD_IS_NOT_PRESENT(field_type, table_fields_type)) {
            SX_LOG_ERR("Field's type is not supported\n");
            *is_supported = false;
            return SAI_STATUS_SUCCESS;
        }

#ifndef MLNX_ACL_SKIP_EXTRA_KEYS
        status = mlnx_acl_field_types_to_extra_sx_keys(field_type, field_keys, &field_key_count);
        if (SAI_ERR(status)) {
            return status;
        }
#endif /* MLNX_ACL_SKIP_EXTRA_KEYS */
    }

    key_handle = acl_db_table(acl_table_index).key_type;

    sx_status = sx_api_acl_flex_key_get(gh_sdk, key_handle, table_keys, &table_key_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR(" Failed to get flex acl key in SDK - %s \n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    *is_supported = true;

    for (field_key_index = 0; field_key_index < field_key_count; field_key_index++) {
        mlnx_acl_sx_key_list_find_key(table_keys, table_key_count, field_keys[field_key_index], &is_key_present, NULL);
        if (!is_key_present) {
            *is_supported = false;
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static void mlnx_acl_sx_key_list_find_key(_In_ const sx_acl_key_t *sx_keys,
                                          _In_ uint32_t            sx_key_count,
                                          _In_ sx_acl_key_t        sx_key,
                                          _Out_ bool              *is_present,
                                          _Out_ uint32_t          *key_idx)
{
    uint32_t idx;

    assert(sx_keys);
    assert(is_present);

    for (idx = 0; idx < sx_key_count; idx++) {
        if (sx_keys[idx] == sx_key) {
            *is_present = true;
            if (key_idx) {
                *key_idx = idx;
            }
            return;
        }
    }

    *is_present = false;
}

static void mlnx_acl_sx_key_list_add_key(_Inout_ sx_acl_key_t    *sx_keys,
                                         _Inout_ uint32_t        *sx_key_count,
                                         _In_ const sx_acl_key_t *sx_new_keys,
                                         _In_ uint32_t            sx_new_keys_count)
{
    uint32_t new_key_idx;
    bool     is_key_present;

    assert(sx_keys);
    assert(sx_key_count);
    assert(sx_new_keys);

    for (new_key_idx = 0; new_key_idx < sx_new_keys_count; new_key_idx++) {
        mlnx_acl_sx_key_list_find_key(sx_keys, *sx_key_count, sx_new_keys[new_key_idx], &is_key_present, NULL);

        if (!is_key_present) {
            sx_keys[*sx_key_count] = sx_new_keys[new_key_idx];
            (*sx_key_count)++;
        }
    }
}

static sai_status_t mlnx_acl_field_info_data_fetch(_In_ sai_attr_id_t                attr_id,
                                                   _Out_opt_ mlnx_acl_field_type_t  *fields_types,
                                                   _Out_opt_ sx_acl_key_t           *sx_keys,
                                                   _Inout_opt_ uint32_t             *sx_key_count,
                                                   _Out_ mlnx_acl_supported_stage_t *supported_stage,
                                                   _Out_ mlnx_acl_supported_chip_t  *supported_chip)
{
    const mlnx_acl_single_key_field_info_t *single_key_field;
    const mlnx_acl_multi_key_field_info_t  *multi_key_field;

    assert((sx_keys && sx_key_count) || (fields_types));

    single_key_field = mlnx_acl_single_key_field_info_fetch(attr_id);
    if (NULL != single_key_field) {
        if (sx_keys) {
            mlnx_acl_sx_key_list_add_key(sx_keys, sx_key_count, &single_key_field->key_id, 1);
        }

        if (fields_types) {
            *fields_types = single_key_field->field_type;
        }

        if (supported_stage) {
            *supported_stage = single_key_field->supported_stage;
        }

        if (supported_chip) {
            *supported_chip = single_key_field->supported_chip;
        }

        return SAI_STATUS_SUCCESS;
    }

    multi_key_field = mlnx_acl_multi_key_field_info_fetch(attr_id);

    if (NULL != multi_key_field) {
        if (sx_keys) {
            mlnx_acl_sx_key_list_add_key(sx_keys, sx_key_count, multi_key_field->key_list, multi_key_field->key_count);
        }

        if (fields_types) {
            *fields_types = multi_key_field->field_type;
        }

        if (supported_stage) {
            /* Currently, all the 'multi_key_field' fields are supported for both stages */
            *supported_stage = MLNX_ACL_SUPPORTED_STAGE_BOTH;
        }

        if (supported_chip) {
            *supported_chip = multi_key_field->supported_chip;
        }

        return SAI_STATUS_SUCCESS;
    }

    SX_LOG_ERR("Failed to find info for attribute (%d)\n", attr_id);
    return SAI_STATUS_FAILURE;
}

static sai_status_t mlnx_acl_table_fields_to_sx(_In_ const sai_attribute_t  *attr_list,
                                                _In_ uint32_t                attr_count,
                                                _In_ sai_acl_stage_t         table_stage,
                                                _Out_ mlnx_acl_field_type_t *table_fields_types,
                                                _Out_ sx_acl_key_t          *sx_keys,
                                                _Inout_ uint32_t            *sx_key_count)
{
    sai_status_t               status;
    mlnx_acl_field_type_t      field_type;
    mlnx_acl_supported_stage_t field_supported_stage;
    uint32_t                   new_key_count, ii;
    bool                       is_field_stage_supported;
    mlnx_acl_supported_chip_t  supported_chip;
    bool                       is_key_supported;

    assert(NULL != attr_list);
    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);

    *table_fields_types = MLNX_ACL_FIELD_TYPE_EMPTY;
    new_key_count = *sx_key_count;

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

        if ((SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN <= attr_list[ii].id) &&
            (attr_list[ii].id <= SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MAX)) {
            continue;
        }

        field_type = MLNX_ACL_FIELD_TYPE_INVALID;

        status = mlnx_acl_field_info_data_fetch(attr_list[ii].id, &field_type, sx_keys,
                                                &new_key_count, &field_supported_stage, &supported_chip);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_acl_stage_is_supported(table_stage, field_supported_stage, &is_field_stage_supported);
        if (SAI_ERR(status)) {
            return status;
        }

        if (!is_field_stage_supported) {
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        status = mlnx_acl_key_is_supported(supported_chip, &is_key_supported);
        if (SAI_ERR(status)) {
            return status;
        }

        if (!is_key_supported) {
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        (*table_fields_types) |= field_type;
    }
#ifndef MLNX_ACL_SKIP_EXTRA_KEYS
    status = mlnx_acl_field_types_to_extra_sx_keys(*table_fields_types, sx_keys, &new_key_count);
    if (SAI_ERR(status)) {
        return status;
    }
#endif /* MLNX_ACL_SKIP_EXTRA_KEYS */

    *sx_key_count = new_key_count;

    if (MLNX_ACL_FIELD_IS_PRESENT(MLNX_ACL_FIELD_TYPE_INNER_L4, *table_fields_types)) {
        mlnx_parsing_depth_increase();
    }

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

        if ((SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN <= attr_list[ii].id) &&
            (attr_list[ii].id <= SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MAX)) {
            continue;
        }

        if (mlnx_acl_field_is_not_trivial(attr_list[ii].id)) {
            continue;
        }

        if (!attr_list[ii].value.aclfield.enable) {
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

        entry_fields_type |= field_type;
    }

    status = mlnx_acl_field_types_check(entry_fields_type);
    if (SAI_ERR(status)) {
        return status;
    }

#ifndef MLNX_ACL_SKIP_EXTRA_KEYS
    status = mlnx_acl_field_types_to_extra_sx_key_descs(entry_fields_type, sx_keys, sx_key_count);
    if (SAI_ERR(status)) {
        return status;
    }
#endif /* MLNX_ACL_SKIP_EXTRA_KEYS */

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_field_types_check(_In_ mlnx_acl_field_type_t field_type)
{
    uint32_t              ii;
    mlnx_acl_field_type_t invalid_fields;

    assert(MLNX_ACL_FIELD_TYPE_INVALID != field_type);

    if (MLNX_ACL_FIELD_TYPE_EMPTY == field_type) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < mlnx_acl_invalid_field_sets_size; ii++) {
        invalid_fields = mlnx_acl_invalid_field_sets[ii];
        if (MLNX_ACL_FIELD_IS_PRESENT(invalid_fields, field_type)) {
            SX_LOG_ERR("Field type combination 0x%x mathces invalid combination 0x%x at idx %d - %s\n",
                       field_type,
                       invalid_fields,
                       ii,
                       SAI_ACL_FIELD_SET_STR(ii));
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_keys_to_field_type(_In_ const sx_flex_acl_key_desc_t *sx_descs,
                                                   _In_ uint32_t                      sx_descs_count,
                                                   _Out_ mlnx_acl_field_type_t       *fields_types)
{
    uint32_t ii;

    assert(sx_descs);
    assert(fields_types);

    *fields_types = MLNX_ACL_FIELD_TYPE_EMPTY;

    for (ii = 0; ii < sx_descs_count; ii++) {
        switch (sx_descs[ii].key_id) {
        case FLEX_ACL_KEY_INNER_VLAN_VALID:
            (*fields_types) |= sx_descs[ii].key.inner_vlan_valid ? MLNX_ACL_FIELD_TYPE_INNER_VLAN_VALID :
                               MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID;
            break;

        case FLEX_ACL_KEY_IP_OK:
            (*fields_types) |= sx_descs[ii].key.ip_ok ? MLNX_ACL_FIELD_TYPE_IP : MLNX_ACL_FIELD_TYPE_NON_IP;
            break;

        case FLEX_ACL_KEY_IS_IP_V4:
            if (!sx_descs[ii].key.is_ip_v4) {
                (*fields_types) |= MLNX_ACL_FIELD_TYPE_NON_IPV4;
            } else {
                SX_LOG_ERR("FLEX_ACL_KEY_IS_IP_V4 (true) is used, "
                           "while MLNX_ACL_FIELD_TYPE_IPV4 should be implemented via L3 type\n");
                return SAI_STATUS_FAILURE;
            }
            break;

        case FLEX_ACL_KEY_L3_TYPE:
            switch (sx_descs[ii].key.l3_type) {
            case SX_ACL_L3_TYPE_IPV4:
                (*fields_types) |= MLNX_ACL_FIELD_TYPE_IPV4;
                break;

            case SX_ACL_L3_TYPE_IPV6:
                (*fields_types) |= MLNX_ACL_FIELD_TYPE_IPV6;
                break;

            case SX_ACL_L3_TYPE_ARP:
                (*fields_types) |= MLNX_ACL_FIELD_TYPE_ARP;
                break;

            default:
                SX_LOG_ERR("Unexpected FLEX_ACL_KEY_L3_TYPE value - %u\n", sx_descs[ii].key.l3_type);
                return SAI_STATUS_FAILURE;
            }
            break;

        case FLEX_ACL_KEY_INNER_L3_TYPE:
            (*fields_types) |=
                (sx_descs[ii].key.inner_l3_type == SX_ACL_L3_TYPE_IPV4) ? MLNX_ACL_FIELD_TYPE_INNER_IPV4 :
                MLNX_ACL_FIELD_TYPE_INNER_IPV6;
            break;

        case FLEX_ACL_KEY_L4_OK:
            (*fields_types) |= MLNX_ACL_FIELD_TYPE_TCP_UDP;
            break;

        case FLEX_ACL_KEY_L4_TYPE:
            (*fields_types) |= MLNX_ACL_FIELD_TYPE_TCP;
            break;

        case FLEX_ACL_KEY_INNER_IP_OK:
            (*fields_types) |= MLNX_ACL_FIELD_TYPE_INNER_IP;
            break;

        case FLEX_ACL_KEY_INNER_L4_OK:
            (*fields_types) |= MLNX_ACL_FIELD_TYPE_INNER_L4;
            break;

        case FLEX_ACL_KEY_L4_TYPE_EXTENDED:
            (*fields_types) |= MLNX_ACL_FIELD_TYPE_ICMP;
            break;

        default:
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_field_types_to_extra_sx_keys(_In_ mlnx_acl_field_type_t fields_types,
                                                          _Out_ sx_acl_key_t        *sx_keys,
                                                          _Inout_ uint32_t          *sx_key_count)
{
    const mlnx_acl_field_extra_keys_t *extra_key;
    uint32_t                           ii;

    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);
    assert(MLNX_ACL_FIELD_TYPE_INVALID != fields_types);

    for (ii = 0; ii < mlnx_acl_field_extra_keys_map_size; ii++) {
        extra_key = &mlnx_acl_field_extra_keys_map[ii];

        if (MLNX_ACL_FIELD_IS_PRESENT(extra_key->field_type, fields_types)) {
            mlnx_acl_sx_key_list_add_key(sx_keys, sx_key_count, &extra_key->sx_key_desc.key_id, 1);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_field_types_to_extra_sx_key_descs(_In_ mlnx_acl_field_type_t    fields_types,
                                                               _Out_ sx_flex_acl_key_desc_t *sx_keys,
                                                               _Inout_ uint32_t             *sx_key_count)
{
    const mlnx_acl_field_extra_keys_t *extra_key;
    uint32_t                           new_key_count, ii;

    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);
    assert(MLNX_ACL_FIELD_TYPE_INVALID != fields_types);

    new_key_count = *sx_key_count;

    for (ii = 0; ii < mlnx_acl_field_extra_keys_map_size; ii++) {
        extra_key = &mlnx_acl_field_extra_keys_map[ii];

        if (MLNX_ACL_FIELD_IS_PRESENT(extra_key->field_type, fields_types)) {
            sx_keys[new_key_count] = extra_key->sx_key_desc;
            new_key_count++;
        }
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
    return mlnx_acl_entry_field_to_sx_update(attr_id, value, attr_index, table_index, sx_keys,
                                             sx_key_count, field_type, NULL, 0);
}

static sai_status_t mlnx_acl_entry_field_to_sx_update(_In_ sai_acl_entry_attr_t          attr_id,
                                                      _In_ const sai_attribute_value_t  *value,
                                                      _In_ uint32_t                      attr_index,
                                                      _In_ uint32_t                      table_index,
                                                      _Out_ sx_flex_acl_key_desc_t      *sx_keys,
                                                      _Inout_ uint32_t                  *sx_key_count,
                                                      _Inout_ mlnx_acl_field_type_t     *field_type,
                                                      _In_ const sx_flex_acl_key_desc_t *prev_sx_keys,
                                                      _In_ uint32_t                      prev_sx_keys_count)
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


    case SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS:
        status = mlnx_acl_ip_flags_field_to_sx(attr_id,
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

    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE:
        status = mlnx_acl_icmp_field_to_sx(attr_id,
                                           value,
                                           attr_index,
                                           table_index,
                                           sx_keys,
                                           sx_key_count,
                                           field_type,
                                           prev_sx_keys,
                                           prev_sx_keys_count);
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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

    field_info = mlnx_acl_single_key_field_info_fetch(attr_id);
    if (!field_info) {
        SX_LOG_ERR("Failed to fetch field info for ACL field (%d)\n", attr_id);
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

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

    field_info = mlnx_acl_single_key_field_info_fetch(attr_id);
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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

    packet_vlan = value->aclfield.data.s32;

    switch (packet_vlan) {
    case SAI_PACKET_VLAN_UNTAG:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_VLAN_TAGGED;
        sx_keys[*sx_key_count].key.vlan_tagged = false;
        sx_keys[*sx_key_count].mask.vlan_tagged = true;
        (*sx_key_count)++;
        break;

    case SAI_PACKET_VLAN_SINGLE_OUTER_TAG:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_VLAN_TAGGED;
        sx_keys[*sx_key_count].key.vlan_tagged = true;
        sx_keys[*sx_key_count].mask.vlan_tagged = true;
        (*sx_key_count)++;

        *field_type = MLNX_ACL_FIELD_TYPE_INNER_VLAN_INVALID;
        break;

    case SAI_PACKET_VLAN_DOUBLE_TAG:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_VLAN_TAGGED;
        sx_keys[*sx_key_count].key.vlan_tagged = true;
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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

    sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_DSCP;
    sx_keys[*sx_key_count].key.dscp = (value->aclfield.data.u8 >> 0x02) & 0x3f;
    sx_keys[*sx_key_count].mask.dscp = (value->aclfield.mask.u8 >> 0x02) & 0x3f;
    (*sx_key_count)++;

    sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_ECN;
    sx_keys[*sx_key_count].key.ecn = (value->aclfield.data.u8) & 0x03;
    sx_keys[*sx_key_count].mask.ecn = (value->aclfield.mask.u8) & 0x03;
    (*sx_key_count)++;

    *field_type = MLNX_ACL_FIELD_TYPE_IPV4;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_ip_flags_field_to_sx(_In_ sai_acl_entry_attr_t         attr_id,
                                                  _In_ const sai_attribute_value_t *value,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ uint32_t                     table_index,
                                                  _Out_ sx_flex_acl_key_desc_t     *sx_keys,
                                                  _Inout_ uint32_t                 *sx_key_count,
                                                  _Inout_ mlnx_acl_field_type_t    *field_type)
{
    assert(SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS == attr_id);

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }
    if (value->aclfield.mask.u8 > 0x7) {
        SX_LOG_ERR("ACL filed mask %u is bigger then expected [0x7]\n",
                   value->aclfield.mask.u8);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_DONT_FRAGMENT;
    sx_keys[*sx_key_count].key.ip_dont_fragment = (value->aclfield.data.u8 >> 1) & 0x1;
    sx_keys[*sx_key_count].mask.ip_dont_fragment = (value->aclfield.mask.u8 >> 1) & 0x1;
    (*sx_key_count)++;
    sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_MORE_FRAGMENTS;
    sx_keys[*sx_key_count].key.ip_more_fragments = (value->aclfield.data.u8 >> 2) & 0x1;
    sx_keys[*sx_key_count].mask.ip_more_fragments = (value->aclfield.mask.u8 >> 2) & 0x1;
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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

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
#ifdef MLNX_ACL_L3_TYPE_REDUCED
        SX_LOG_ERR("SAI_ACL_IP_TYPE_NON_IPV4 is not supported\n");
        return SAI_STATUS_NOT_SUPPORTED;
#endif
        *field_type = MLNX_ACL_FIELD_TYPE_NON_IPV4;
        break;

    case SAI_ACL_IP_TYPE_IPV6ANY:
        *field_type = MLNX_ACL_FIELD_TYPE_IPV6;
        break;

    case SAI_ACL_IP_TYPE_NON_IPV6:
        SX_LOG_ERR("SAI_ACL_IP_TYPE_NON_IPV6 is not supported\n");
        return SAI_STATUS_NOT_SUPPORTED;

    case SAI_ACL_IP_TYPE_ARP:
        *field_type = MLNX_ACL_FIELD_TYPE_ARP;
        break;

    case SAI_ACL_IP_TYPE_ARP_REQUEST:
        SX_LOG_ERR("SAI_ACL_IP_TYPE_ARP_REQUEST is not supported\n");
        return SAI_STATUS_NOT_SUPPORTED;

    case SAI_ACL_IP_TYPE_ARP_REPLY:
        SX_LOG_ERR("SAI_ACL_IP_TYPE_ARP_REPLY is not supported\n");
        return SAI_STATUS_NOT_SUPPORTED;

    default:
        SX_LOG_ERR("Invalid type of ip type (%d)\n", ip_type);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

#ifdef MLNX_ACL_SKIP_EXTRA_KEYS
    sai_status_t status;
    status = mlnx_acl_field_types_to_extra_sx_key_descs(*field_type, sx_keys, sx_key_count);
    if (SAI_ERR(status)) {
        return status;
    }
#endif /* MLNX_ACL_SKIP_EXTRA_KEYS */

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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

    ip_frag = value->aclfield.data.s32;

    switch (ip_frag) {
    case SAI_ACL_IP_FRAG_ANY:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented = true;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_NON_FRAG:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented = false;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_NON_FRAG_OR_HEAD:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
        sx_keys[*sx_key_count].key.ip_fragment_not_first = false;
        sx_keys[*sx_key_count].mask.ip_fragment_not_first = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_HEAD:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented = true;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;

        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
        sx_keys[*sx_key_count].key.ip_fragment_not_first = false;
        sx_keys[*sx_key_count].mask.ip_fragment_not_first = true;
        (*sx_key_count)++;
        break;

    case SAI_ACL_IP_FRAG_NON_HEAD:
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_FRAGMENTED;
        sx_keys[*sx_key_count].key.ip_fragmented = true;
        sx_keys[*sx_key_count].mask.ip_fragmented = true;
        (*sx_key_count)++;

        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;
        sx_keys[*sx_key_count].key.ip_fragment_not_first = true;
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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_acl_range_validate_and_fetch(&value->aclfield.data.objlist,
                                               &sx_keys[*sx_key_count].key.l4_port_range,
                                               table_index);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_L4_PORT_RANGE;
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

    if (!value->aclfield.enable) {
        return SAI_STATUS_SUCCESS;
    }

    if ((value->aclfield.data.u32 <= ACL_USER_META_RANGE_MAX) &&
        (value->aclfield.mask.u32 <= ACL_USER_META_RANGE_MAX)) {
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_USER_TOKEN;
        sx_keys[*sx_key_count].key.user_token = (uint16_t)value->aclfield.data.u32;
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

static sai_status_t mlnx_acl_icmp_field_to_sx(_In_ sai_acl_entry_attr_t          attr_id,
                                              _In_ const sai_attribute_value_t  *value,
                                              _In_ uint32_t                      attr_index,
                                              _In_ uint32_t                      table_index,
                                              _Out_ sx_flex_acl_key_desc_t      *sx_keys,
                                              _Inout_ uint32_t                  *sx_key_count,
                                              _Inout_ mlnx_acl_field_type_t     *field_type,
                                              _In_ const sx_flex_acl_key_desc_t *prev_sx_keys,
                                              _In_ uint32_t                      prev_sx_keys_count)
{
    const mlnx_acl_single_key_field_info_t *field_info;
    uint16_t                                data = 0, mask = 0;
    uint16_t                                new_data, new_mask;
    uint32_t                                existing_key_idx, ii;
    bool                                    is_key_exists = false;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE == attr_id));

    new_data = (value->aclfield.enable) ? value->aclfield.data.u8 : 0;
    new_mask = (value->aclfield.enable) ? value->aclfield.mask.u8 : 0;

    if (prev_sx_keys_count > 0) {
        assert(prev_sx_keys);

        if (prev_sx_keys_count != 1) {
            SX_LOG_ERR("Unexpected count of previous sx keys for ICMP field - %d (expected 1)\n", prev_sx_keys_count);
            return SAI_STATUS_FAILURE;
        }

        if (prev_sx_keys[0].key_id != FLEX_ACL_KEY_L4_SOURCE_PORT) {
            SX_LOG_ERR("Unexpected previous sx key id %d for ICMP field (expected L4_SOURCE_PORT)\n",
                       prev_sx_keys[0].key_id);
            return SAI_STATUS_FAILURE;
        }

        data = prev_sx_keys[0].key.l4_source_port;
        mask = prev_sx_keys[0].mask.l4_source_port;
    } else {
        for (ii = 0; ii < *sx_key_count; ii++) {
            if (FLEX_ACL_KEY_L4_SOURCE_PORT == sx_keys[ii].key_id) {
                existing_key_idx = ii;
                is_key_exists = true;

                data = sx_keys[ii].key.l4_source_port;
                mask = sx_keys[ii].mask.l4_source_port;
            }
        }
    }

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE:
        data = (data & 0xFF) | (new_data << 8);
        mask = (mask & 0xFF) | (new_mask << 8);
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE:
        data = (data & 0xFF00) | new_data;
        mask = (mask & 0xFF00) | new_mask;
        break;

    default:
        SX_LOG_ERR("Unexpected attr_id %d\n", attr_id);
        return SAI_STATUS_FAILURE;
    }

    if (is_key_exists) {
        sx_keys[existing_key_idx].key.l4_source_port = data;
        sx_keys[existing_key_idx].mask.l4_source_port = mask;
    } else {
        sx_keys[*sx_key_count].key_id = FLEX_ACL_KEY_L4_SOURCE_PORT;
        sx_keys[*sx_key_count].key.l4_source_port = data;
        sx_keys[*sx_key_count].mask.l4_source_port = mask;
        (*sx_key_count)++;
    }

    field_info = mlnx_acl_single_key_field_info_fetch(attr_id);
    assert(field_info);

    assert(MLNX_ACL_FIELD_TYPE_ICMP & field_info->field_type);

    *field_type = field_info->field_type;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t acl_db_find_entry_free_index(_Out_ uint32_t *free_index)
{
    uint32_t last_free_index, new_free_index;

    assert(free_index != NULL);

    last_free_index = sai_acl_db->acl_settings_tbl->entry_db_first_free_index;

    if (last_free_index == ACL_INVALID_DB_INDEX) {
        SX_LOG_ERR("Max Limit of ACL Entries Reached\n");
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    new_free_index =
        sai_acl_db->acl_entry_db[last_free_index].next_entry_index;
    sai_acl_db->acl_settings_tbl->entry_db_first_free_index = new_free_index;

    sai_acl_db->acl_entry_db[last_free_index].is_used = true;
    sai_acl_db->acl_settings_tbl->entry_db_indexes_allocated++;

    *free_index = last_free_index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t acl_db_find_table_free_index(_Out_ uint32_t *free_index)
{
    sai_status_t status;
    uint32_t     ii;

    SX_LOG_ENTER();
    assert(free_index != NULL);

    for (ii = 0; ii < ACL_TABLE_DB_SIZE; ii++) {
        if ((false == acl_db_table(ii).is_used) &&
            (0 == acl_db_table(ii).queued)) {
            *free_index = ii;
            acl_db_table(ii).is_used = true;
            status = SAI_STATUS_SUCCESS;
            break;
        }
    }

    if (ii == ACL_TABLE_DB_SIZE) {
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

    for (ii = 0; ii < (ACL_GROUP_NUMBER / g_sai_db_ptr->acl_divider); ii++) {
        if (false == sai_acl_db_group_ptr(ii)->is_used) {
            *free_index = ii;
            sai_acl_db_group_ptr(ii)->is_used = true;
            status = SAI_STATUS_SUCCESS;
            break;
        }
    }

    if (ii == (ACL_GROUP_NUMBER / g_sai_db_ptr->acl_divider)) {
        SX_LOG_ERR("Max Limit of ACL Groups Reached\n");
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_acl_db_free_entries_get(_In_ sai_object_type_t resource_type, _Out_ uint32_t         *free_entries)
{
    uint32_t ii, count = 0;

    assert((resource_type == SAI_OBJECT_TYPE_ACL_TABLE_GROUP) || (resource_type == SAI_OBJECT_TYPE_ACL_TABLE));

    if (resource_type == SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
        for (ii = 0; ii < (ACL_GROUP_NUMBER / g_sai_db_ptr->acl_divider); ii++) {
            if (false == sai_acl_db_group_ptr(ii)->is_used) {
                count++;
            }
        }
    } else { /* SAI_OBJECT_TYPE_ACL_TABLE */
        for (ii = 0; ii < ACL_TABLE_DB_SIZE; ii++) {
            if (false == acl_db_table(ii).is_used) {
                count++;
            }
        }
    }

    *free_entries = count;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_db_entries_foreach(_In_ mlnx_acl_entry_iter_fn fn, void *opaque)
{
    sai_status_t status;
    uint32_t     table_idx, entry_idx;
    uint32_t     stat_exec = 0, stat_skiped = 0;

    for (table_idx = 0; table_idx < ACL_TABLE_DB_SIZE; table_idx++) {
        if (!acl_db_table(table_idx).is_used) {
            continue;
        }

        acl_table_write_lock(table_idx);

        entry_idx = acl_db_table(table_idx).head_entry_index;
        while (entry_idx != ACL_INVALID_DB_INDEX) {
            status = fn(table_idx, entry_idx, opaque);
            if (status == SAI_STATUS_NOT_EXECUTED) {
                stat_skiped++;
                entry_idx = acl_db_entry(entry_idx).next_entry_index;
                continue;
            }

            if (SAI_ERR(status)) {
                SX_LOG_ERR("Iteration failed at table %d entry %d\n", table_idx, entry_idx);
                acl_table_unlock(table_idx);
                return status;
            }

            stat_exec++;

            entry_idx = acl_db_entry(entry_idx).next_entry_index;
        }

        acl_table_unlock(table_idx);
    }

    SX_LOG_DBG("%d executed, %d skipped\n", stat_exec, stat_skiped);

    return SAI_STATUS_SUCCESS;
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
    uint16_t     table_index_tmp;
    uint8_t      table_data[EXTENDED_DATA_SIZE] = {0};

    SX_LOG_ENTER();

    assert((acl_table_index != NULL) && (acl_entry_index != NULL));

    status = mlnx_object_to_type(entry_object_id, SAI_OBJECT_TYPE_ACL_ENTRY, &entry_data, table_data);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    memcpy(&table_index_tmp, table_data, sizeof(table_index_tmp));

    *acl_table_index = table_index_tmp;

    if (!acl_table_index_check_range(*acl_table_index)) {
        SX_LOG_ERR("Got bad ACL Table index from object_id - %x\n", *acl_table_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    if (false == acl_db_table(*acl_table_index).is_used) {
        SX_LOG_ERR("Table [%d] is deleted\n", *acl_table_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    *acl_entry_index = entry_data;
    if (!acl_entry_index_check_range(*acl_entry_index)) {
        SX_LOG_ERR("Got bad ACL Entry index from object_id - %x\n", *acl_entry_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    if (false == acl_db_entry(*acl_entry_index).is_used) {
        SX_LOG_ERR("Entry [%d] is deleted\n", *acl_entry_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
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
        value->u32 = ACL_SX_RULE_PRIO_TO_SAI(sai_acl_db->acl_entry_db[acl_entry_index].sx_prio);
        break;

    case SAI_ACL_ENTRY_ATTR_ADMIN_STATE:
        value->booldata = true;
        break;
    }

    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

/*
 * Returns a sx_flex_acl_flex_rule_t located in
 * [SAI ACL Table (acl_table_index) : SAI ACL Entry (acl_entry_index)]
 *
 * The caller is resonible for calling a mlnx_acl_flex_rule_free for flex_acl_rule_p
 */
static sai_status_t mlnx_acl_entry_sx_acl_rule_get(_In_ uint32_t                    acl_table_index,
                                                   _In_ uint32_t                    acl_entry_index,
                                                   _Inout_ sx_flex_acl_flex_rule_t *flex_acl_rule_p)
{
    sx_status_t          sx_status;
    sai_status_t         status = SAI_STATUS_SUCCESS;
    sx_acl_region_id_t   region_id = 0;
    sx_acl_rule_offset_t rule_offset;
    sx_acl_key_type_t    key_type;
    uint32_t             rule_count;

    assert(MLNX_ACL_SX_FLEX_RULE_IS_EMPTY(flex_acl_rule_p));

    SX_LOG_ENTER();

    rule_offset = acl_db_entry(acl_entry_index).offset;
    region_id = acl_db_table(acl_table_index).region_id;
    key_type = acl_db_table(acl_table_index).key_type;

    memset(flex_acl_rule_p, 0, sizeof(sx_flex_acl_flex_rule_t));

    sx_status = sx_lib_flex_acl_rule_init(key_type, ACL_MAX_NUM_OF_ACTIONS,
                                          flex_acl_rule_p);
    if (SAI_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    rule_count = 1;
    sx_status = sx_api_acl_flex_rules_get(gh_sdk, region_id, &rule_offset, flex_acl_rule_p, &rule_count);
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
    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META:
        value->aclfield.data.u32 = sx_key->key.user_token;
        value->aclfield.mask.u32 = sx_key->mask.user_token;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE:
        value->aclfield.data.u8 = sx_key->key.l4_source_port >> 8;
        value->aclfield.mask.u8 = sx_key->mask.l4_source_port >> 8;
        if ((value->aclfield.data.u8 == 0) && (value->aclfield.mask.u8 == 0)) {
            value->aclfield.enable = false;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE:
        value->aclfield.data.u8 = sx_key->key.l4_source_port & 0xff;
        value->aclfield.mask.u8 = sx_key->mask.l4_source_port & 0xff;
        if ((value->aclfield.data.u8 == 0) && (value->aclfield.mask.u8 == 0)) {
            value->aclfield.enable = false;
        }
        break;

    default:
        memcpy(&value->aclfield.data, &sx_key->key, key_size);
        memcpy(&value->aclfield.mask, &sx_key->mask, key_size);
        break;
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
    sx_flex_acl_flex_rule_t                 flex_acl_rule =
        MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_key_t field_extra_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    uint32_t     key_desc_index, ii, field_extra_key_count;
    uint32_t     acl_table_index, acl_entry_index;
    bool         is_field_suppoted, is_key_type_present, is_extra_keys_present;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_ETHER_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DSCP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_BTH_OPCODE == attr_id));

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
#ifndef MLNX_ACL_SKIP_EXTRA_KEYS
    status = mlnx_acl_field_types_to_extra_sx_keys(field_info->field_type, field_extra_keys, &field_extra_key_count);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }
#endif /* MLNX_ACL_SKIP_EXTRA_KEYS */

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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
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
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    uint32_t                acl_table_index, acl_entry_index, key_desc_index;
    bool                    is_key_present;

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->aclfield.enable = true;

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, FLEX_ACL_KEY_L3_TYPE, &key_desc_index, &is_key_present);

    if (is_key_present) {
        switch (flex_acl_rule.key_desc_list_p[key_desc_index].key.l3_type) {
        case SX_ACL_L3_TYPE_ARP:
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_ARP;
            break;

        case SX_ACL_L3_TYPE_IPV4:
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IPV4ANY;
            break;

        case SX_ACL_L3_TYPE_IPV6:
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_IPV6ANY;
            break;

        default:
            SX_LOG_ERR("Unexpected FLEX_ACL_KEY_L3_TYPE value - %u\n",
                       flex_acl_rule.key_desc_list_p[key_desc_index].key.l3_type);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        goto out;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, FLEX_ACL_KEY_IS_IP_V4, &key_desc_index, &is_key_present);

    if (is_key_present) {
        if (!flex_acl_rule.key_desc_list_p[key_desc_index].key.is_ip_v4) {
            value->aclfield.data.s32 = SAI_ACL_IP_TYPE_NON_IPV4;
        } else {
            SX_LOG_ERR("FLEX_ACL_KEY_IS_IP_V4 (true) is used, "
                       "while MLNX_ACL_FIELD_TYPE_IPV4 should be implemented via L3 type\n");
            status = SAI_STATUS_FAILURE;
            goto out;
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

static sai_status_t mlnx_acl_entry_udf_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sx_acl_key_t            custom_byte_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {0};
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sai_acl_entry_attr_t    entry_udf_attr;
    const acl_udf_group_t  *udf_group_list;
    uint32_t                udf_group_length, custom_byte_count, sx_key_index, ii;
    uint32_t                acl_table_index, acl_entry_index, acl_table_udf_attr_index, udf_group_db_index;
    bool                    is_sx_key_present;

    SX_LOG_ENTER();

    entry_udf_attr = (int64_t)arg;

    assert((SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN <= entry_udf_attr) &&
           (entry_udf_attr <= SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN + MLNX_UDF_ACL_ATTR_MAX_ID));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();
    acl_table_read_lock(acl_table_index);

    udf_group_list = acl_db_table(acl_table_index).udf_group_list;

    acl_table_udf_attr_index = entry_udf_attr - SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN;

    if (false == udf_group_list[acl_table_udf_attr_index].is_set) {
        SX_LOG_ERR("Failed to get attribute %d - UDF Group was not specified for ACL Table\n", entry_udf_attr);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    udf_group_db_index = udf_group_list[acl_table_udf_attr_index].udf_group_db_index;

    status = mlnx_udf_group_length_get(udf_group_db_index, &udf_group_length);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_attribute_value_list_size_check(&value->aclfield.data.u8list.count, udf_group_length);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_attribute_value_list_size_check(&value->aclfield.mask.u8list.count, udf_group_length);
    if (SAI_ERR(status)) {
        goto out;
    }

    custom_byte_count = 0;
    status =
        mlnx_udf_group_db_index_to_sx_acl_keys(udf_group_db_index, custom_byte_keys, &custom_byte_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (ii = 0; ii < custom_byte_count; ii++) {
        mlnx_acl_flex_rule_key_find(&flex_acl_rule, custom_byte_keys[ii], &sx_key_index, &is_sx_key_present);

        if (false == is_sx_key_present) {
            /* If we found that some part of custom bytes are presnt and some part is not
             * region structure is broken */
            assert(0 == ii);

            value->aclfield.enable = false;
            value->aclfield.data.u8list.count = 0;
            value->aclfield.mask.u8list.count = 0;
            goto out;
        }

        value->aclfield.enable = true;
        value->aclfield.data.u8list.list[ii] = flex_acl_rule.key_desc_list_p[sx_key_index].key.custom_byte;
        value->aclfield.mask.u8list.list[ii] = flex_acl_rule.key_desc_list_p[sx_key_index].mask.custom_byte;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_udf_attrs_parse(_In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list,
                                                   _Out_ sx_acl_key_t         *sx_keys,
                                                   _Inout_ uint32_t           *sx_key_count,
                                                   _Out_ acl_udf_group_list_t  udf_group_list)
{
    sai_status_t                 status;
    sai_acl_table_attr_t         udf_group_attr_id;
    const sai_attribute_value_t *udf_group_attr;
    uint32_t                     udf_group_attr_index, udf_group_db_index, ii;

    assert(NULL != attr_list);
    assert(NULL != udf_group_list);
    assert(NULL != sx_keys);
    assert(NULL != sx_key_count);

    for (udf_group_attr_id = SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN;
         udf_group_attr_id <= SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN + MLNX_UDF_ACL_ATTR_COUNT;
         udf_group_attr_id++) {
        status = find_attrib_in_list(attr_count, attr_list, udf_group_attr_id, &udf_group_attr, &udf_group_attr_index);
        if (SAI_STATUS_SUCCESS == status) {
            status = mlnx_udf_group_oid_validate_and_fetch(udf_group_attr->oid,
                                                           udf_group_attr_index,
                                                           &udf_group_db_index);
            if (SAI_ERR(status)) {
                return status;
            }

            status = mlnx_udf_group_db_index_to_sx_acl_keys(udf_group_db_index, sx_keys, sx_key_count);
            if (SAI_ERR(status)) {
                return status;
            }

            ii = udf_group_attr_id -
                 SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN;
            udf_group_list[ii].is_set = true;
            udf_group_list[ii].udf_group_db_index = udf_group_db_index;
        }
    }

    for (ii = 0; ii < attr_count; ii++) {
        if (mlnx_udf_acl_attribute_id_is_not_supported(attr_list[ii].id)) {
            SX_LOG_ERR(
                "The SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP attributes are only supported in a range (0, %d)\n",
                MLNX_UDF_ACL_ATTR_MAX_ID);
            return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + ii;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_udf_attrs_parse(_In_ _In_ uint32_t            attr_count,
                                                   _In_ const sai_attribute_t   *attr_list,
                                                   _In_ uint32_t                 acl_table_index,
                                                   _Out_ sx_flex_acl_key_desc_t *key_desc,
                                                   _Inout_ uint32_t             *key_desc_count)
{
    sai_status_t                 status;
    sai_acl_entry_attr_t         udf_attr_id;
    sx_acl_key_t                 custom_byte_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {0};
    const sai_attribute_value_t *udf_attr_value;
    const sai_acl_field_data_t  *value;
    uint32_t                     attr_index, custom_byte_count, ii;

    assert(NULL != attr_list);
    assert(NULL != key_desc);
    assert(NULL != key_desc_count);

    for (udf_attr_id = SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN;
         udf_attr_id < SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN + MLNX_UDF_ACL_ATTR_COUNT;
         udf_attr_id++) {
        status = find_attrib_in_list(attr_count, attr_list, udf_attr_id, &udf_attr_value, &attr_index);
        if (SAI_STATUS_SUCCESS == status) {
            value = &udf_attr_value->aclfield;
            if (value->enable) {
                status = mlnx_acl_entry_udf_attrs_validate_and_fetch(udf_attr_value,
                                                                     udf_attr_id,
                                                                     attr_index,
                                                                     acl_table_index,
                                                                     custom_byte_keys,
                                                                     &custom_byte_count);
                if (SAI_ERR(status)) {
                    return status;
                }

                assert(custom_byte_count == value->data.u8list.count);

                for (ii = 0; ii < value->data.u8list.count; ii++) {
                    key_desc[*key_desc_count].key_id = custom_byte_keys[ii];
                    key_desc[*key_desc_count].key.custom_byte = value->data.u8list.list[ii];
                    key_desc[*key_desc_count].mask.custom_byte = value->mask.u8list.list[ii];
                    (*key_desc_count)++;
                }
            }
        }
    }

    for (ii = 0; ii < attr_count; ii++) {
        if (mlnx_udf_acl_attribute_id_is_not_supported(attr_list[ii].id)) {
            SX_LOG_ERR("The SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD attributes are only supported in a range (0, %d)\n",
                       MLNX_UDF_ACL_ATTR_MAX_ID);
            return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + ii;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_udf_attrs_validate_and_fetch(_In_ const sai_attribute_value_t *udf_attr,
                                                                _In_ sai_acl_entry_attr_t         udf_attr_id,
                                                                _In_ uint32_t                     attr_index,
                                                                _In_ uint32_t                     acl_table_index,
                                                                _Out_ sx_acl_key_t               *custom_byte_keys,
                                                                _Inout_ uint32_t                 *custom_byte_count)
{
    sai_status_t                status;
    const acl_udf_group_t      *udf_group_list;
    const sai_acl_field_data_t *value;
    uint32_t                    table_udf_group_index, udf_group_length, udf_group_db_index;

    assert(NULL != udf_attr);
    assert(NULL != custom_byte_keys);
    assert(NULL != custom_byte_count);

    udf_group_list = acl_db_table(acl_table_index).udf_group_list;

    table_udf_group_index = udf_attr_id - SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN;

    if (false == udf_group_list[table_udf_group_index].is_set) {
        SX_LOG_ERR("Failed to set attribute %d - UDF Group was not specified for ACL Table\n", udf_attr_id);
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    value = &udf_attr->aclfield;

    udf_group_db_index = udf_group_list[table_udf_group_index].udf_group_db_index;

    status = mlnx_udf_group_length_get(udf_group_db_index, &udf_group_length);
    if (SAI_ERR(status)) {
        return status;
    }

    if (udf_group_length != value->data.u8list.count) {
        SX_LOG_ERR("Invalid count of data bytes (%d) for attr (%d), should be - %d\n",
                   value->data.u8list.count, udf_attr_id, udf_group_length);
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    if (udf_group_length != value->mask.u8list.count) {
        SX_LOG_ERR("Invalid count of mask bytes (%d) for attr (%d), should be - %d\n",
                   value->mask.u8list.count, udf_attr_id, udf_group_length);
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    *custom_byte_count = 0;
    status =
        mlnx_udf_group_db_index_to_sx_acl_keys(udf_group_db_index, custom_byte_keys, custom_byte_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_ip_frag_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_key_t            ip_frag_key, ip_frag_not_first_key;
    uint32_t                key_desc_index = 0;
    uint32_t                ip_frag_key_desc_index = 0, ip_frag_not_first_key_desc_index = 0;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_ip_frag_key_present = false, is_ip_frag_not_first_key_present = false;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG == (int64_t)arg);

    ip_frag_key = FLEX_ACL_KEY_IP_FRAGMENTED;
    ip_frag_not_first_key = FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST;

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
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
            } else {
                SX_LOG_ERR("Invalid sx region state - FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST value is true but "
                           "FLEX_ACL_KEY_IP_FRAGMENTED is not present\n");
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        } else {
            value->aclfield.enable = false;
        }
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_flags_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_key_t            ip_dont_fragment_key;
    sx_acl_key_t            ip_more_fragments_key;
    uint32_t                key_desc_index = 0;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_ip_dont_fragment_key_present = false, is_ip_more_fragments_key_present = false;
    uint32_t                ip_flag_dont_fragment_key_desc_index = 0, ip_flag_more_fragments_key_desc_index = 0;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS == (int64_t)arg);

    ip_dont_fragment_key = FLEX_ACL_KEY_IP_DONT_FRAGMENT;
    ip_more_fragments_key = FLEX_ACL_KEY_IP_MORE_FRAGMENTS;

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    value->aclfield.enable = true;
    value->aclfield.data.u8 = 0;
    value->aclfield.mask.u8 = 0;

    for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == ip_dont_fragment_key) {
            is_ip_dont_fragment_key_present = true;
            ip_flag_dont_fragment_key_desc_index = key_desc_index;
        }
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == ip_more_fragments_key) {
            is_ip_more_fragments_key_present = true;
            ip_flag_more_fragments_key_desc_index = key_desc_index;
        }
        if (is_ip_dont_fragment_key_present && is_ip_more_fragments_key_present) {
            break;
        }
    }

    if ((is_ip_dont_fragment_key_present) && (is_ip_more_fragments_key_present)) {
        value->aclfield.data.u8 =
            flex_acl_rule.key_desc_list_p[ip_flag_dont_fragment_key_desc_index].key.ip_dont_fragment << 1;
        value->aclfield.data.u8 |=
            flex_acl_rule.key_desc_list_p[ip_flag_more_fragments_key_desc_index].key.ip_more_fragments << 2;
        value->aclfield.mask.u8 =
            flex_acl_rule.key_desc_list_p[ip_flag_dont_fragment_key_desc_index].mask.ip_dont_fragment << 1;
        value->aclfield.mask.u8 |=
            flex_acl_rule.key_desc_list_p[ip_flag_more_fragments_key_desc_index].mask.ip_more_fragments << 2;
    } else {
        SX_LOG_ERR("Invalid sx region state - FLEX_ACL_KEY_IP_DONT_FRAGMENT or "
                   "FLEX_ACL_KEY_IP_MORE_FRAGMENTS is not present\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_udf_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sai_status_t               status;
    sx_flex_acl_flex_rule_t    flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_flex_acl_rule_offset_t *offsets_list_p = NULL;
    sx_acl_key_t               custom_byte_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {0};
    sai_acl_entry_attr_t       entry_udf_attr;
    uint32_t                   acl_table_index, acl_entry_index, sx_key_index;
    uint32_t                   custom_byte_count, ii;
    bool                       is_sx_key_present;

    SX_LOG_ENTER();

    entry_udf_attr = (int64_t)arg;

    assert((SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN <= entry_udf_attr) &&
           (entry_udf_attr <= SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN + MLNX_UDF_ACL_ATTR_MAX_ID));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);

    status = mlnx_acl_entry_udf_attrs_validate_and_fetch(value, entry_udf_attr, 0, acl_table_index,
                                                         custom_byte_keys, &custom_byte_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (ii = 0; ii < custom_byte_count; ii++) {
        mlnx_acl_flex_rule_key_find(&flex_acl_rule, custom_byte_keys[ii], &sx_key_index, &is_sx_key_present);

        if (value->aclfield.enable) {
            flex_acl_rule.key_desc_list_p[sx_key_index].key_id = custom_byte_keys[ii];
            flex_acl_rule.key_desc_list_p[sx_key_index].key.custom_byte =
                value->aclfield.data.u8list.list[ii];
            flex_acl_rule.key_desc_list_p[sx_key_index].mask.custom_byte =
                value->aclfield.mask.u8list.list[ii];

            if (false == is_sx_key_present) {
                flex_acl_rule.key_desc_count += 1;
            }
        } else {
            if (is_sx_key_present) {
                mlnx_acl_flex_rule_key_del(&flex_acl_rule, sx_key_index);
            }
        }
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);
    free(offsets_list_p);

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
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_ip_addr_t            ipaddr_data, ipaddr_mask;
    sai_ip_address_t        ip_address_data, ip_address_mask;
    uint32_t                key_id = 0;
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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
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
                goto out;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dipv6,
                                                          &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
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
                goto out;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dipv6,
                                                          &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
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
                goto out;
            }

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.sip,
                                                               &ip_address_mask))) {
                goto out;
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
                goto out;
            }

            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_translate_sdk_ip_address_to_sai(&flex_acl_rule.key_desc_list_p[key_desc_index].mask.dip,
                                                               &ip_address_mask))) {
                goto out;
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
                goto out;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_sip,
                &ip_address_mask);
            if (SAI_ERR(status)) {
                goto out;
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
                goto out;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_dip,
                &ip_address_mask);
            if (SAI_ERR(status)) {
                goto out;
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
                goto out;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_sipv6,
                &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
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
                goto out;
            }

            status = mlnx_translate_sdk_ip_address_to_sai(
                &flex_acl_rule.key_desc_list_p[key_desc_index].mask.inner_dipv6,
                &ip_address_mask);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
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

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ports_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sai_attr_id_t           attr_id;
    sx_flex_acl_flex_rule_t rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_key_t            key_id;
    sx_mc_container_id_t    mc_container = SX_MC_CONTAINER_ID_INVALID;
    sai_object_id_t        *port_object_list = NULL;
    uint32_t                acl_table_index, acl_entry_index, key_index;
    uint32_t                port_count = MAX_PORTS;
    bool                    is_field_suppoted, is_key_present;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == attr_id));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();
    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, attr_id, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%d) is not supported for this entry [%lx]\n",
                   attr_id,
                   key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
        key_id = FLEX_ACL_KEY_RX_PORT_LIST;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
        key_id = FLEX_ACL_KEY_TX_PORT_LIST;
        break;

    default:
        SX_LOG_ERR("Unexpeceted attr_id (%d)\n", attr_id);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_key_find(&rule, key_id, &key_index, &is_key_present);

    if (is_key_present) {
        if (key_id == FLEX_ACL_KEY_RX_PORT_LIST) {
            mc_container = rule.key_desc_list_p[key_index].key.rx_port_list.mc_container_id;
        } else { /* FLEX_ACL_KEY_TX_PORT_LIST */
            mc_container = rule.key_desc_list_p[key_index].key.tx_port_list.mc_container_id;
        }
    } else {
        mc_container = SX_MC_CONTAINER_ID_INVALID;
    }

    port_object_list = calloc(MAX_PORTS, sizeof(*port_object_list));
    if (!port_object_list) {
        SX_LOG_ERR("Failed to allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    status = mlnx_acl_sx_mc_container_sai_ports_get(mc_container, port_object_list, &port_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->aclfield.enable = (port_count > 0);

    status = mlnx_fill_objlist(port_object_list, port_count, &value->aclfield.data.objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&rule);
    free(port_object_list);

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
    sai_attr_id_t           attr_id;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_key_t            key_id = 0;
    mlnx_port_config_t     *port;
    uint32_t                key_desc_index;
    uint32_t                acl_table_index, acl_entry_index;
    bool                    is_field_suppoted, is_key_type_present = false;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == attr_id));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;

    default:
        SX_LOG_ERR("Unexpeceted attr_id (%d)\n", attr_id);
        return SAI_STATUS_FAILURE;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_table_is_entry_field_supported(acl_table_index, (int64_t)arg, &is_field_suppoted);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (false == is_field_suppoted) {
        SX_LOG_ERR("ACL Entry attribute (%d) is not supported for this entry [%lx]\n",
                   attr_id,
                   key->key.object_id);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, key_id, &key_desc_index, &is_key_type_present);

    value->aclfield.enable = true;

    if (is_key_type_present) {
        status = mlnx_port_by_log_id(flex_acl_rule.key_desc_list_p[key_desc_index].key.src_port, &port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("SX ACL rule contains a port %x which is not present in SAI DB\n",
                       flex_acl_rule.key_desc_list_p[key_desc_index].key.src_port);
            goto out;
        }

        value->aclfield.data.oid = port->saiport;
    } else {
        value->aclfield.enable = false;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

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
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    uint32_t                key_desc_index;
    uint32_t                acl_table_index, acl_entry_index;
    uint32_t                vlan_tagged_key_desc_index = 0, inner_vlan_valid_key_desc_index = 0;
    bool                    is_vlan_tagged = false, is_inner_vlan_valid = false, is_field_suppoted;

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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    for (key_desc_index = 0; key_desc_index < flex_acl_rule.key_desc_count; key_desc_index++) {
        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_VLAN_TAGGED) {
            is_vlan_tagged = true;
            vlan_tagged_key_desc_index = key_desc_index;
        }

        if (flex_acl_rule.key_desc_list_p[key_desc_index].key_id == FLEX_ACL_KEY_INNER_VLAN_VALID) {
            is_inner_vlan_valid = true;
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
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    const sx_acl_key_t     *sx_ip_ident_keys;
    uint32_t                first_sx_key_index, second_sx_key_index;
    uint32_t                acl_table_index, acl_entry_index;
    uint16_t                data, mask;
    bool                    is_first_sx_key_present, is_second_sx_key_present;

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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

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

    value->aclfield.enable = true;
    value->aclfield.data.u16 = htons(data);
    value->aclfield.mask.u16 = htons(mask);

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ip_ident_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sai_status_t            status;
    const sx_acl_key_t     *sx_ip_ident_keys;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    uint32_t                acl_table_index, acl_entry_index;
    uint32_t                first_sx_key_index, second_sx_key_index;
    bool                    is_first_sx_key_present, is_second_sx_key_present;

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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to fetch ACL rule params \n");
        goto out;
    }

    sx_ip_ident_keys = sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys;

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, sx_ip_ident_keys[0], &first_sx_key_index, &is_first_sx_key_present);
    mlnx_acl_flex_rule_key_find(&flex_acl_rule, sx_ip_ident_keys[1], &second_sx_key_index, &is_second_sx_key_present);

    if (is_first_sx_key_present != is_second_sx_key_present) {
        SX_LOG_ERR("Faield to get IP_IDENTIFICATION failed - sx rule is broken\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (is_first_sx_key_present) {
        mlnx_acl_flex_rule_key_del_by_key_id(&flex_acl_rule, sx_ip_ident_keys[0]);
        mlnx_acl_flex_rule_key_del_by_key_id(&flex_acl_rule, sx_ip_ident_keys[1]);
    }

    if (value->aclfield.enable) {
        mlnx_acl_ip_ident_key_desc_create(value->aclfield.data.u16, value->aclfield.mask.u16,
                                          flex_acl_rule.key_desc_list_p, flex_acl_rule.key_desc_count);
        flex_acl_rule.key_desc_count += ACL_IP_IDENT_FIELD_BYTE_COUNT;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

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
    sx_flex_acl_flex_rule_t         rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    const sx_flex_acl_port_range_t *sx_port_range;
    uint32_t                        acl_table_index, acl_entry_index;
    uint32_t                        key_desc_index, range_count, ii;
    bool                            is_range_key_present = false;

    SX_LOG_ENTER();

    assert(SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE == (int64_t)arg);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    mlnx_acl_flex_rule_key_find(&rule, FLEX_ACL_KEY_L4_PORT_RANGE, &key_desc_index, &is_range_key_present);

    if (false == is_range_key_present) {
        range_count = 0;
    } else {
        sx_port_range = &rule.key_desc_list_p[key_desc_index].key.l4_port_range;
        range_count = sx_port_range->port_range_cnt;
    }

    if (value->aclfield.data.objlist.count < range_count) {
        if (0 == value->aclfield.data.objlist.count) {
            status = MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST;
        } else {
            status = SAI_STATUS_BUFFER_OVERFLOW;
        }
        SX_LOG(((0 == value->aclfield.data.objlist.count) ? SX_LOG_NOTICE : SX_LOG_ERROR),
               " Re-allocate list size as list size is not large enough \n");
        value->aclfield.data.objlist.count = range_count;
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
    mlnx_acl_flex_rule_free(&rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_redirect_sx_to_sai(_In_ const sx_flex_acl_flex_action_t *sx_action,
                                                _In_ mlnx_acl_pbs_info_t              pbs_info,
                                                _Out_ sai_acl_action_data_t          *sai_action_data)
{
    sai_status_t        status;
    mlnx_bridge_port_t *bport = NULL;
    sx_ecmp_id_t        sx_ecmp_id;

    assert(sx_action);
    assert(sai_action_data);

    switch (sx_action->type) {
    case SX_FLEX_ACL_ACTION_PBS:
        status = mlnx_acl_pbs_info_to_sai_oid(pbs_info, &sai_action_data->parameter.oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SX_FLEX_ACL_ACTION_UC_ROUTE:
        sx_ecmp_id = sx_action->fields.action_uc_route.uc_route_param.ecmp_id;
        status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP, sx_ecmp_id, NULL,
                                    &sai_action_data->parameter.oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SX_FLEX_ACL_ACTION_NVE_TUNNEL_ENCAP:
        status = mlnx_bridge_port_by_tunnel_id(sx_action->fields.action_nve_tunnel_encap.tunnel_id, &bport);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_bridge_port_to_oid(bport, &sai_action_data->parameter.oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected sx action type - %d\n", sx_action->type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_tos_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }

    value->aclfield.enable = false;
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

    if (is_key_type_present || is_key_id_two_present) {
        value->aclfield.enable = true;
    }

    mlnx_acl_flex_rule_free(&flex_acl_rule);

out:
    acl_table_unlock(acl_table_index);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_trivial_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg)
{
    sai_status_t                  status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t       sx_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    const mlnx_acl_action_info_t *action_info;
    sai_acl_entry_attr_t          action_id;
    uint32_t                      table_db_idx, entry_db_idx, action_idx;
    bool                          is_action_type_present = false;

    SX_LOG_ENTER();

    action_id = (sai_acl_entry_attr_t)arg;

    status = mlnx_acl_action_info_find(action_id, 0, &action_info);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    if (action_info->convert_to_sx != NULL) {
        SX_LOG_ERR("mlnx_acl_entry_action_trivial_get is called for action with convert_fn\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &table_db_idx, &entry_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_read_lock(table_db_idx);

    status = mlnx_acl_entry_sx_acl_rule_get(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_action_find(&sx_rule, action_info->sx_type, &action_idx, &is_action_type_present);

    if (is_action_type_present) {
        value->aclaction.enable = true;
        memcpy(&value->aclaction.parameter, &sx_rule.action_list_p[action_idx].fields, action_info->field_size);
    } else {
        value->aclaction.enable = false;
    }

out:
    acl_table_unlock(table_db_idx);
    mlnx_acl_flex_rule_free(&sx_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_priority_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sai_status_t status;
    uint32_t     prio, sx_prio, acl_entry_index, acl_table_index;

    SX_LOG_ENTER();

    prio = value->u32;

    if (!ACL_SAI_ENTRY_PRIO_CHECK_RANGE(prio)) {
        SX_LOG_ERR("Priority %u is out of range (%u,%u)\n", prio, ACL_SAI_ENTRY_MIN_PRIO, ACL_SAI_ENTRY_MAX_PRIO);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    sx_prio = ACL_SAI_ENTRY_PRIO_TO_SX(prio);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = mlnx_acl_entry_prio_set(acl_table_index, acl_entry_index, sx_prio);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_db_entry(acl_entry_index).sx_prio = sx_prio;

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
    sai_acl_entry_attr_t       attr_id;
    const sx_acl_key_t        *ip_type_keys;
    sx_acl_key_t               field_keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    sx_flex_acl_key_desc_t     rule_extra_key_desc[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    sx_flex_acl_key_desc_t     rule_prev_key_desc[SX_FLEX_ACL_MAX_FIELDS_IN_KEY];
    sx_flex_acl_flex_rule_t    flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    mlnx_acl_field_type_t      field_type, current_fields_types;
    mlnx_acl_supported_stage_t field_stage;
    uint32_t                   acl_table_index, acl_entry_index;
    uint32_t                   field_key_count, field_extra_key_count = 0, ii;
    uint32_t                   field_key_index, found_key_index, ip_type_key_count;
    uint32_t                   rule_prev_key_desc_count = 0;
    mlnx_acl_supported_chip_t  supported_chip;
    bool                       is_key_present, is_field_stage_supported, is_key_supported;

    SX_LOG_ENTER();

    attr_id = (int64_t)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_ETHER_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_DSCP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ECN == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TTL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_CFI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TC == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_USER_META == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_PACKET_VLAN == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_TOS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_BTH_OPCODE == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE) == attr_id);

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    field_key_count = 0;

    status = mlnx_acl_field_info_data_fetch(attr_id,
                                            &field_type,
                                            field_keys,
                                            &field_key_count,
                                            &field_stage,
                                            &supported_chip);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = mlnx_acl_stage_is_supported(acl_db_table(acl_table_index).stage, field_stage, &is_field_stage_supported);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!is_field_stage_supported) {
        status = SAI_STATUS_INVALID_ATTRIBUTE_0;
        goto out;
    }

    status = mlnx_acl_key_is_supported(supported_chip, &is_key_supported);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!is_key_supported) {
        status = SAI_STATUS_INVALID_ATTRIBUTE_0;
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* Upadte of IP Type is limited
     * because all the L3/L4 keys use IP Type related keys
     * So it is only allowed when entry doesn't contain any L3/L4 fields
     */
    if (SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE == attr_id) {
        ip_type_keys = mlnx_acl_multi_key_fields_info[SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE].key_list;
        ip_type_key_count = mlnx_acl_multi_key_fields_info[SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE].key_count;

        for (ii = 0; ii < ip_type_key_count; ii++) {
            mlnx_acl_flex_rule_key_find(&flex_acl_rule, ip_type_keys[ii], &found_key_index, &is_key_present);

            if (is_key_present) {
                SX_LOG_ERR("Failed to update IP Type - entry already contains a field with specific IP Type\n");
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        }
    }

    /* Remove all the sx keys related to this sai field */
    for (field_key_index = 0; field_key_index < field_key_count; field_key_index++) {
        mlnx_acl_flex_rule_key_find(&flex_acl_rule,
                                    field_keys[field_key_index],
                                    &found_key_index,
                                    &is_key_present);

        if (is_key_present) {
            rule_prev_key_desc[rule_prev_key_desc_count] = flex_acl_rule.key_desc_list_p[found_key_index];
            rule_prev_key_desc_count++;

            mlnx_acl_flex_rule_key_del(&flex_acl_rule, found_key_index);
        }
    }

    status = mlnx_acl_entry_field_to_sx_update(attr_id, value, 0, acl_table_index,
                                               flex_acl_rule.key_desc_list_p,
                                               &flex_acl_rule.key_desc_count, &field_type,
                                               rule_prev_key_desc, rule_prev_key_desc_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* Checking if a new field doesn't put the entry into invalid state
     * e.g. setting IPv6 field while there is an IPv4, or setting ICMP field while there is L4 src port
     */
    status = mlnx_acl_sx_keys_to_field_type(flex_acl_rule.key_desc_list_p,
                                            flex_acl_rule.key_desc_count,
                                            &current_fields_types);
    if (SAI_ERR(status)) {
        goto out;
    }

    current_fields_types |= field_type;

    status = mlnx_acl_field_types_check(current_fields_types);
    if (SAI_ERR(status)) {
        goto out;
    }

#ifndef MLNX_ACL_SKIP_EXTRA_KEYS
    status = mlnx_acl_field_types_to_extra_sx_key_descs(field_type, rule_extra_key_desc, &field_extra_key_count);
    if (SAI_ERR(status)) {
        goto out;
    }
#endif /* MLNX_ACL_SKIP_EXTRA_KEYS */

    status = mlnx_acl_extra_key_descs_merge(&flex_acl_rule, rule_extra_key_desc, field_extra_key_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_ports_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t             status;
    sai_attr_id_t            attr_id;
    sx_acl_key_t             key_id;
    sx_flex_acl_flex_rule_t  flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_mc_container_id_t     mc_container = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_id_t     mc_container_to_delete = SX_MC_CONTAINER_ID_INVALID;
    const sai_object_list_t *new_ports_obj_list = NULL;
    mlnx_acl_port_db_refs_t  old_refs, new_refs;
    uint32_t                 acl_table_index, acl_entry_index;
    uint32_t                 key_desc_index, new_key_desc_index;
    bool                     is_key_type_present = false, update_sx_rule = false;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == attr_id));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);

    if ((SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS == attr_id) &&
        (acl_db_table(acl_table_index).stage != SAI_ACL_STAGE_EGRESS)) {
        SX_LOG_ERR("FIELD_OUT_PORTS in only supported for SAI_ACL_STAGE_EGRESS\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
        key_id = FLEX_ACL_KEY_RX_PORT_LIST;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
        key_id = FLEX_ACL_KEY_TX_PORT_LIST;
        break;

    default:
        SX_LOG_ERR("Unexpeceted attr_id (%d)\n", attr_id);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    new_ports_obj_list = NULL;

    if ((true == value->aclfield.enable) && (value->aclfield.data.objlist.count > 0)) {
        new_ports_obj_list = &value->aclfield.data.objlist;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&flex_acl_rule, old_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, key_id, &key_desc_index, &is_key_type_present);

    if (is_key_type_present) {
        if (key_id == FLEX_ACL_KEY_RX_PORT_LIST) {
            mc_container = flex_acl_rule.key_desc_list_p[key_desc_index].key.rx_port_list.mc_container_id;
        } else { /* FLEX_ACL_KEY_TX_PORT_LIST */
            mc_container = flex_acl_rule.key_desc_list_p[key_desc_index].key.tx_port_list.mc_container_id;
        }
    } else {
        mc_container = SX_MC_CONTAINER_ID_INVALID;
    }

    if (new_ports_obj_list) {
        if (is_key_type_present) {
            status = mlnx_acl_sx_mc_container_update(new_ports_obj_list, mc_container);
            if (SAI_ERR(status)) {
                goto out;
            }
        } else {
            status = mlnx_acl_sx_mc_container_create(new_ports_obj_list, &mc_container);
            if (SAI_ERR(status)) {
                goto out;
            }

            update_sx_rule = true;
        }
    } else {
        if (is_key_type_present) {
            mlnx_acl_flex_rule_key_del(&flex_acl_rule, key_desc_index);
            update_sx_rule = true;

            /* Will be deleted after sx rule update */
            mc_container_to_delete = mc_container;
        }
    }

    if (update_sx_rule) {
        if (new_ports_obj_list) {
            new_key_desc_index = flex_acl_rule.key_desc_count;

            switch (attr_id) {
            case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
                flex_acl_rule.key_desc_list_p[new_key_desc_index].key_id = key_id;
                flex_acl_rule.key_desc_list_p[new_key_desc_index].key.rx_port_list.match_type
                    =
                        SX_ACL_PORT_LIST_MATCH_POSITIVE;
                flex_acl_rule.key_desc_list_p[new_key_desc_index].key.rx_port_list.mc_container_id = mc_container;
                flex_acl_rule.key_desc_list_p[new_key_desc_index].mask.rx_port_list = true;
                flex_acl_rule.key_desc_count++;
                break;

            case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
                flex_acl_rule.key_desc_list_p[new_key_desc_index].key_id = key_id;
                flex_acl_rule.key_desc_list_p[new_key_desc_index].key.tx_port_list.match_type
                    =
                        SX_ACL_PORT_LIST_MATCH_POSITIVE;
                flex_acl_rule.key_desc_list_p[new_key_desc_index].key.tx_port_list.mc_container_id = mc_container;
                flex_acl_rule.key_desc_list_p[new_key_desc_index].mask.tx_port_list = true;
                flex_acl_rule.key_desc_count++;
                break;

            default:
                SX_LOG_ERR("Unexpeceted attr_id (%d)\n", attr_id);
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        }

        status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&flex_acl_rule, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_update(old_refs, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_sx_mc_container_remove(mc_container_to_delete);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove old sx_mc_container (%d)\n", mc_container_to_delete);
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_mirror_config_validate(_In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                    _In_ sx_flex_acl_flex_action_type_t sx_mirror_action_type,
                                                    _In_ sx_span_session_id_t           db_session)
{
    const mlnx_mirror_policer_t *mirror_policer = NULL;
    sx_span_session_id_t         sx_rule_session;
    uint32_t                     action_idx;
    bool                         is_action_present;

    assert(sx_rule);
    assert((sx_mirror_action_type == SX_FLEX_ACL_ACTION_MIRROR) ||
           (sx_mirror_action_type == SX_FLEX_ACL_ACTION_EGRESS_MIRROR));

    if (MLNX_ACL_SX_SPAN_SESSION_IS_VALID(db_session)) {
        if (SPAN_SESSION_MAX <= db_session) {
            SX_LOG_ERR("ACL DB sx_span_session %u is out of range [0, %u)\n",
                       db_session, SPAN_SESSION_MAX);
            return SAI_STATUS_FAILURE;
        }

        mirror_policer = &g_sai_db_ptr->mirror_policer[db_session];
    }

    mlnx_acl_flex_rule_action_find(sx_rule, sx_mirror_action_type, &action_idx, &is_action_present);

    if (is_action_present) {
        if (!MLNX_ACL_SX_SPAN_SESSION_IS_VALID(db_session)) {
            SX_LOG_ERR("SX Action mirror is present, but value in SAI DB is not valid\n");
            return SAI_STATUS_FAILURE;
        }

        if (sx_mirror_action_type == SX_FLEX_ACL_ACTION_MIRROR) {
            sx_rule_session = sx_rule->action_list_p[action_idx].fields.action_mirror.session_id;
        } else { /* SX_FLEX_ACL_ACTION_EGRESS_MIRROR */
            sx_rule_session = sx_rule->action_list_p[action_idx].fields.action_egress_mirror.session_id;
        }

        if (db_session != sx_rule_session) {
            SX_LOG_ERR("Span session in ACL db %d != span session in flex rule %d\n", db_session, sx_rule_session);
            return SAI_STATUS_FAILURE;
        }
    } else {
        if ((MLNX_ACL_SX_SPAN_SESSION_IS_VALID(db_session)) &&
            (mirror_policer->policer_oid == SAI_NULL_OBJECT_ID)) {
            SX_LOG_ERR("SX Action mirror is not present, but value in SAI DB is valid and policer is NULL\n");
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_port_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sai_status_t            status;
    sai_attr_id_t           attr_id;
    sai_object_id_t         new_port_object_id;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_port_log_id_t        sx_port = SX_INVALID_PORT;
    sx_acl_key_t            key_id;
    mlnx_acl_port_db_refs_t old_refs, new_refs;
    uint32_t                acl_entry_index, acl_table_index, key_desc_index, new_key_desc_index;
    bool                    is_key_type_present = false;

    SX_LOG_ENTER();

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == attr_id));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    new_port_object_id = SAI_NULL_OBJECT_ID;
    if (value->aclfield.enable) {
        new_port_object_id = value->aclfield.data.oid;
    }

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        key_id = FLEX_ACL_KEY_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        key_id = FLEX_ACL_KEY_DST_PORT;
        break;

    default:
        SX_LOG_ERR("Unexpeceted attr_id (%d)\n", attr_id);
        return SAI_STATUS_FAILURE;
    }

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);

    if ((SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT == attr_id) &&
        (acl_db_table(acl_table_index).stage != SAI_ACL_STAGE_EGRESS)) {
        SX_LOG_ERR("FIELD_OUT_PORT in only supported for SAI_ACL_STAGE_EGRESS\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_key_find(&flex_acl_rule, key_id, &key_desc_index, &is_key_type_present);

    if (SAI_NULL_OBJECT_ID != new_port_object_id) {
        status = mlnx_acl_field_port_to_sx(new_port_object_id, &sx_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to fetch sx port id from oid - %lx\n", new_port_object_id);
            goto out;
        }
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&flex_acl_rule, old_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (is_key_type_present) {
        mlnx_acl_flex_rule_key_del(&flex_acl_rule, key_desc_index);
    }

    new_key_desc_index = flex_acl_rule.key_desc_count;

    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
        if (SX_INVALID_PORT != sx_port) {
            flex_acl_rule.key_desc_list_p[new_key_desc_index].key_id = key_id;
            flex_acl_rule.key_desc_list_p[new_key_desc_index].key.src_port = sx_port;
            flex_acl_rule.key_desc_list_p[new_key_desc_index].mask.src_port = true;
            flex_acl_rule.key_desc_count++;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
        if (SX_INVALID_PORT != sx_port) {
            flex_acl_rule.key_desc_list_p[new_key_desc_index].key_id = key_id;
            flex_acl_rule.key_desc_list_p[new_key_desc_index].key.dst_port = sx_port;
            flex_acl_rule.key_desc_list_p[new_key_desc_index].mask.dst_port = true;
            flex_acl_rule.key_desc_count++;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected attr_id (%d)\n", attr_id);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&flex_acl_rule, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_update(old_refs, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_packet_action_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t                   status;
    sx_flex_acl_flex_rule_t        flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sai_packet_action_t            packet_action_type;
    sx_flex_acl_flex_action_type_t action_type;
    uint32_t                       flex_action_index;
    uint8_t                        trap_action_index = 0, forward_action_index = 0;
    bool                           is_trap_action_present = false, is_forward_action_present = false;
    uint32_t                       acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (flex_action_index = 0; flex_action_index < flex_acl_rule.action_count; flex_action_index++) {
        action_type = flex_acl_rule.action_list_p[flex_action_index].type;
        if (action_type == SX_FLEX_ACL_ACTION_TRAP) {
            is_trap_action_present = true;
            trap_action_index = flex_action_index;
        }

        if (action_type == SX_FLEX_ACL_ACTION_FORWARD) {
            is_forward_action_present = true;
            forward_action_index = flex_action_index;
        }

        if (is_forward_action_present && is_trap_action_present) {
            break;
        }
    }

    packet_action_type = value->aclaction.parameter.s32;

    if (is_forward_action_present) {
        mlnx_acl_flex_rule_action_del(&flex_acl_rule, forward_action_index);
    }

    if (is_trap_action_present) {
        mlnx_acl_flex_rule_action_del(&flex_acl_rule, trap_action_index);
    }

    flex_action_index = flex_acl_rule.action_count;

    if (value->aclaction.enable == true) {
        status = mlnx_acl_packet_actions_handler(packet_action_type, SX_TRAP_ID_ACL_MIN, flex_acl_rule.action_list_p,
                                                 &flex_action_index);
        if (SAI_ERR(status)) {
            goto out;
        }

        flex_acl_rule.action_count = flex_action_index;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_policer_check_allowed(_In_ sx_span_session_id_t entry_span_session)
{
    const mlnx_mirror_policer_t *mirror_policer;

    if (!MLNX_ACL_SX_SPAN_SESSION_IS_VALID(entry_span_session)) {
        return SAI_STATUS_SUCCESS;
    }

    mirror_policer = &g_sai_db_ptr->mirror_policer[entry_span_session];

    if (mirror_policer->policer_oid != SAI_NULL_OBJECT_ID) {
        SX_LOG_ERR("Cannot use ACTION_SET_POLICER in ACL Entry that has ACTION_SET_MIRROR with policer\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_action_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_status_t                   status;
    uint32_t                       flex_action_index;
    uint32_t                       action_set_policer_id_data;
    sx_flex_acl_flex_rule_t        flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    bool                           is_action_type_present = false;
    sx_flex_acl_flex_action_type_t action_type = 0;
    uint32_t                       acl_table_index, acl_entry_index;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == (int64_t)arg));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
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

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR:
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

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, action_type, &flex_action_index, &is_action_type_present);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
        status = mlnx_acl_entry_action_policer_check_allowed(acl_db_entry(acl_entry_index).sx_span_session);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (value->aclaction.enable == true) {
            status = mlnx_object_to_type(value->aclaction.parameter.oid, SAI_OBJECT_TYPE_POLICER,
                                         &action_set_policer_id_data, NULL);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }

            status = mlnx_sai_get_or_create_regular_sx_policer_for_bind(
                value->aclaction.parameter.oid,
                false,
                &flex_acl_rule.action_list_p[flex_action_index].fields.
                action_policer.policer_id);
            if (SAI_STATUS_SUCCESS != status) {
                SX_LOG_ERR("Failed to obtain sx_policer_id. input sai policer object_id:0x%" PRIx64 "\n",
                           value->aclaction.parameter.oid);
                goto out;
            }
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_POLICER;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_prio.prio_val =
                value->aclaction.parameter.u8;
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_PRIO;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dscp.dscp_val =
                value->aclaction.parameter.u8;
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_DSCP;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_ecn.ecn_val =
                value->aclaction.parameter.u8;
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_ECN;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_color.color_val =
                value->aclaction.parameter.s32;
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_COLOR;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].fields.action_dec_ttl.ttl_val = 1;
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_DEC_TTL;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA:
        if (value->aclaction.enable == true) {
            if (value->aclaction.parameter.u32 <= ACL_USER_META_RANGE_MAX) {
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_user_token.user_token =
                    (uint16_t)value->aclaction.parameter.u32;
                flex_acl_rule.action_list_p[flex_action_index].fields.action_set_user_token.mask =
                    ACL_USER_META_RANGE_MAX;
                flex_acl_rule.action_list_p[flex_action_index].type =
                    SX_FLEX_ACL_ACTION_SET_USER_TOKEN;
            } else {
                SX_LOG_ERR(" ACL user Meta value %u to Set is out of range [%d, %d] \n",
                           value->aclaction.parameter.u32,
                           ACL_USER_META_RANGE_MIN, ACL_USER_META_RANGE_MAX);
                status = SAI_STATUS_INVALID_PARAMETER;
                goto out;
            }
        }
        break;
    }

    if (value->aclaction.enable == false) {
        if (is_action_type_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule, flex_action_index);
        }
    } else {
        if (!is_action_type_present) {
            flex_acl_rule.action_count++;
        }
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_egress_block_port_set(_In_ const sai_object_key_t      *key,
                                                                _In_ const sai_attribute_value_t *value,
                                                                void                             *arg)
{
    sai_status_t                   status;
    sx_flex_acl_flex_action_type_t sx_action_type;
    sx_flex_acl_flex_rule_t        flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_mc_container_id_t           mc_container = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_id_t           mc_container_to_delete = SX_MC_CONTAINER_ID_INVALID;
    const sai_object_list_t       *new_ports_obj_list = NULL;
    mlnx_acl_port_db_refs_t        cur_refs, new_refs;
    uint32_t                       acl_table_index, acl_entry_index;
    uint32_t                       sx_action_index, new_sx_action_index;
    bool                           is_action_present = false, update_sx_rule = false;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    sx_action_type = SX_FLEX_ACL_ACTION_PORT_FILTER;

    sai_db_read_lock();
    acl_table_write_lock(acl_table_index);

    new_ports_obj_list = NULL;

    if ((true == value->aclaction.enable) && (value->aclaction.parameter.objlist.count > 0)) {
        new_ports_obj_list = &value->aclaction.parameter.objlist;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&flex_acl_rule, cur_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, sx_action_type, &sx_action_index, &is_action_present);

    if (is_action_present) {
        mc_container = flex_acl_rule.action_list_p[sx_action_index].fields.action_port_filter.mc_container_id;
    } else {
        mc_container = SX_MC_CONTAINER_ID_INVALID;
    }

    if (new_ports_obj_list) {
        if (is_action_present) {
            status = mlnx_acl_sx_mc_container_update(new_ports_obj_list, mc_container);
            if (SAI_ERR(status)) {
                goto out;
            }
        } else {
            status = mlnx_acl_sx_mc_container_create(new_ports_obj_list, &mc_container);
            if (SAI_ERR(status)) {
                goto out;
            }

            update_sx_rule = true;
        }
    } else {
        if (is_action_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule, sx_action_index);
            update_sx_rule = true;

            /* Will be deleted after sx rule update */
            mc_container_to_delete = mc_container;
        }
    }

    if (update_sx_rule) {
        if (new_ports_obj_list) {
            new_sx_action_index = flex_acl_rule.action_count;

            flex_acl_rule.action_list_p[new_sx_action_index].type = sx_action_type;
            flex_acl_rule.action_list_p[new_sx_action_index].fields.action_port_filter.mc_container_id
                = mc_container;
            flex_acl_rule.action_count++;
        }

        status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_acl_sx_mc_container_remove(mc_container_to_delete);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove old sx_mc_container (%d)\n", mc_container_to_delete);
        goto out;
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&flex_acl_rule, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_update(cur_refs, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_redirect_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg)
{
    sai_status_t            status;
    sai_attr_id_t           attr_id;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_pbs_id_t         sx_pbs_id;
    mlnx_acl_port_db_refs_t cur_refs, new_refs;
    mlnx_acl_pbs_info_t     cur_pbs_info = MLNX_ACL_PBS_INFO_INVALID, new_pbs_info = MLNX_ACL_PBS_INFO_INVALID;
    uint32_t                acl_table_index, acl_entry_index;
    uint32_t                ii, action_index;
    bool                    is_action_present;

    attr_id = (long)arg;

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_FLOOD == attr_id));

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

    cur_pbs_info = acl_db_entry(acl_entry_index).pbs_info;

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    is_action_present = false;
    action_index = flex_acl_rule.action_count;
    for (ii = 0; ii < flex_acl_rule.action_count; ii++) {
        if ((flex_acl_rule.action_list_p[ii].type == SX_FLEX_ACL_ACTION_PBS) ||
            (flex_acl_rule.action_list_p[ii].type == SX_FLEX_ACL_ACTION_UC_ROUTE) ||
            (flex_acl_rule.action_list_p[ii].type == SX_FLEX_ACL_ACTION_NVE_TUNNEL_ENCAP)) {
            if (is_action_present) {
                SX_LOG_ERR("Flex action type related to SAI Redirect actions appears twice in flex rule\n");
                status = SAI_STATUS_FAILURE;
                goto out;
            }

            is_action_present = true;
            action_index = ii;
        }
    }

    if (value->aclaction.enable) {
        switch (attr_id) {
        case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
            /* Nothing to update */
            if (is_action_present) {
                status = SAI_STATUS_SUCCESS;
                goto out;
            }

            status = mlnx_acl_flood_pbs_create_or_get(&sx_pbs_id, &new_pbs_info);
            if (SAI_ERR(status)) {
                goto out;
            }

            flex_acl_rule.action_list_p[action_index].type = SX_FLEX_ACL_ACTION_PBS;
            flex_acl_rule.action_list_p[action_index].fields.action_pbs.pbs_id = sx_pbs_id;
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST:
            status = mlnx_acl_pbs_ports_create_or_get(value->aclaction.parameter.objlist.list,
                                                      value->aclaction.parameter.objlist.count,
                                                      &sx_pbs_id,
                                                      &new_pbs_info);
            if (SAI_ERR(status)) {
                goto out;
            }

            flex_acl_rule.action_list_p[action_index].type = SX_FLEX_ACL_ACTION_PBS;
            flex_acl_rule.action_list_p[action_index].fields.action_pbs.pbs_id = sx_pbs_id;
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
            status = mlnx_sai_acl_redirect_action_create(value->aclaction.parameter.oid, 0,
                                                         &new_pbs_info,
                                                         &flex_acl_rule.action_list_p[action_index]);
            if (SAI_ERR(status)) {
                goto out;
            }
            break;

        default:
            SX_LOG_ERR("Unexpected attr_id - %d\n", attr_id);
            return SAI_STATUS_FAILURE;
        }

        if (!is_action_present) {
            flex_acl_rule.action_count++;
        }
    } else {
        if (is_action_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule, action_index);
        }
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_db_entry(acl_entry_index).pbs_info = new_pbs_info;

    status = mlnx_acl_pbs_info_port_refs_get(cur_pbs_info, cur_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_pbs_info_port_refs_get(new_pbs_info, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_update(cur_refs, new_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_pbs_info_delete(cur_pbs_info);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    if (SAI_ERR(status)) {
        mlnx_acl_pbs_info_delete(new_pbs_info);
    }

    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_endpoint_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg)
{
    sai_status_t            status;
    uint32_t                acl_table_index, acl_entry_index;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    uint32_t                action_index;
    bool                    is_action_present;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_action_find(&flex_acl_rule,
                                   SX_FLEX_ACL_ACTION_NVE_TUNNEL_ENCAP,
                                   &action_index,
                                   &is_action_present);

    status = mlnx_acl_redirect_endpoint_set(&value->aclaction, 0, is_action_present, action_index,
                                            flex_acl_rule.action_list_p, &flex_acl_rule.action_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_mac_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    sai_status_t                   status;
    sx_flex_acl_flex_rule_t        flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_flex_acl_flex_action_type_t action_type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
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

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, action_type, &flex_action_index, &is_action_type_present);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_MAC:
        if (value->aclaction.enable == true) {
            memcpy(&flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac,
                   value->aclaction.parameter.mac,
                   sizeof(flex_acl_rule.action_list_p[flex_action_index].fields.action_set_src_mac.mac));
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_SRC_MAC;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_MAC:
        if (value->aclaction.enable == true) {
            memcpy(&flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dst_mac.mac,
                   value->aclaction.parameter.mac,
                   sizeof(flex_acl_rule.action_list_p[flex_action_index].fields.action_set_dst_mac.mac));
            flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_SET_DST_MAC;
        }
        break;
    }

    if (value->aclaction.enable == false) {
        if (is_action_type_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule, flex_action_index);
        }
    } else {
        if (!is_action_type_present) {
            flex_acl_rule.action_count++;
        }
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_vlan_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg)
{
    sai_status_t                   status;
    sx_flex_acl_flex_rule_t        flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_flex_acl_flex_action_type_t action_type = 0;
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

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
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
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_INNER_VLAN_ID;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_id.vlan_id =
                value->aclaction.parameter.u16;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_INNER_VLAN_PRI;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_inner_vlan_prio.pcp =
                value->aclaction.parameter.u8;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_ID:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_ID;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_id.vlan_id =
                value->aclaction.parameter.u16;
        }
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI:
        if (value->aclaction.enable == true) {
            flex_acl_rule.action_list_p[flex_action_index].type =
                SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_PRI;
            flex_acl_rule.action_list_p[flex_action_index].fields.action_set_outer_vlan_prio.pcp =
                value->aclaction.parameter.u8;
            break;
        }
        break;
    }
    if (value->aclaction.enable == false) {
        if (is_action_type_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule, flex_action_index);
        }
    } else {
        if (!is_action_type_present) {
            flex_acl_rule.action_count++;
        }
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_action_counter_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_flow_counter_id_t    sx_counter_id;
    uint32_t                flex_action_index;
    uint32_t                acl_table_index, acl_entry_index, counter_table_idx;
    bool                    is_action_type_present = false;
    bool                    counter_byte_flag, counter_packet_flag;

    SX_LOG_ENTER();

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_action_find(&flex_acl_rule, SX_FLEX_ACL_ACTION_COUNTER,
                                   &flex_action_index, &is_action_type_present);

    if (value->aclaction.enable == false) {
        if (is_action_type_present) {
            mlnx_acl_flex_rule_action_del(&flex_acl_rule, flex_action_index);

            acl_db_entry(acl_entry_index).sx_counter_id = SX_FLOW_COUNTER_ID_INVALID;
        }
    } else {
        status = mlnx_acl_counter_oid_data_get(value->aclaction.parameter.oid,
                                               &sx_counter_id,
                                               &counter_byte_flag,
                                               &counter_packet_flag,
                                               &counter_table_idx);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (counter_table_idx != acl_table_index) {
            SX_LOG_ERR("Failed to set counter oid %lx - counter's table %d != entry's table %d\n",
                       value->aclaction.parameter.oid, counter_table_idx, acl_table_index);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0;
            goto out;
        }

        flex_acl_rule.action_list_p[flex_action_index].fields.action_counter.counter_id = sx_counter_id;
        flex_acl_rule.action_list_p[flex_action_index].type = SX_FLEX_ACL_ACTION_COUNTER;
        if (!is_action_type_present) {
            flex_acl_rule.action_count++;
        }

        acl_db_entry(acl_entry_index).sx_counter_id = sx_counter_id;
        acl_db_entry(acl_entry_index).counter_byte_flag = counter_byte_flag;
        acl_db_entry(acl_entry_index).counter_packet_flag = counter_packet_flag;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_packet_actions_handler(_In_ sai_packet_action_t           packet_action_type,
                                                    _In_ uint16_t                      trap_id,
                                                    _Inout_ sx_flex_acl_flex_action_t *flex_actions,
                                                    _Inout_ uint32_t                  *flex_action_index)
{
    sx_status_t status = SAI_STATUS_SUCCESS;
    uint32_t    a_index = *flex_action_index;

    SX_LOG_ENTER();

    switch (packet_action_type) {
    case SAI_PACKET_ACTION_DROP:
        flex_actions[a_index].fields.action_forward.action = SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_FORWARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_FORWARD:
        flex_actions[a_index].fields.action_forward.action = SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD;
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_FORWARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_COPY:
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_TRAP;
        flex_actions[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_TRAP;
        flex_actions[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        break;

    case SAI_PACKET_ACTION_COPY_CANCEL:
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_TRAP;
        flex_actions[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        flex_actions[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        break;

    case SAI_PACKET_ACTION_LOG:
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_TRAP;
        flex_actions[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_TRAP;
        flex_actions[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_FORWARD;
        flex_actions[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_TRAP:
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_TRAP;
        flex_actions[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_TRAP;
        flex_actions[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_FORWARD;
        flex_actions[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_DENY:
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_TRAP;
        flex_actions[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_DISCARD;
        flex_actions[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_FORWARD;
        flex_actions[a_index].fields.action_forward.action =
            SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD;
        a_index++;
        break;

    case SAI_PACKET_ACTION_TRANSIT:
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_TRAP;
        flex_actions[a_index].fields.action_trap.action =
            SX_ACL_TRAP_ACTION_TYPE_DISCARD;
        flex_actions[a_index].fields.action_trap.trap_id = trap_id;
        a_index++;
        flex_actions[a_index].type = SX_FLEX_ACL_ACTION_FORWARD;
        flex_actions[a_index].fields.action_forward.action =
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

static sai_status_t mlnx_acl_entry_action_ip_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t                   status;
    sai_acl_entry_attr_t           action;
    mlnx_acl_action_ctx_t          action_ctx = MLNX_ACL_ACTION_CTX_EMPTY;
    sx_flex_acl_flex_rule_t        sx_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_flex_acl_flex_action_type_t sx_action;
    uint32_t                       action_index;
    uint32_t                       table_db_idx, entry_db_idx;
    bool                           is_action_type_present = false;

    SX_LOG_ENTER();

    action = (int64_t)arg;

    assert((action == SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6));

    switch (action) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP:
        sx_action = SX_FLEX_ACL_ACTION_SET_SIP_ADDR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP:
        sx_action = SX_FLEX_ACL_ACTION_SET_DIP_ADDR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6:
        sx_action = SX_FLEX_ACL_ACTION_SET_SIPV6_ADDR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6:
        sx_action = SX_FLEX_ACL_ACTION_SET_DIPV6_ADDR;
        break;

    default:
        return SAI_STATUS_FAILURE;
    }

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &table_db_idx, &entry_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(table_db_idx);

    status = mlnx_acl_entry_sx_acl_rule_get(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_action_find(&sx_rule, sx_action, &action_index, &is_action_type_present);

    if (is_action_type_present) {
        mlnx_acl_flex_rule_action_del(&sx_rule, action_index);
    }

    if (value->aclaction.enable) {
        status = mlnx_acl_action_ip_to_sx(action, &value->aclaction, 0, &acl_db_table(table_db_idx), &action_ctx,
                                          sx_rule.action_list_p, &sx_rule.action_count);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_acl_entry_sx_acl_rule_set(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(table_db_idx);

    mlnx_acl_flex_rule_free(&sx_rule);
    return status;
}

static sai_status_t mlnx_acl_entry_action_l4port_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t                   status;
    sai_acl_entry_attr_t           action;
    sx_flex_acl_flex_rule_t        sx_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_flex_acl_flex_action_type_t sx_action;
    uint32_t                       action_index;
    uint32_t                       table_db_idx, entry_db_idx;
    bool                           is_action_type_present = false;

    SX_LOG_ENTER();

    action = (int64_t)arg;

    assert((action == SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT));

    switch (action) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT:
        sx_action = SX_FLEX_ACL_ACTION_SET_L4_SRC_PORT;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT:
        sx_action = SX_FLEX_ACL_ACTION_SET_L4_DST_PORT;
        break;

    default:
        return SAI_STATUS_FAILURE;
    }

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &table_db_idx, &entry_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(table_db_idx);

    status = mlnx_acl_entry_sx_acl_rule_get(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    mlnx_acl_flex_rule_action_find(&sx_rule, sx_action, &action_index, &is_action_type_present);

    if (is_action_type_present) {
        mlnx_acl_flex_rule_action_del(&sx_rule, action_index);
    }

    if (value->aclaction.enable) {
        sx_rule.action_list_p[sx_rule.action_count].type = sx_action;
        switch (action) {
        case SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_SRC_PORT:
            sx_rule.action_list_p[sx_rule.action_count].fields.action_set_l4_src_port.l4_port =
                value->aclaction.parameter.u16;
            break;

        case SAI_ACL_ENTRY_ATTR_ACTION_SET_L4_DST_PORT:
            sx_rule.action_list_p[sx_rule.action_count].fields.action_set_l4_dst_port.l4_port =
                value->aclaction.parameter.u16;
            break;

        default:
            return SAI_STATUS_FAILURE;
        }

        sx_rule.action_count++;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(table_db_idx);

    mlnx_acl_flex_rule_free(&sx_rule);
    return status;
}

static sai_status_t mlnx_acl_ip_ident_key_create_or_get(_Out_ sx_acl_key_t *keys)
{
    sai_status_t                         status;
    sx_acl_custom_bytes_set_attributes_t sx_custom_bytes_attrs;

    assert(NULL != keys);

    if (0 == sai_acl_db->acl_settings_tbl->ip_ident_keys.refs) {
        memset(&sx_custom_bytes_attrs, 0, sizeof(sx_custom_bytes_attrs));

        sx_custom_bytes_attrs.extraction_point.extraction_group_type =
            SX_ACL_CUSTOM_BYTES_EXTRACTION_GROUP_L3;
        sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_ipv4.extraction_point_type =
            SX_ACL_CUSTOM_BYTES_EXTRACTION_POINT_TYPE_IPV4_START_OF_HEADER;

        sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_ipv4.offset =
            ACL_IP_IDENT_FIELD_START_OFFSET;

        status = mlnx_custom_bytes_set(SX_ACCESS_CMD_CREATE, &sx_custom_bytes_attrs,
                                       sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys,
                                       ACL_IP_IDENT_FIELD_BYTE_COUNT);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    sai_acl_db->acl_settings_tbl->ip_ident_keys.refs++;

    memcpy(keys, sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys,
           sizeof(sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_ip_ident_key_ref_remove(void)
{
    sai_status_t                         status;
    sx_acl_custom_bytes_set_attributes_t sx_custom_bytes_attrs;

    assert(sai_acl_db->acl_settings_tbl->ip_ident_keys.refs > 0);

    sai_acl_db->acl_settings_tbl->ip_ident_keys.refs--;

    if (0 == sai_acl_db->acl_settings_tbl->ip_ident_keys.refs) {
        memset(&sx_custom_bytes_attrs, 0, sizeof(sx_custom_bytes_attrs));

        status = mlnx_custom_bytes_set(SX_ACCESS_CMD_DESTROY, &sx_custom_bytes_attrs,
                                       sai_acl_db->acl_settings_tbl->ip_ident_keys.sx_keys,
                                       ACL_IP_IDENT_FIELD_BYTE_COUNT);
        if (SAI_ERR(status)) {
            return status;
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
    mask = ntohs(mask);

    key_descs[key_desc_count].key_id = ip_ident_keys[0];
    key_descs[key_desc_count].key.custom_byte = value & 0xFF;
    key_descs[key_desc_count].mask.custom_byte = mask & 0xFF;

    key_descs[key_desc_count + 1].key_id = ip_ident_keys[1];
    key_descs[key_desc_count + 1].key.custom_byte = (value >> 8) & 0xFF;
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

static sai_status_t mlnx_acl_action_eg_block_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                   _In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ const acl_table_db_t        *table,
                                                   _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t         status;
    sx_mc_container_id_t mc_container;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    assert(ctx->sx_mc_container_egress_block == SX_MC_CONTAINER_ID_INVALID);

    status = mlnx_acl_sx_mc_container_create(&action_data->parameter.objlist,
                                             &mc_container);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_PORT_FILTER;
    sx_action_list[*sx_action_count].fields.action_port_filter.mc_container_id = mc_container;
    (*sx_action_count)++;

    ctx->sx_mc_container_egress_block = mc_container;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_eg_block_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                    _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                    _In_ const acl_entry_db_t          *entry,
                                                    _In_ const acl_table_db_t          *table,
                                                    _In_ uint32_t                       attr_index,
                                                    _Out_ sai_acl_action_data_t        *action_data)
{
    sai_status_t         status;
    sx_mc_container_id_t mc_container;
    sai_object_id_t     *ports_oids = NULL;
    uint32_t             action_idx, ports_count = MAX_PORTS;
    bool                 is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(action_data);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_PORT_FILTER, &action_idx, &is_action_present);

    if (!is_action_present) {
        action_data->enable = false;
        action_data->parameter.objlist.count = 0;
        return SAI_STATUS_SUCCESS;
    }

    mc_container = sx_rule->action_list_p[action_idx].fields.action_port_filter.mc_container_id;

    ports_oids = calloc(MAX_PORTS, sizeof(sai_object_id_t));
    if (!ports_oids) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    status = mlnx_acl_sx_mc_container_sai_ports_get(mc_container, ports_oids, &ports_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    action_data->enable = (ports_count > 0);

    status = mlnx_fill_objlist(ports_oids, ports_count, &action_data->parameter.objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    free(ports_oids);
    return status;
}

static sai_status_t mlnx_acl_action_redirect_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                   _In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ const acl_table_db_t        *table,
                                                   _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t        status;
    mlnx_acl_pbs_info_t pbs_info = MLNX_ACL_PBS_INFO_INVALID;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    if (ctx->is_redirect_action_present) {
        SX_LOG_ERR("Only one of redirect actions (redirect/redirect_list/flood) is allowed in single entry\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_sai_acl_redirect_action_create(action_data->parameter.oid,
                                                 attr_index, &pbs_info,
                                                 &sx_action_list[*sx_action_count]);
    if (SAI_ERR(status)) {
        return status;
    }

    if (sx_action_list[*sx_action_count].type == SX_FLEX_ACL_ACTION_NVE_TUNNEL_ENCAP) {
        ctx->is_redirect_endpoint_needed = true;
        ctx->redirect_action_idx = *sx_action_count;
    }

    (*sx_action_count)++;

    ctx->is_redirect_action_present = true;
    ctx->pbs_info = pbs_info;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_redirect_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                    _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                    _In_ const acl_entry_db_t          *entry,
                                                    _In_ const acl_table_db_t          *table,
                                                    _In_ uint32_t                       attr_index,
                                                    _Out_ sai_acl_action_data_t        *action_data)
{
    sai_status_t        status;
    sai_object_id_t    *pbs_ports = NULL;
    mlnx_acl_pbs_info_t pbs_info;
    uint32_t            action_index = 0, pbs_ports_number, ii;
    bool                is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(action_data);

    assert((SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == action) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST == action));

    pbs_info = entry->pbs_info;

    is_action_present = false;
    for (ii = 0; ii < sx_rule->action_count; ii++) {
        if ((sx_rule->action_list_p[ii].type == SX_FLEX_ACL_ACTION_PBS) ||
            (sx_rule->action_list_p[ii].type == SX_FLEX_ACL_ACTION_UC_ROUTE) ||
            (sx_rule->action_list_p[ii].type == SX_FLEX_ACL_ACTION_NVE_TUNNEL_ENCAP)) {
            if (is_action_present) {
                SX_LOG_ERR("Flex action type related to SAI Redirect actions appears twice in flex rule\n");
                return SAI_STATUS_FAILURE;
            }

            is_action_present = true;
            action_index = ii;
        }
    }

    if (!is_action_present) {
        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    if ((sx_rule->action_list_p[action_index].type == SX_FLEX_ACL_ACTION_PBS) &&
        (!MLNX_ACL_PBS_INFO_IS_VALID(pbs_info))) {
        SX_LOG_ERR("Invalid ACL entry DB state: SX_FLEX_ACL_ACTION_PBS is present but pbs_info is not valid\n");
        return SAI_STATUS_FAILURE;
    }

    action_data->enable = true;

    if (action == SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT) {
        status = mlnx_acl_redirect_sx_to_sai(&sx_rule->action_list_p[action_index], pbs_info, action_data);
        if (SAI_ERR(status)) {
            return status;
        }
    } else { /* SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST */
        pbs_ports_number = MAX_PORTS;
        pbs_ports = calloc(MAX_PORTS, sizeof(*pbs_ports));
        if (!pbs_ports) {
            SX_LOG_ERR("Failed to allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        status = mlnx_acl_pbs_info_sai_ports_get(pbs_info, pbs_ports, &pbs_ports_number);
        if (SAI_ERR(status)) {
            free(pbs_ports);
            return status;
        }

        status = mlnx_fill_objlist(pbs_ports, pbs_ports_number, &action_data->parameter.objlist);
        if (SAI_ERR(status)) {
            free(pbs_ports);
            return status;
        }
    }

    free(pbs_ports);
    return SAI_STATUS_SUCCESS;
}

static sx_flex_acl_flex_action_type_t mlnx_acl_mirror_sx_direction_to_sx_action(_In_ sx_acl_direction_t sx_direction)
{
    assert(sx_direction < SX_ACL_DIRECTION_LAST);

    switch (sx_direction) {
    case SX_ACL_DIRECTION_INGRESS:
    case SX_ACL_DIRECTION_RIF_INGRESS:
    case SX_ACL_DIRECTION_RIF_EGRESS:
        return SX_FLEX_ACL_ACTION_MIRROR;

    case SX_ACL_DIRECTION_EGRESS:
        return SX_FLEX_ACL_ACTION_EGRESS_MIRROR;

    default:
        return SX_FLEX_ACL_FLEX_ACTION_TYPE_MAX;
    }
}

static sai_status_t mlnx_acl_mirror_acl_create(_In_ mlnx_mirror_policer_acl_t *acl,
                                               _In_ sx_acl_direction_t         sx_direction,
                                               _In_ sx_span_session_id_t       sx_span_session)
{
    sai_status_t                   status = SAI_STATUS_SUCCESS;
    sx_status_t                    sx_status;
    sx_acl_key_t                   keys[1];
    sx_acl_key_type_t              key_handle;
    sx_acl_region_id_t             region_id;
    sx_acl_region_group_t          region_group;
    sx_acl_id_t                    acl_id, acl_group;
    sx_flex_acl_flex_rule_t        rules[2] = {MLNX_ACL_SX_FLEX_RULE_EMPTY, MLNX_ACL_SX_FLEX_RULE_EMPTY};
    sx_flex_acl_flex_action_type_t action_type;
    sx_acl_rule_offset_t           offsets[2] = { 0, 1 };

    assert(acl);
    assert(sx_direction < SX_ACL_DIRECTION_LAST);
    assert(sx_span_session < SPAN_SESSION_MAX);

    action_type = mlnx_acl_mirror_sx_direction_to_sx_action(sx_direction);
    keys[0] = FLEX_ACL_KEY_COLOR;

    sx_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_CREATE, keys, 1, &key_handle);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR(" Failed to create flex key - %s. \n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl->key = key_handle;

    sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_CREATE, key_handle,
                                      SX_ACL_ACTION_TYPE_BASIC, 2, &region_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create region - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl->region = region_id;

    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    region_group.regions.acl_packet_agnostic.region = region_id;

    sx_status = sx_api_acl_set(gh_sdk,
                               SX_ACCESS_CMD_CREATE,
                               SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC,
                               sx_direction,
                               &region_group,
                               &acl_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create acl - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl->acl = acl_id;

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_direction, NULL, 0, &acl_group);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create acl group - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_direction, &acl_id, 1, &acl_group);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create acl group - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_lib_flex_acl_rule_init(key_handle, ACL_MAX_NUM_OF_ACTIONS, &rules[0]);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_lib_flex_acl_rule_init(key_handle, ACL_MAX_NUM_OF_ACTIONS, &rules[1]);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to init acl rule - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    rules[0].valid = true;
    rules[0].key_desc_list_p[0].key_id = FLEX_ACL_KEY_COLOR;
    rules[0].key_desc_list_p[0].key.color = 0;  /* green */
    rules[0].key_desc_list_p[0].mask.color = true;
    rules[0].key_desc_count = 1;

    rules[0].action_list_p[0].type = action_type;
    rules[0].action_list_p[0].fields.action_mirror.session_id = sx_span_session;
    rules[0].action_count = 1;

    rules[1].valid = true;
    rules[1].key_desc_list_p[0].key_id = FLEX_ACL_KEY_COLOR;
    rules[1].key_desc_list_p[0].key.color = 0;  /* green */
    rules[1].key_desc_list_p[0].mask.color = false; /* match all */
    rules[1].key_desc_count = 1;

    rules[1].action_list_p[0].type = SX_FLEX_ACL_ACTION_SET_COLOR;
    rules[1].action_list_p[0].fields.action_set_color.color_val = SX_ACL_FLEX_COLOR_GREEN;
    rules[1].action_count = 1;

    sx_status = sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, offsets, rules, 2);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set acl rule - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl->is_acl_created = true;
    acl->acl_group = acl_group;

out:
    mlnx_acl_flex_rule_free(&rules[0]);
    mlnx_acl_flex_rule_free(&rules[1]);

    return status;
}

static sai_status_t mlnx_acl_mirror_acl_remove(_In_ mlnx_mirror_policer_acl_t *acl,
                                               _In_ sx_acl_direction_t         sx_direction)
{
    sx_status_t sx_status;

    assert(acl);
    assert(sx_direction < SX_ACL_DIRECTION_LAST);

    if (!acl->is_acl_created) {
        return SAI_STATUS_SUCCESS;
    }

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, sx_direction, NULL, 0, &acl->acl_group);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create acl group - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_acl_set(gh_sdk,
                               SX_ACCESS_CMD_DESTROY,
                               SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC,
                               sx_direction,
                               NULL,
                               &acl->acl);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy acl - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_DESTROY, acl->key,
                                      SX_ACL_ACTION_TYPE_BASIC, 1, &acl->region);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy region - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_DELETE, NULL, 0, &acl->key);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy flex key - %s. \n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl->is_acl_created = false;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_mirror_action_ref_update(_In_ sx_span_session_id_t sx_span_session,
                                                      _In_ sx_acl_direction_t   sx_direction,
                                                      _In_ bool                 is_add)
{
    sai_status_t               status;
    mlnx_mirror_policer_t     *mirror_policer;
    mlnx_mirror_policer_acl_t *mirror_extra_acl;

    if (!MLNX_ACL_SX_SPAN_SESSION_IS_VALID(sx_span_session)) {
        return SAI_STATUS_SUCCESS;
    }

    assert(sx_span_session < SPAN_SESSION_MAX);
    assert(sx_direction < SX_ACL_DIRECTION_LAST);

    mirror_policer = &g_sai_db_ptr->mirror_policer[sx_span_session];
    mirror_extra_acl = &mirror_policer->extra_acl[sx_direction];

    if (is_add) {
        mirror_extra_acl->refs++;
        SX_LOG_DBG("Added a ref: mirror_policer[%d] refs = %u\n", sx_span_session, mirror_extra_acl->refs);
    } else {
        if (mirror_extra_acl->refs == 0) {
            SX_LOG_ERR("Attempt to decrease a ref for span session %d while the ref is 0\n", sx_span_session);
            return SAI_STATUS_FAILURE;
        }

        mirror_extra_acl->refs--;
        SX_LOG_DBG("Dec a ref: mirror_policer[%d] refs = %u\n", sx_span_session, mirror_extra_acl->refs);

        if (mirror_extra_acl->refs == 0) {
            status = mlnx_acl_mirror_acl_remove(mirror_extra_acl, sx_direction);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_mirror_session_ref_inc(_In_ sx_span_session_id_t sx_span_session,
                                                    _In_ sx_acl_direction_t   sx_direction)
{
    return mlnx_acl_mirror_action_ref_update(sx_span_session, sx_direction, true);
}

static sai_status_t mlnx_acl_mirror_session_ref_dec(_In_ sx_span_session_id_t sx_span_session,
                                                    _In_ sx_acl_direction_t   sx_direction)
{
    return mlnx_acl_mirror_action_ref_update(sx_span_session, sx_direction, false);
}

static sai_status_t mlnx_acl_mirror_policer_extra_actions_add(_Out_ sx_flex_acl_flex_action_t *sx_action_list,
                                                              _Inout_ uint32_t                *action_count,
                                                              _In_ sx_acl_direction_t          sx_direction,
                                                              _In_ sx_span_session_id_t        sx_span_session)
{
    sai_status_t               status;
    mlnx_mirror_policer_t     *mirror_policer;
    mlnx_mirror_policer_acl_t *extra_acl;
    sx_policer_id_t            sx_policer_id;

    assert(sx_action_list);
    assert(action_count);
    assert(sx_direction < SX_ACL_DIRECTION_LAST);
    assert(sx_span_session < SPAN_SESSION_MAX);

    mirror_policer = &g_sai_db_ptr->mirror_policer[sx_span_session];

    if (mirror_policer->policer_oid == SAI_NULL_OBJECT_ID) {
        SX_LOG_DBG("Policer for mirror session %d is not set\n", sx_span_session);
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_sai_get_or_create_mirror_sx_policer_for_bind(mirror_policer->policer_oid, &sx_policer_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_action_list[*action_count].type = SX_FLEX_ACL_ACTION_POLICER;
    sx_action_list[*action_count].fields.action_policer.policer_id = sx_policer_id;
    (*action_count)++;

    extra_acl = &mirror_policer->extra_acl[sx_direction];
    if (!extra_acl->is_acl_created) {
        status = mlnx_acl_mirror_acl_create(extra_acl, sx_direction, sx_span_session);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    sx_action_list[*action_count].type = SX_FLEX_ACL_ACTION_GOTO;
    sx_action_list[*action_count].fields.action_goto.acl_group_id = extra_acl->acl_group;
    sx_action_list[*action_count].fields.action_goto.goto_action_cmd = SX_ACL_ACTION_GOTO_CALL;
    (*action_count)++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_mirror_policer_extra_action_del(_In_ sx_flex_acl_flex_rule_t *sx_rule)
{
    uint32_t policer_action_idx, goto_action_idx;
    bool     is_policer_action_present, is_goto_action_present;

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_POLICER, &policer_action_idx,
                                   &is_policer_action_present);
    if (is_policer_action_present) {
        mlnx_acl_flex_rule_action_del(sx_rule, policer_action_idx);
    }

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_GOTO, &goto_action_idx, &is_goto_action_present);
    if (is_goto_action_present) {
        mlnx_acl_flex_rule_action_del(sx_rule, goto_action_idx);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_mirror_action_bind(_Out_ sx_flex_acl_flex_action_t *sx_action_list,
                                                      _Inout_ uint32_t                *action_count,
                                                      _In_ sx_acl_direction_t          sx_direction,
                                                      _In_ sx_span_session_id_t        sx_span_session)
{
    sai_status_t                   status;
    const mlnx_mirror_policer_t   *mirror_policer;
    sx_flex_acl_flex_action_type_t sx_mirror_action;

    assert(sx_action_list);
    assert(action_count);
    assert(sx_span_session < SPAN_SESSION_MAX);

    mirror_policer = &g_sai_db_ptr->mirror_policer[sx_span_session];
    sx_mirror_action = mlnx_acl_mirror_sx_direction_to_sx_action(sx_direction);

    /* Regular ACTION_MIRROR */
    if (mirror_policer->policer_oid == SAI_NULL_OBJECT_ID) {
        sx_action_list[*action_count].type = sx_mirror_action;

        if (sx_mirror_action == SX_FLEX_ACL_ACTION_MIRROR) {
            sx_action_list[*action_count].fields.action_mirror.session_id = sx_span_session;
        } else { /* SX_FLEX_ACL_ACTION_EGRESS_MIRROR */
            sx_action_list[*action_count].fields.action_egress_mirror.session_id = sx_span_session;
        }

        (*action_count)++;
    } else {
        status =
            mlnx_acl_mirror_policer_extra_actions_add(sx_action_list, action_count, sx_direction, sx_span_session);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_mirror_action_unbind(_In_ sx_flex_acl_flex_rule_t *sx_rule,
                                                        _In_ sx_acl_direction_t       sx_direction)
{
    sai_status_t                   status;
    sx_flex_acl_flex_action_type_t sx_mirror_action;
    uint32_t                       mirror_action_idx;
    bool                           is_mirror_action_present;

    assert(sx_rule);

    sx_mirror_action = mlnx_acl_mirror_sx_direction_to_sx_action(sx_direction);

    mlnx_acl_flex_rule_action_find(sx_rule, sx_mirror_action, &mirror_action_idx, &is_mirror_action_present);
    if (is_mirror_action_present) {
        mlnx_acl_flex_rule_action_del(sx_rule, mirror_action_idx);
    }

    status = mlnx_acl_mirror_policer_extra_action_del(sx_rule);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_mirror_policer_update_check_allowed(_In_ const sx_flex_acl_flex_rule_t *sx_rule)
{
    uint32_t policer_action_idx, goto_action_idx;
    bool     is_policer_action_present, is_goto_action_present;

    assert(sx_rule);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_POLICER, &policer_action_idx,
                                   &is_policer_action_present);
    if (is_policer_action_present) {
        mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_GOTO, &goto_action_idx, &is_goto_action_present);
        if (!is_goto_action_present) {
            SX_LOG_ERR("Failed to update a policer on mirror session - ACL entry contains ACTION_SET_POLICER\n");
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_mirror_action_check_allowed(_In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                               _In_ sx_span_session_id_t           sx_span_session)
{
    const mlnx_mirror_policer_t *mirror_policer;

    if (!MLNX_ACL_SX_SPAN_SESSION_IS_VALID(sx_span_session)) {
        return SAI_STATUS_SUCCESS;
    }

    mirror_policer = &g_sai_db_ptr->mirror_policer[sx_span_session];
    if (mirror_policer->policer_oid == SAI_NULL_OBJECT_ID) {
        return SAI_STATUS_SUCCESS;
    }

    return mlnx_acl_entry_mirror_policer_update_check_allowed(sx_rule);
}

static sai_status_t mlnx_acl_entry_action_mirror_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t                   status;
    sai_acl_stage_t                acl_stage = SAI_ACL_STAGE_INGRESS;
    sx_flex_acl_flex_action_type_t sx_action_type = SX_FLEX_ACL_ACTION_MIRROR;
    uint32_t                       acl_table_index, acl_entry_index, oid_session;
    sx_acl_direction_t             sx_direction;
    sx_span_session_id_t           current_session_id = MLNX_ACL_SX_SPAN_SESSION_INVALID;
    sx_span_session_id_t           new_session_id = MLNX_ACL_SX_SPAN_SESSION_INVALID;
    sx_flex_acl_flex_rule_t        flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;

    SX_LOG_ENTER();

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == (int64_t)arg) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == (int64_t)arg));

    if (value->aclaction.parameter.objlist.count != 1) {
        SX_LOG_ERR(" Failure : Only 1 Session ID is allowed to associate in an ACL Rule at this phase\n");
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (value->aclaction.enable == true) {
        status = mlnx_object_to_type(value->aclaction.parameter.objlist.list[0], SAI_OBJECT_TYPE_MIRROR_SESSION,
                                     &oid_session, NULL);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return status;
        }

        new_session_id = oid_session;
    }

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &acl_table_index, &acl_entry_index);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_EXIT();
        return status;
    }

    acl_table_write_lock(acl_table_index);

    switch ((int64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
        acl_stage = SAI_ACL_STAGE_INGRESS;
        sx_action_type = SX_FLEX_ACL_ACTION_MIRROR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
        acl_stage = SAI_ACL_STAGE_EGRESS;
        sx_action_type = SX_FLEX_ACL_ACTION_EGRESS_MIRROR;
        break;
    }

    sx_direction = mlnx_acl_table_sx_direction_get(&acl_db_table(acl_table_index));

    /* For SX_ACL_DIRECTION_RIF_EGRESS sdk uses SX_FLEX_ACL_ACTION_MIRROR (not EGRESS_MIRROR) */
    if ((acl_db_table(acl_table_index).stage != acl_stage) && (sx_direction != SX_ACL_DIRECTION_RIF_EGRESS)) {
        SX_LOG_ERR("Table stage %s and Action stage %s doesn't match\n",
                   sai_metadata_get_acl_stage_name(acl_db_table(acl_table_index).stage),
                   sai_metadata_get_acl_stage_name(acl_stage));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    current_session_id = acl_db_entry(acl_entry_index).sx_span_session;

    if (current_session_id == new_session_id) {
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_get(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_mirror_config_validate(&flex_acl_rule, sx_action_type, current_session_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_mirror_action_check_allowed(&flex_acl_rule, new_session_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (MLNX_ACL_SX_SPAN_SESSION_IS_VALID(current_session_id)) {
        status = mlnx_acl_entry_mirror_action_unbind(&flex_acl_rule, sx_direction);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to delete current action mirror\n");
            goto out;
        }
    }

    if (MLNX_ACL_SX_SPAN_SESSION_IS_VALID(new_session_id)) {
        status = mlnx_acl_entry_mirror_action_bind(flex_acl_rule.action_list_p,
                                                   &flex_acl_rule.action_count,
                                                   sx_direction,
                                                   new_session_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to add new action mirror\n");
            goto out;
        }
    }

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_mirror_session_ref_inc(new_session_id, sx_direction);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_mirror_session_ref_dec(current_session_id, sx_direction);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_db_entry(acl_entry_index).sx_span_session = new_session_id;

out:
    acl_table_unlock(acl_table_index);

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_action_redirect_list_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                        _In_ const sai_acl_action_data_t *action_data,
                                                        _In_ uint32_t                     attr_index,
                                                        _In_ const acl_table_db_t        *table,
                                                        _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                        _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                        _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t        status;
    sx_acl_pbs_id_t     sx_pbs_id;
    mlnx_acl_pbs_info_t pbs_info = MLNX_ACL_PBS_INFO_INVALID;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    if (ctx->is_redirect_action_present) {
        SX_LOG_ERR("Only one of redirect actions (redirect/redirect_list/flood) is allowed in single entry\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_acl_pbs_ports_create_or_get(action_data->parameter.objlist.list,
                                              action_data->parameter.objlist.count,
                                              &sx_pbs_id, &pbs_info);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_PBS;
    sx_action_list[*sx_action_count].fields.action_pbs.pbs_id = sx_pbs_id;

    (*sx_action_count)++;

    ctx->is_redirect_action_present = true;
    ctx->pbs_info = pbs_info;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_redirect_endpoint_set(_In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ bool                         is_redirect_endpoint_needed,
                                                   _In_ uint32_t                     redirect_action_idx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t  status;
    sx_ip_addr_t *sx_ip;
    bool          enable;

    assert(action_data);
    assert(sx_action_list);
    assert(sx_action_count);

    enable = action_data->enable;

    if (is_redirect_endpoint_needed) {
        if (enable) {
            sx_ip = &sx_action_list[redirect_action_idx].fields.action_nve_tunnel_encap.underlay_dip;
            status = mlnx_translate_sai_ip_address_to_sdk(&action_data->parameter.ipaddr, sx_ip);
            if (SAI_ERR(status)) {
                return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
            }
        } else {
            SX_LOG_ERR(
                "ACL Entry is in invalid state - ACTION_REDIRECT set to tunnel but ACTION_ENDPOINT_IP is not set\n");
            return SAI_STATUS_FAILURE;
        }
    } else {
        if (enable) {
            SX_LOG_ERR(
                "Failed to set ACTION_ENDPOINT_IP - ACL entry doesn't have a redirect action to SAI_BRIDGE_PORT_TYPE_TUNNEL\n");
            return SAI_STATUS_FAILURE;
        } else {
            /* Nothing to update */
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_endpoint_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                   _In_ const sai_acl_action_data_t *action_data,
                                                   _In_ uint32_t                     attr_index,
                                                   _In_ const acl_table_db_t        *table,
                                                   _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                   _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                   _Inout_ uint32_t                 *sx_action_count)
{
    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    ctx->is_redirect_endpoint_set = true;

    return mlnx_acl_redirect_endpoint_set(action_data, attr_index, ctx->is_redirect_endpoint_needed,
                                          ctx->redirect_action_idx, sx_action_list, sx_action_count);
}

static sai_status_t mlnx_acl_action_endpoint_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                    _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                    _In_ const acl_entry_db_t          *entry,
                                                    _In_ const acl_table_db_t          *table,
                                                    _In_ uint32_t                       attr_index,
                                                    _Out_ sai_acl_action_data_t        *action_data)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     action_index;
    bool         is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(action_data);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_NVE_TUNNEL_ENCAP, &action_index, &is_action_present);

    if (is_action_present) {
        action_data->enable = true;
        status = mlnx_translate_sdk_ip_address_to_sai(
            &sx_rule->action_list_p[action_index].fields.action_nve_tunnel_encap.underlay_dip,
            &action_data->parameter.ipaddr);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        action_data->enable = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_flood_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                _In_ const sai_acl_action_data_t *action_data,
                                                _In_ uint32_t                     attr_index,
                                                _In_ const acl_table_db_t        *table,
                                                _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t        status;
    sx_acl_pbs_id_t     sx_pbs_id;
    mlnx_acl_pbs_info_t pbs_info;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    if (ctx->is_redirect_action_present) {
        SX_LOG_ERR("Only one of redirect actions (redirect/redirect_list/flood) is allowed in single entry\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_acl_flood_pbs_create_or_get(&sx_pbs_id, &pbs_info);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_PBS;
    sx_action_list[*sx_action_count].fields.action_pbs.pbs_id = sx_pbs_id;
    (*sx_action_count)++;

    ctx->is_redirect_action_present = true;
    ctx->pbs_info = pbs_info;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_mirror_action_policer_update(_In_ uint32_t table_idx,
                                                                _In_ uint32_t entry_idx,
                                                                _In_ void    *opaque)
{
    sai_status_t            status;
    sx_span_session_id_t    sx_span_session;
    sx_acl_direction_t      sx_direction;
    sx_flex_acl_flex_rule_t sx_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;

    assert(acl_table_index_check_range(table_idx));
    assert(acl_entry_index_check_range(entry_idx));

    sx_span_session = (sx_span_session_id_t)(uintptr_t)(opaque);

    assert(sx_span_session < SPAN_SESSION_MAX);

    if (acl_db_entry(entry_idx).sx_span_session != sx_span_session) {
        return SAI_STATUS_NOT_EXECUTED;
    }

    sx_direction = mlnx_acl_table_sx_direction_get(&acl_db_table(table_idx));

    status = mlnx_acl_entry_sx_acl_rule_get(table_idx, entry_idx, &sx_rule);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_entry_mirror_policer_update_check_allowed(&sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_mirror_action_unbind(&sx_rule, sx_direction);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_mirror_action_bind(sx_rule.action_list_p,
                                               &sx_rule.action_count,
                                               sx_direction,
                                               sx_span_session);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_acl_rule_set(table_idx, entry_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    mlnx_acl_flex_rule_free(&sx_rule);
    return status;
}

sai_status_t mlnx_acl_mirror_action_policer_update(_In_ sx_span_session_id_t sx_span_session_id)
{
    sai_status_t           status;
    mlnx_mirror_policer_t *mirror_policer;
    sx_acl_direction_t     sx_direction;

    assert(sx_span_session_id < SPAN_SESSION_MAX);

    status = mlnx_acl_db_entries_foreach(mlnx_acl_entry_mirror_action_policer_update,
                                         (void*)(uintptr_t)sx_span_session_id);
    if (SAI_ERR(status)) {
        return status;
    }

    mirror_policer = &g_sai_db_ptr->mirror_policer[sx_span_session_id];

    if (mirror_policer->policer_oid == SAI_NULL_OBJECT_ID) {
        for (sx_direction = SX_ACL_DIRECTION_INGRESS; sx_direction < SX_ACL_DIRECTION_LAST; sx_direction++) {
            status = mlnx_acl_mirror_acl_remove(&mirror_policer->extra_acl[sx_direction], sx_direction);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_flood_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                 _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                 _In_ const acl_entry_db_t          *entry,
                                                 _In_ const acl_table_db_t          *table,
                                                 _In_ uint32_t                       attr_index,
                                                 _Out_ sai_acl_action_data_t        *action_data)
{
    mlnx_acl_pbs_info_t pbs_info;
    uint32_t            action_index;
    bool                is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(table);
    assert(action_data);

    pbs_info = entry->pbs_info;

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_PBS, &action_index, &is_action_present);

    if (!is_action_present) {
        if (MLNX_ACL_PBS_INFO_IS_VALID(pbs_info)) {
            SX_LOG_ERR("Invalid ACL DB / SDK state - sx rule doesn't contain action PBS, but SAI DB has a valid pbs\n");
            return SAI_STATUS_FAILURE;
        }

        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    if (MLNX_ACL_PBS_INFO_IS_FLOOD(pbs_info)) {
        action_data->enable = true;
    } else {
        action_data->enable = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_pkt_act_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t        status;
    sai_packet_action_t pkt_action;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    pkt_action = action_data->parameter.s32;

    status = mlnx_acl_packet_actions_handler(pkt_action, SX_TRAP_ID_ACL_MIN, sx_action_list, sx_action_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_pkt_act_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data)
{
    sai_packet_action_t          packet_action = -1;
    sx_flex_acl_forward_action_t forward_action;
    sx_flex_acl_trap_action_t    trap_action;
    uint32_t                     forward_action_index, trap_action_index;
    bool                         is_trap_action_present = false;
    bool                         is_forward_action_present = false;

    assert(sx_rule);
    assert(entry);
    assert(action_data);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_TRAP, &trap_action_index, &is_trap_action_present);
    mlnx_acl_flex_rule_action_find(sx_rule,
                                   SX_FLEX_ACL_ACTION_FORWARD,
                                   &forward_action_index,
                                   &is_forward_action_present);

    if (!is_trap_action_present && !is_forward_action_present) {
        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    if (is_forward_action_present && !is_trap_action_present) {
        forward_action = sx_rule->action_list_p[forward_action_index].fields.action_forward.action;
        if (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD) {
            packet_action = SAI_PACKET_ACTION_DROP;
        } else if (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD) {
            packet_action = SAI_PACKET_ACTION_FORWARD;
        }
    } else if (!is_forward_action_present && is_trap_action_present) {
        trap_action = sx_rule->action_list_p[trap_action_index].fields.action_trap.action;
        if (trap_action == SX_ACL_TRAP_ACTION_TYPE_TRAP) {
            packet_action = SAI_PACKET_ACTION_COPY;
        } else if (trap_action == SX_ACL_TRAP_ACTION_TYPE_DISCARD) {
            packet_action = SAI_PACKET_ACTION_COPY_CANCEL;
        }
    }
    /* if trap action and forward action both are present */
    else {
        trap_action = sx_rule->action_list_p[trap_action_index].fields.action_trap.action;
        forward_action = sx_rule->action_list_p[forward_action_index].fields.action_forward.action;

        if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_TRAP) &&
            (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD)) {
            packet_action = SAI_PACKET_ACTION_LOG;
        } else if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_TRAP) &&
                   (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD)) {
            packet_action = SAI_PACKET_ACTION_TRAP;
        } else if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_DISCARD) &&
                   (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_DISCARD)) {
            packet_action = SAI_PACKET_ACTION_DENY;
        } else if ((trap_action == SX_ACL_TRAP_ACTION_TYPE_DISCARD) &&
                   (forward_action == SX_ACL_TRAP_FORWARD_ACTION_TYPE_FORWARD)) {
            packet_action = SAI_PACKET_ACTION_TRANSIT;
        }
    }

    action_data->enable = true;
    action_data->parameter.s32 = packet_action;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_counter_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t status;
    uint32_t     counter_table_idx;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    status = mlnx_acl_counter_oid_data_get(action_data->parameter.oid, &ctx->sx_counter_id,
                                           &ctx->counter_byte_flag, &ctx->counter_packet_flag, &counter_table_idx);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if (&acl_db_table(counter_table_idx) != table) {
        SX_LOG_ERR("Failed to set counter oid %lx - counter's table %d != entry's table\n",
                   action_data->parameter.oid, counter_table_idx);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_COUNTER;
    sx_action_list[*sx_action_count].fields.action_counter.counter_id = ctx->sx_counter_id;
    (*sx_action_count)++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_counter_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data)
{
    uint32_t action_index;
    bool     is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(table);
    assert(action_data);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_COUNTER, &action_index, &is_action_present);

    if (!is_action_present) {
        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    action_data->enable = true;

    return mlnx_acl_counter_oid_create(entry->sx_counter_id,
                                       entry->counter_byte_flag,
                                       entry->counter_packet_flag,
                                       MLNX_ACL_DB_TABLE_TO_IDX(table),
                                       &action_data->parameter.oid);
}

static sai_status_t mlnx_acl_action_mirror_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                 _In_ const sai_acl_action_data_t *action_data,
                                                 _In_ uint32_t                     attr_index,
                                                 _In_ const acl_table_db_t        *table,
                                                 _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                 _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                 _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t       status;
    uint32_t           session_id;
    sai_acl_stage_t    action_stage;
    sx_acl_direction_t table_sx_direction;

    assert((action == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS));
    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    if (action_data->parameter.objlist.count != 1) {
        SX_LOG_ERR(" Failure : Only 1 Session ID is associated to an ACL Rule at this phase \n");
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    status = mlnx_object_to_type(action_data->parameter.objlist.list[0], SAI_OBJECT_TYPE_MIRROR_SESSION,
                                 &session_id, NULL);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    action_stage = (action == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS) ?
                   SAI_ACL_STAGE_INGRESS : SAI_ACL_STAGE_EGRESS;
    table_sx_direction = mlnx_acl_table_sx_direction_get(table);

    /* For SX_ACL_DIRECTION_RIF_EGRESS sdk uses SX_FLEX_ACL_ACTION_MIRROR (not EGRESS_MIRROR) */
    if ((table->stage != action_stage) && (table_sx_direction != SX_ACL_DIRECTION_RIF_EGRESS)) {
        SX_LOG_ERR("Table stage %s and Action stage %s doesn't match\n",
                   sai_metadata_get_acl_stage_name(table->stage),
                   sai_metadata_get_acl_stage_name(action_stage));
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    if (ctx->is_policer_action_present) {
        status = mlnx_acl_entry_action_policer_check_allowed(session_id);
        if (SAI_ERR(status)) {
            return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + attr_index;
        }
    }

    status = mlnx_acl_entry_mirror_action_bind(sx_action_list, sx_action_count, table_sx_direction, session_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add new action mirror\n");
        return status;
    }

    ctx->sx_span_session = session_id;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_mirror_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                  _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                  _In_ const acl_entry_db_t          *entry,
                                                  _In_ const acl_table_db_t          *table,
                                                  _In_ uint32_t                       attr_index,
                                                  _Out_ sai_acl_action_data_t        *action_data)
{
    sai_status_t                   status;
    sai_object_id_t                mirror_oid;
    sai_acl_stage_t                action_stage;
    sx_acl_direction_t             sx_direction;
    sx_flex_acl_flex_action_type_t sx_action_type;

    assert((SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == action) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == action));
    assert(sx_rule);
    assert(entry);
    assert(table);
    assert(action_data);

    switch (action) {
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
        action_stage = SAI_ACL_STAGE_INGRESS;
        sx_action_type = SX_FLEX_ACL_ACTION_MIRROR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
        action_stage = SAI_ACL_STAGE_EGRESS;
        sx_action_type = SX_FLEX_ACL_ACTION_EGRESS_MIRROR;
        break;

    default:
        return SAI_STATUS_FAILURE;
    }

    sx_direction = mlnx_acl_table_sx_direction_get(table);

    if ((table->stage != action_stage) && (sx_direction != SX_ACL_DIRECTION_RIF_EGRESS)) {
        SX_LOG_ERR("Table stage %s and Action stage %s doesn't match\n",
                   sai_metadata_get_acl_stage_name(table->stage),
                   sai_metadata_get_acl_stage_name(action_stage));
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    status = mlnx_acl_mirror_config_validate(sx_rule, sx_action_type, entry->sx_span_session);
    if (SAI_ERR(status)) {
        return status;
    }

    if (MLNX_ACL_SX_SPAN_SESSION_IS_VALID(entry->sx_span_session)) {
        action_data->enable = true;
        status = mlnx_create_object(SAI_OBJECT_TYPE_MIRROR_SESSION,
                                    entry->sx_span_session,
                                    NULL,
                                    &mirror_oid);
        if (SAI_ERR(status)) {
            return status;
        }

        return mlnx_fill_objlist(&mirror_oid, 1, &action_data->parameter.objlist);
    }

    action_data->enable = false;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_policer_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t status;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    status = mlnx_acl_entry_action_policer_check_allowed(ctx->sx_span_session);
    if (SAI_ERR(status)) {
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + attr_index;
    }

    status = mlnx_sai_get_or_create_regular_sx_policer_for_bind(action_data->parameter.oid,
                                                                false,
                                                                &sx_action_list[*sx_action_count].fields.action_policer.policer_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to obtain sx_policer_id. input sai policer object_id:0x%" PRIx64 "\n",
                   action_data->parameter.oid);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_POLICER;
    (*sx_action_count)++;

    ctx->is_policer_action_present = true;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_policer_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data)
{
    sai_status_t status;
    uint32_t     action_index, policer_db_idx;
    bool         is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(table);
    assert(action_data);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_POLICER, &action_index, &is_action_present);

    if (!is_action_present) {
        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    action_data->enable = true;

    status = db_find_sai_policer_entry_ind(sx_rule->action_list_p[action_index].fields.action_policer.policer_id,
                                           &policer_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to obtain sai_policer from sx_policer:0x%" PRIx64 "for acl\n",
                   sx_rule->action_list_p[action_index].fields.action_policer.policer_id);
        return status;
    }

    return mlnx_create_object(SAI_OBJECT_TYPE_POLICER, policer_db_idx, NULL, &action_data->parameter.oid);
}

static sai_status_t mlnx_acl_action_dec_ttl_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                  _In_ const sai_acl_action_data_t *action_data,
                                                  _In_ uint32_t                     attr_index,
                                                  _In_ const acl_table_db_t        *table,
                                                  _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                  _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                  _Inout_ uint32_t                 *sx_action_count)
{
    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_DEC_TTL;
    sx_action_list[*sx_action_count].fields.action_dec_ttl.ttl_val = 1;
    (*sx_action_count)++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_dec_ttl_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                   _In_ const acl_entry_db_t          *entry,
                                                   _In_ const acl_table_db_t          *table,
                                                   _In_ uint32_t                       attr_index,
                                                   _Out_ sai_acl_action_data_t        *action_data)
{
    uint32_t action_index;
    bool     is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(table);
    assert(action_data);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_DEC_TTL, &action_index, &is_action_present);

    if (is_action_present) {
        if (sx_rule->action_list_p[action_index].fields.action_dec_ttl.ttl_val != 1) {
            SX_LOG_ERR("Unexpected value for SX_FLEX_ACL_ACTION_DEC_TTL - %u\n",
                       sx_rule->action_list_p[action_index].fields.action_dec_ttl.ttl_val);
            return SAI_STATUS_FAILURE;
        }

        action_data->enable = true;
    } else {
        action_data->enable = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_vlan_prio_to_sx(_In_ sai_acl_entry_attr_t         action,
                                                    _In_ const sai_acl_action_data_t *action_data,
                                                    _In_ uint32_t                     attr_index,
                                                    _In_ const acl_table_db_t        *table,
                                                    _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                                    _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                                    _Inout_ uint32_t                 *sx_action_count)
{
    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    assert((action == SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI));

    if (action_data->parameter.u8 > 0x7) {
        SX_LOG_ERR("Parameter 0x%x is out of range [0, 0x7]\n", action_data->parameter.u8);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI) {
        sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_PRI;
        sx_action_list[*sx_action_count].fields.action_set_outer_vlan_prio.pcp = action_data->parameter.u8;
        (*sx_action_count)++;
    } else {
        sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_SET_INNER_VLAN_PRI;
        sx_action_list[*sx_action_count].fields.action_set_inner_vlan_prio.pcp = action_data->parameter.u8;
        (*sx_action_count)++;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_vlan_prio_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                     _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                     _In_ const acl_entry_db_t          *entry,
                                                     _In_ const acl_table_db_t          *table,
                                                     _In_ uint32_t                       attr_index,
                                                     _Out_ sai_acl_action_data_t        *action_data)
{
    sx_flex_acl_flex_action_type_t sx_action;
    uint32_t                       action_index;
    bool                           is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(table);
    assert(action_data);

    assert((action == SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI));

    sx_action = (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI) ?
                SX_FLEX_ACL_ACTION_SET_OUTER_VLAN_PRI : SX_FLEX_ACL_ACTION_SET_INNER_VLAN_PRI;

    mlnx_acl_flex_rule_action_find(sx_rule, sx_action, &action_index, &is_action_present);

    if (!is_action_present) {
        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    action_data->enable = true;
    if (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI) {
        action_data->parameter.u8 = sx_rule->action_list_p[action_index].fields.action_set_outer_vlan_prio.pcp;
    } else {
        action_data->parameter.u8 = sx_rule->action_list_p[action_index].fields.action_set_inner_vlan_prio.pcp;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_meta_to_sx(_In_ sai_acl_entry_attr_t         action,
                                               _In_ const sai_acl_action_data_t *action_data,
                                               _In_ uint32_t                     attr_index,
                                               _In_ const acl_table_db_t        *table,
                                               _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                               _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                               _Inout_ uint32_t                 *sx_action_count)
{
    uint32_t val;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    val = action_data->parameter.u32;

    if (ACL_USER_META_RANGE_MAX < val) {
        SX_LOG_ERR(" ACL user Meta value %u is out of range [%d, %d] \n",
                   val, ACL_USER_META_RANGE_MIN, ACL_USER_META_RANGE_MAX);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_action_list[*sx_action_count].type = SX_FLEX_ACL_ACTION_SET_USER_TOKEN;
    sx_action_list[*sx_action_count].fields.action_set_user_token.user_token = val;
    sx_action_list[*sx_action_count].fields.action_set_user_token.mask = ACL_USER_META_RANGE_MAX;
    (*sx_action_count)++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_meta_to_sai(_In_ sai_acl_entry_attr_t           action,
                                                _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                                _In_ const acl_entry_db_t          *entry,
                                                _In_ const acl_table_db_t          *table,
                                                _In_ uint32_t                       attr_index,
                                                _Out_ sai_acl_action_data_t        *action_data)
{
    uint32_t action_index;
    bool     is_action_present;

    assert(sx_rule);
    assert(entry);
    assert(table);
    assert(action_data);

    mlnx_acl_flex_rule_action_find(sx_rule, SX_FLEX_ACL_ACTION_SET_USER_TOKEN, &action_index, &is_action_present);

    if (!is_action_present) {
        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    action_data->enable = true;
    action_data->parameter.u32 = sx_rule->action_list_p[action_index].fields.action_set_user_token.user_token;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_ip_to_sx(_In_ sai_acl_entry_attr_t         action,
                                             _In_ const sai_acl_action_data_t *action_data,
                                             _In_ uint32_t                     attr_index,
                                             _In_ const acl_table_db_t        *table,
                                             _Inout_ mlnx_acl_action_ctx_t    *ctx,
                                             _Out_ sx_flex_acl_flex_action_t  *sx_action_list,
                                             _Inout_ uint32_t                 *sx_action_count)
{
    sai_status_t                   status;
    sai_ip_addr_family_t           addr_family;
    sai_ip_address_t               ip_addr;
    sx_ip_addr_t                  *sx_ip_addr;
    sx_flex_acl_flex_action_type_t sx_action;

    assert(action_data);
    assert(ctx);
    assert(sx_action_list);
    assert(sx_action_count);
    assert((action == SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6));

    switch (action) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP:
        addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sx_action = SX_FLEX_ACL_ACTION_SET_SIP_ADDR;
        sx_ip_addr = &sx_action_list[*sx_action_count].fields.action_set_sip.ip_addr;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP:
        addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sx_action = SX_FLEX_ACL_ACTION_SET_DIP_ADDR;
        sx_ip_addr = &sx_action_list[*sx_action_count].fields.action_set_dip.ip_addr;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6:
        addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        sx_action = SX_FLEX_ACL_ACTION_SET_SIPV6_ADDR;
        sx_ip_addr = &sx_action_list[*sx_action_count].fields.action_set_sipv6.ip_addr;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6:
        addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        sx_action = SX_FLEX_ACL_ACTION_SET_DIPV6_ADDR;
        sx_ip_addr = &sx_action_list[*sx_action_count].fields.action_set_dipv6.ip_addr;
        break;

    default:
        return SAI_STATUS_FAILURE;
    }

    memset(&ip_addr, 0, sizeof(ip_addr));
    memset(sx_ip_addr, 0, sizeof(*sx_ip_addr));

    ip_addr.addr_family = addr_family;

    if (SAI_IP_ADDR_FAMILY_IPV4 == addr_family) {
        ip_addr.addr.ip4 = action_data->parameter.ip4;
    } else {
        memcpy(&ip_addr.addr.ip6, &action_data->parameter.ip6, sizeof(ip_addr.addr.ip6));
    }

    status = mlnx_translate_sai_ip_address_to_sdk(&ip_addr, sx_ip_addr);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    sx_action_list[*sx_action_count].type = sx_action;
    (*sx_action_count)++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_ip_to_sai(_In_ sai_acl_entry_attr_t           action,
                                              _In_ const sx_flex_acl_flex_rule_t *sx_rule,
                                              _In_ const acl_entry_db_t          *entry,
                                              _In_ const acl_table_db_t          *table,
                                              _In_ uint32_t                       attr_index,
                                              _Out_ sai_acl_action_data_t        *action_data)
{
    sai_status_t                   status;
    sai_ip_addr_family_t           addr_family;
    sai_ip_address_t               ip_addr;
    const sx_ip_addr_t            *sx_ip_addr;
    sx_flex_acl_flex_action_type_t sx_action;
    uint32_t                       action_index;
    bool                           is_action_present;

    assert(sx_rule);
    assert(action_data);
    assert((action == SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP) ||
           (action == SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6));

    switch (action) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP:
        sx_action = SX_FLEX_ACL_ACTION_SET_SIP_ADDR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP:
        sx_action = SX_FLEX_ACL_ACTION_SET_DIP_ADDR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6:
        sx_action = SX_FLEX_ACL_ACTION_SET_SIPV6_ADDR;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6:
        sx_action = SX_FLEX_ACL_ACTION_SET_DIPV6_ADDR;
        break;

    default:
        return SAI_STATUS_FAILURE;
    }

    mlnx_acl_flex_rule_action_find(sx_rule, sx_action, &action_index, &is_action_present);

    if (!is_action_present) {
        action_data->enable = false;
        return SAI_STATUS_SUCCESS;
    }

    switch (action) {
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP:
        addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sx_ip_addr = &sx_rule->action_list_p[action_index].fields.action_set_sip.ip_addr;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP:
        addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sx_ip_addr = &sx_rule->action_list_p[action_index].fields.action_set_dip.ip_addr;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6:
        addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        sx_ip_addr = &sx_rule->action_list_p[action_index].fields.action_set_sipv6.ip_addr;
        break;

    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6:
        addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        sx_ip_addr = &sx_rule->action_list_p[action_index].fields.action_set_dipv6.ip_addr;
        break;

    default:
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_translate_sdk_ip_address_to_sai(sx_ip_addr, &ip_addr);
    if (SAI_ERR(status)) {
        return status;
    }

    action_data->enable = true;

    if (addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        action_data->parameter.ip4 = ip_addr.addr.ip4;
    } else {
        memcpy(&action_data->parameter.ip6, ip_addr.addr.ip6, sizeof(action_data->parameter.ip6));
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_ctx_validate(_In_ const mlnx_acl_action_ctx_t *ctx)
{
    assert(ctx);

    if (ctx->is_redirect_endpoint_needed && (!ctx->is_redirect_endpoint_set)) {
        SX_LOG_ERR("Action endpoint IP is required for action redirect\n");
        return SAI_STATUS_FAILURE;
    }

    if ((!ctx->is_redirect_endpoint_needed) && ctx->is_redirect_endpoint_set) {
        SX_LOG_ERR("Action endpoint IP is set but action redirect to tunnel is not\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_action_chip_check(_In_ sai_acl_entry_attr_t          action_id,
                                                     _In_ const mlnx_acl_action_info_t *action_info)
{
    const char *attr_name = "Invalid";

    assert((SAI_ACL_ENTRY_ATTR_ACTION_START <= action_id) && (action_id <= SAI_ACL_ENTRY_ATTR_ACTION_END));
    assert(action_info);

    if (action_info->supported_chip & MLNX_ACL_SX_CHIP_TO_SUPPORTED_CHIP(g_sai_db_ptr->sx_chip_type)) {
        return SAI_STATUS_SUCCESS;
    } else {
        sai_attribute_short_name_fetch(SAI_OBJECT_TYPE_ACL_ENTRY, action_id, &attr_name);
        SX_LOG_ERR("%s is not supported for chip type %s\n", attr_name, SX_CHIP_TYPE_STR(g_sai_db_ptr->sx_chip_type));
        return SAI_STATUS_FAILURE;
    }
}

static sai_status_t mlnx_acl_entry_action_to_sx(_In_ const sai_attribute_t      *attr_list,
                                                _In_ uint32_t                    attr_count,
                                                _In_ const acl_table_db_t       *table,
                                                _Inout_ mlnx_acl_action_ctx_t   *action_ctx,
                                                _Out_ sx_flex_acl_flex_action_t *sx_action_list,
                                                _Inout_ uint32_t                *sx_action_count)
{
    sai_status_t                  status;
    const mlnx_acl_action_info_t *action_info = NULL;
    const char                   *attr_name = "Invalid";
    sai_acl_stage_t               table_stage;
    uint32_t                      ii;
    bool                          is_action_stage_supported;

    assert(attr_list);
    assert(table);
    assert(action_ctx);
    assert(sx_action_list);
    assert(sx_action_count);

    table_stage = table->stage;

    for (ii = 0; ii < attr_count; ii++) {
        if ((attr_list[ii].id < SAI_ACL_ENTRY_ATTR_ACTION_START) ||
            (SAI_ACL_ENTRY_ATTR_ACTION_END < attr_list[ii].id)) {
            continue;
        }

        if (!attr_list[ii].value.aclaction.enable) {
            continue;
        }

        status = mlnx_acl_action_info_find(attr_list[ii].id, ii, &action_info);
        if (SAI_ERR(status)) {
            return status;
        }

        assert(action_info);

        status = mlnx_acl_stage_is_supported(table_stage, action_info->supported_stage, &is_action_stage_supported);
        if (SAI_ERR(status)) {
            return status;
        }

        if (!is_action_stage_supported) {
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        status = mlnx_acl_entry_action_chip_check(attr_list[ii].id, action_info);
        if (SAI_ERR(status)) {
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if (action_info->convert_to_sx) {
            status = action_info->convert_to_sx(attr_list[ii].id,
                                                &attr_list[ii].value.aclaction,
                                                ii,
                                                table,
                                                action_ctx,
                                                sx_action_list,
                                                sx_action_count);
            if (SAI_ERR(status)) {
                sai_attribute_short_name_fetch(SAI_OBJECT_TYPE_ACL_ENTRY, attr_list[ii].id, &attr_name);
                SX_LOG_ERR("Failed to convert %s\n", attr_name);
                return status;
            }
        } else {
            sx_action_list[*sx_action_count].type = action_info->sx_type;
            memcpy(&sx_action_list[*sx_action_count].fields,
                   &attr_list[ii].value.aclaction.parameter,
                   action_info->field_size);
            (*sx_action_count)++;
        }
    }

    status = mlnx_acl_action_ctx_validate(action_ctx);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_action_fn_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t                  status;
    sx_flex_acl_flex_rule_t       sx_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sai_acl_entry_attr_t          attr_id;
    const mlnx_acl_action_info_t *action_info = NULL;
    uint32_t                      table_db_idx, entry_db_idx;

    SX_LOG_ENTER();

    attr_id = (int64_t)arg;

    assert((SAI_ACL_ENTRY_ATTR_ACTION_EGRESS_BLOCK_PORT_LIST == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT_LIST == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_ENDPOINT_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_COUNTER == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_OUTER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_INNER_VLAN_PRI == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_FLOOD == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_DECREMENT_TTL == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_SRC_IPV6 == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IP == attr_id) ||
           (SAI_ACL_ENTRY_ATTR_ACTION_SET_DST_IPV6 == attr_id));

    status = extract_acl_table_index_and_entry_index(key->key.object_id, &table_db_idx, &entry_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_acl_action_info_find(attr_id, attr_index, &action_info);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    if (!action_info->convert_to_sai) {
        SX_LOG_ERR("action_info->convert_to_sai in NULL for attribute %d\n", attr_id);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    acl_table_read_lock(table_db_idx);

    status = mlnx_acl_entry_sx_acl_rule_get(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = action_info->convert_to_sai(attr_id, &sx_rule, &acl_db_entry(entry_db_idx), &acl_db_table(table_db_idx),
                                         attr_index, &value->aclaction);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_table_unlock(table_db_idx);
    mlnx_acl_flex_rule_free(&sx_rule);

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
    sx_flex_acl_flex_rule_t      flex_acl_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_rule_offset_t         sx_acl_rule_offset;
    sx_ip_addr_t                 ipaddr_data, ipaddr_mask;
    sx_flex_acl_key_desc_t      *sx_key_descs = NULL;
    sx_flex_acl_flex_action_t   *sx_action_list = NULL;
    sx_mc_container_id_t         sx_mc_container_rx = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_id_t         sx_mc_container_tx = SX_MC_CONTAINER_ID_INVALID;
    sx_acl_direction_t           sx_direction;
    mlnx_acl_action_ctx_t        action_ctx = MLNX_ACL_ACTION_CTX_EMPTY;
    sai_acl_stage_t              stage;
    sai_ip_address_t             ip_address_data, ip_address_mask;
    const sai_attribute_value_t *table_id, *priority;
    const sai_attribute_value_t *in_port, *in_ports, *out_port, *out_ports, *ip_ident;
    const sai_attribute_value_t *admin_state;
    mlnx_acl_port_db_refs_t      ports_refs;
    uint32_t                     table_id_index, priority_index;
    uint32_t                     in_port_index, admin_state_index, in_ports_index, ip_ident_index;
    uint32_t                     out_port_index, out_ports_index;
    uint32_t                     in_port_data, out_port_data;
    uint32_t                     acl_table_index, acl_entry_index = ACL_INVALID_DB_INDEX;
    uint32_t                     key_desc_index = 0, sx_action_count = 0;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    bool                         is_in_port_key_present = false;
    bool                         is_out_port_key_present = false;
    uint32_t                     table_size, created_entry_count, max_flex_keys;
    bool                         is_table_dynamic_sized, is_ip_idnet_used;
    uint32_t                     sx_rule_prio;
    bool                         is_offset_allocated = false, is_sx_rule_set = false;

    SX_LOG_ENTER();

    memset(&flex_acl_rule, 0, sizeof(flex_acl_rule));
    memset(&ipaddr_data, 0, sizeof(ipaddr_data));
    memset(&ip_address_data, 0, sizeof(ip_address_data));
    memset(&ipaddr_mask, 0, sizeof(ipaddr_mask));
    memset(&ip_address_mask, 0, sizeof(ip_address_mask));
    memset(&sx_key_descs, 0, sizeof(sx_key_descs));

    if (NULL == acl_entry_id) {
        SX_LOG_ERR("NULL acl entry id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_ENTRY, acl_entry_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }
    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_ENTRY, MAX_LIST_VALUE_STR_LEN, list_str);
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

    stage = acl_db_table(acl_table_index).stage;
    table_size = ACL_SX_REG_SIZE_TO_TABLE_SIZE(acl_db_table(acl_table_index).region_size);
    created_entry_count = acl_db_table(acl_table_index).created_entry_count;
    is_table_dynamic_sized = acl_db_table(acl_table_index).is_dynamic_sized;
    is_ip_idnet_used = acl_db_table(acl_table_index).is_ip_ident_used;
    sx_direction = mlnx_acl_table_sx_direction_get(&acl_db_table(acl_table_index));

    if ((created_entry_count == table_size) &&
        (false == is_table_dynamic_sized)) {
        SX_LOG_ERR("Table is full\n");
        status = SAI_STATUS_TABLE_FULL;
        goto out;
    }

    sx_key_descs = calloc(ACL_MAX_FLEX_KEY_COUNT, sizeof(*sx_key_descs));
    if (NULL == sx_key_descs) {
        SX_LOG_ERR(" Unable to allocate memory for sx_key_descs\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    sx_action_list = calloc(ACL_MAX_ACTIONS_COUNT, sizeof(*sx_action_list));
    if (NULL == sx_action_list) {
        SX_LOG_ERR(" Unable to allocate memory for sx_action_list\n");
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
        if (!ACL_SAI_ENTRY_PRIO_CHECK_RANGE(priority->u32)) {
            SX_LOG_ERR("Priority %u is out of range (%u,%u)\n",
                       priority->u32,
                       ACL_SAI_ENTRY_MIN_PRIO,
                       ACL_SAI_ENTRY_MAX_PRIO);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + priority_index;
            goto out;
        }

        sx_rule_prio = ACL_SAI_ENTRY_PRIO_TO_SX(priority->u32);
    } else {
        sx_rule_prio = ACL_SAI_ENTRY_PRIO_TO_SX(ACL_SAI_ENTRY_DEF_PRIO);
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

    status = mlnx_acl_entry_udf_attrs_parse(attr_count, attr_list, acl_table_index, sx_key_descs, &key_desc_index);
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

        if (0 == in_ports->aclfield.data.objlist.count) {
            SX_LOG_ERR("Empty object list for FIELD_IN_PORTS is not allowed\n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + in_ports_index;
            goto out;
        }

        status = mlnx_acl_sx_mc_container_create(&in_ports->aclfield.data.objlist, &sx_mc_container_rx);
        if (SAI_ERR(status)) {
            goto out;
        }

        sx_key_descs[key_desc_index].key_id = FLEX_ACL_KEY_RX_PORT_LIST;
        sx_key_descs[key_desc_index].key.rx_port_list.match_type = SX_ACL_PORT_LIST_MATCH_POSITIVE;
        sx_key_descs[key_desc_index].key.rx_port_list.mc_container_id = sx_mc_container_rx;
        sx_key_descs[key_desc_index].mask.rx_port_list = true;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS, &out_ports, &out_ports_index)) {
        if (stage != SAI_ACL_STAGE_EGRESS) {
            SX_LOG_ERR("FIELD_OUT_PORTS in only supported for SAI_ACL_STAGE_EGRESS\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        if (is_out_port_key_present) {
            SX_LOG_ERR("Both OUT_PORT and OUT_PORTS in one entry are not allowed\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        is_out_port_key_present = true;


        if (0 == out_ports->aclfield.data.objlist.count) {
            SX_LOG_ERR("Empty object list for FIELD_OUT_PORTS is not allowed\n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + out_ports_index;
            goto out;
        }

        status = mlnx_acl_sx_mc_container_create(&out_ports->aclfield.data.objlist, &sx_mc_container_tx);
        if (SAI_ERR(status)) {
            goto out;
        }

        sx_key_descs[key_desc_index].key_id = FLEX_ACL_KEY_TX_PORT_LIST;
        sx_key_descs[key_desc_index].key.tx_port_list.match_type = SX_ACL_PORT_LIST_MATCH_POSITIVE;
        sx_key_descs[key_desc_index].key.tx_port_list.mc_container_id = sx_mc_container_tx;
        sx_key_descs[key_desc_index].mask.tx_port_list = true;
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

        status = mlnx_acl_field_port_to_sx(in_port->aclfield.data.oid, &in_port_data);
        if (SAI_ERR(status)) {
            goto out;
        }

        sx_key_descs[key_desc_index].key.src_port = in_port_data;
        sx_key_descs[key_desc_index].mask.src_port = true;
        sx_key_descs[key_desc_index].key_id = FLEX_ACL_KEY_SRC_PORT;
        key_desc_index++;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT, &out_port, &out_port_index)) {
        if (stage != SAI_ACL_STAGE_EGRESS) {
            SX_LOG_ERR("FIELD_OUT_PORT in only supported for SAI_ACL_STAGE_EGRESS\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        if (is_out_port_key_present) {
            SX_LOG_ERR("Both OUT_PORT and OUT_PORTS in one entry are not allowed\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        is_out_port_key_present = true;

        status = mlnx_acl_field_port_to_sx(out_port->aclfield.data.oid, &out_port_data);
        if (SAI_ERR(status)) {
            goto out;
        }

        sx_key_descs[key_desc_index].key.dst_port = out_port_data;
        sx_key_descs[key_desc_index].mask.dst_port = true;
        sx_key_descs[key_desc_index].key_id = FLEX_ACL_KEY_DST_PORT;
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

    status = mlnx_acl_entry_action_to_sx(attr_list, attr_count, &acl_db_table(
                                             acl_table_index), &action_ctx, sx_action_list, &sx_action_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (sx_action_count > ACL_MAX_NUM_OF_ACTIONS) {
        SX_LOG_ERR("Action count %u > max allowed (%u)\n", sx_action_count, ACL_MAX_NUM_OF_ACTIONS);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    memcpy(flex_acl_rule.action_list_p, sx_action_list, sizeof(sx_flex_acl_flex_action_t) * sx_action_count);

    flex_acl_rule.key_desc_count = key_desc_index;
    flex_acl_rule.action_count = sx_action_count;

    status = acl_db_find_entry_free_index(&acl_entry_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_offset_get(acl_table_index, acl_entry_index, sx_rule_prio, &sx_acl_rule_offset);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get offset for entry\n");
        goto out;
    }

    is_offset_allocated = true;

    status = mlnx_acl_sx_rule_prio_set(&flex_acl_rule, sx_rule_prio);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_db_entry(acl_entry_index).sx_prio = sx_rule_prio;
    acl_db_entry(acl_entry_index).offset = sx_acl_rule_offset;
    acl_db_entry(acl_entry_index).sx_counter_id = action_ctx.sx_counter_id;
    acl_db_entry(acl_entry_index).counter_byte_flag = action_ctx.counter_byte_flag;
    acl_db_entry(acl_entry_index).counter_packet_flag = action_ctx.counter_packet_flag;
    acl_db_entry(acl_entry_index).next_entry_index = ACL_INVALID_DB_INDEX;
    acl_db_entry(acl_entry_index).prev_entry_index = ACL_INVALID_DB_INDEX;
    acl_db_entry(acl_entry_index).pbs_info = action_ctx.pbs_info;
    acl_db_entry(acl_entry_index).sx_span_session = action_ctx.sx_span_session;

    status = mlnx_acl_entry_sx_acl_rule_set(acl_table_index, acl_entry_index, &flex_acl_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    is_sx_rule_set = true;

    status = mlnx_acl_mirror_session_ref_inc(action_ctx.sx_span_session, sx_direction);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&flex_acl_rule, ports_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_set(ports_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_pbs_info_port_refs_get(action_ctx.pbs_info, ports_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_set(ports_refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_db_entry_add_to_table(acl_table_index, acl_entry_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_create_entry_object_id(acl_entry_id, acl_entry_index, acl_table_index);

    acl_entry_key_to_str(*acl_entry_id, key_str);
    SX_LOG_NTC("Created acl entry %s\n\n", key_str);

out:
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR(" Failed to create Entry \n");

        if (ACL_INVALID_DB_INDEX != acl_entry_index) {
            mlnx_acl_db_entry_delete(acl_entry_index);
        }

        if (is_offset_allocated) {
            mlnx_acl_entry_offset_del(acl_table_index, sx_rule_prio, sx_acl_rule_offset);
        }

        if (is_sx_rule_set) {
            mlnx_acl_flex_rule_delete(acl_table_index, &flex_acl_rule, sx_acl_rule_offset);
        }

        mlnx_acl_sx_mc_container_remove(sx_mc_container_rx);
        mlnx_acl_sx_mc_container_remove(sx_mc_container_tx);
        mlnx_acl_sx_mc_container_remove(action_ctx.sx_mc_container_egress_block);

        mlnx_acl_pbs_info_delete(action_ctx.pbs_info);
    }

    acl_global_unlock();
    acl_table_unlock(acl_table_index);
    sai_db_unlock();

    mlnx_acl_flex_rule_free(&flex_acl_rule);

    free(sx_key_descs);
    free(sx_action_list);

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
    acl_udf_group_list_t         udf_group_list;
    mlnx_acl_field_type_t        table_fields_types = MLNX_ACL_FIELD_TYPE_INVALID;
    uint32_t                     range_type_count = 0;
    uint32_t                     range_type_index;
    uint32_t                     stage_index, table_size_index, acl_action_list_index, ip_ident_index;
    uint32_t                     in_port_index, out_port_index, in_ports_index, out_ports_index;
    uint32_t                     bind_point_types_index;
    uint32_t                     key_count = 0, key_index = 0;
    uint32_t                     acl_table_size = 0;
    sx_acl_size_t                sx_region_size;
    sx_acl_key_type_t            key_handle;
    sx_acl_rule_offset_t         default_rule_offset;
    const sx_acl_action_type_t   action_type = SX_ACL_ACTION_TYPE_BASIC;
    const sx_acl_type_t          acl_type = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_region_id_t           region_id;
    sx_acl_region_group_t        region_group;
    sx_acl_id_t                  acl_id;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_acl_key_t                 keys[SX_FLEX_ACL_MAX_FIELDS_IN_KEY] = {FLEX_ACL_KEY_INVALID};
    bool                         is_dynamic_sized;
    uint32_t                     acl_table_index = 0, ii;
    bool                         key_created = false, region_created = false;
    bool                         acl_created = false, is_table_inited = false;
    bool                         is_range_types_unique, is_ip_ident_used = false;

    SX_LOG_ENTER();

    if (NULL == acl_table_id) {
        SX_LOG_ERR("NULL acl table id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memset(udf_group_list, 0, sizeof(acl_udf_group_list_t));

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_TABLE,
                                    acl_table_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_TABLE, MAX_LIST_VALUE_STR_LEN, list_str);
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

    status = mlnx_acl_table_fields_to_sx(attr_list, attr_count, sai_acl_stage, &table_fields_types, keys, &key_index);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS, &in_ports, &in_ports_index)) {
        if (true == in_ports->booldata) {
            keys[key_index] = FLEX_ACL_KEY_RX_PORT_LIST;
            key_index++;
        }
    }

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS, &out_ports, &out_ports_index)) {
        if (true == out_ports->booldata) {
            keys[key_index] = FLEX_ACL_KEY_TX_PORT_LIST;
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
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, &range_type,
                            &range_type_index)) {
        if (range_type->s32list.count > 0) {
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

    if (SAI_STATUS_SUCCESS ==
        find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_SIZE, &table_size, &table_size_index)) {
        if (0 == table_size->u32) {
            SX_LOG_NTC("Table size received is zero. Value is set to default size (%d)\n", ACL_DEFAULT_TABLE_SIZE);
            acl_table_size = ACL_DEFAULT_TABLE_SIZE;
            is_dynamic_sized = true;
        } else {
            acl_table_size = table_size->u32;
            is_dynamic_sized = false;
        }
    } else {   /* if table size is not present, use default */
        acl_table_size = ACL_DEFAULT_TABLE_SIZE;
        is_dynamic_sized = true;
    }

    assert(table_bind_point_types.count > 0);

    sx_acl_direction = mlnx_acl_sai_bind_point_type_to_sx_direction(table_bind_point_types.types[0], sai_acl_stage);

    sai_db_write_lock();
    acl_global_lock();

    status = mlnx_acl_lazy_init();
    if (SAI_ERR(status)) {
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION, &ip_ident,
                                 &ip_ident_index);
    if (SAI_STATUS_SUCCESS == status) {
        if (true == ip_ident->booldata) {
            status = mlnx_acl_ip_ident_key_create_or_get(&keys[key_index]);
            if (SAI_ERR(status)) {
                goto out;
            }

            is_ip_ident_used = true;
            key_index += ACL_IP_IDENT_FIELD_BYTE_COUNT;
        }
    }

    status = mlnx_acl_table_udf_attrs_parse(attr_count, attr_list, keys, &key_index, udf_group_list);
    if (SAI_ERR(status)) {
        goto out;
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

    sx_region_size = ACL_TABLE_SIZE_TO_SX_REG_SIZE(acl_table_size);

    sx_status = sx_api_acl_region_set(gh_sdk, SX_ACCESS_CMD_CREATE, key_handle,
                                      action_type, sx_region_size, &region_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create region - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    region_created = true;

    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type = acl_type;
    region_group.regions.acl_packet_agnostic.region = region_id;

    sx_status = sx_api_acl_set(gh_sdk, SX_ACCESS_CMD_CREATE, acl_type, sx_acl_direction, &region_group, &acl_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create acl table - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    acl_created = true;

    status = mlnx_acl_table_init(acl_table_index, is_dynamic_sized, sx_region_size);
    if (SAI_STATUS_SUCCESS != status) {
        goto out;
    }
    is_table_inited = true;

    status = mlnx_acl_entry_offset_get(acl_table_index, ACL_INVALID_DB_INDEX,
                                       ACL_SX_RULE_PRIO_GOTO_RULE, &default_rule_offset);
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

    status = mlnx_acl_udf_group_list_references_add(udf_group_list);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* Update D.B */
    acl_db_table(acl_table_index).table_id = acl_id;
    acl_db_table(acl_table_index).region_size = sx_region_size;
    acl_db_table(acl_table_index).stage = sai_acl_stage;
    acl_db_table(acl_table_index).key_type = key_handle;
    acl_db_table(acl_table_index).region_id = region_id;
    acl_db_table(acl_table_index).is_dynamic_sized = is_dynamic_sized;
    acl_db_table(acl_table_index).created_entry_count = 0;
    acl_db_table(acl_table_index).range_type_count = range_type_count;
    acl_db_table(acl_table_index).group_references = 0;
    acl_db_table(acl_table_index).def_rules_offset = default_rule_offset;
    acl_db_table(acl_table_index).def_rule_key = keys[0];
    acl_db_table(acl_table_index).wrapping_group.created = false;
    acl_db_table(acl_table_index).bind_point_types = table_bind_point_types;
    acl_db_table(acl_table_index).is_ip_ident_used = is_ip_ident_used;
    acl_db_table(acl_table_index).head_entry_index = ACL_INVALID_DB_INDEX;
    acl_db_table(acl_table_index).table_fields_types = table_fields_types;

    memcpy(acl_db_table(acl_table_index).udf_group_list, udf_group_list, sizeof(udf_group_list));

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

        if (is_table_inited) {
            if (SAI_STATUS_SUCCESS != mlnx_acl_table_deinit(acl_table_index)) {
                SX_LOG_ERR(" Failed to deinit ACL table\n");
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

        if (is_ip_ident_used) {
            mlnx_acl_ip_ident_key_ref_remove();
        }
    }

    acl_global_unlock();
    sai_db_unlock();

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
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ACL_TABLE, acl_table_vendor_attribs, attr);
}

/*
 * Routine Description:
 *   Get ACL table attribute
 *
 * Arguments:
 *    [in] acl_table_id - acl table id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_acl_table_attribute(_In_ sai_object_id_t     acl_table_id,
                                                 _In_ uint32_t            attr_count,
                                                 _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_table_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_table_key_to_str(acl_table_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_ACL_TABLE, acl_table_vendor_attribs, attr_count,
                              attr_list);
}

static void acl_counter_key_to_str(_In_ sai_object_id_t acl_counter_id, _Out_ char *key_str)
{
    sai_status_t         status;
    sx_flow_counter_id_t sx_counter_id;
    bool                 byte_counter_flag;
    bool                 packet_counter_flag;

    status = mlnx_acl_counter_oid_data_get(acl_counter_id,
                                           &sx_counter_id,
                                           &byte_counter_flag,
                                           &packet_counter_flag,
                                           NULL);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid acl counter id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "ACL Counter [%u] type (byte:%s, packet:%s)", sx_counter_id,
                 byte_counter_flag ? "true" : "false", packet_counter_flag ? "true" : "false");
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
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ACL_COUNTER, acl_counter_vendor_attribs, attr);
}

/*
 * Routine Description:
 *   Get ACL counter attribute
 *
 * Arguments:
 *    [in] acl_counter_id - acl counter id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_acl_counter_attribute(_In_ sai_object_id_t     acl_counter_id,
                                                   _In_ uint32_t            attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_counter_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_counter_key_to_str(acl_counter_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_ACL_COUNTER,
                              acl_counter_vendor_attribs,
                              attr_count,
                              attr_list);
}

static sai_status_t mlnx_acl_counter_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg)
{
    sai_status_t         status;
    sx_status_t          sx_status;
    sx_flow_counter_id_t sx_counter_id;

    SX_LOG_ENTER();

    assert((SAI_ACL_COUNTER_ATTR_PACKETS == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_BYTES == (int64_t)arg));

    acl_global_lock();

    status = mlnx_acl_counter_oid_to_sx(key->key.object_id, &sx_counter_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (value->u64 == 0) {
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

    SX_LOG_ENTER();
    assert((SAI_ACL_COUNTER_ATTR_PACKETS == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_BYTES == (int64_t)arg));

    acl_global_lock();

    status = mlnx_acl_counter_oid_to_sx(key->key.object_id, &counter_id);
    if (SAI_ERR(status)) {
        goto out;
    }

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

static sai_status_t mlnx_acl_counter_oid_create(_In_ sx_flow_counter_id_t sx_counter_id,
                                                _In_ bool                 byte_counter_flag,
                                                _In_ bool                 packet_counter_flag,
                                                _In_ uint32_t             table_db_idx,
                                                _Out_ sai_object_id_t    *counter_oid)
{
    mlnx_object_id_t mlnx_counter_obj = {0};

    assert(counter_oid);

    memset(counter_oid, 0, sizeof(*counter_oid));

    mlnx_counter_obj.id.flow_counter_id = sx_counter_id;
    mlnx_counter_obj.ext.flow_counter_type.byte_flag = byte_counter_flag;
    mlnx_counter_obj.ext.flow_counter_type.packet_flag = packet_counter_flag;
    mlnx_counter_obj.ext.flow_counter_type.table_db_idx = table_db_idx;

    return mlnx_object_id_to_sai(SAI_OBJECT_TYPE_ACL_COUNTER, &mlnx_counter_obj, counter_oid);
}

static sai_status_t mlnx_acl_counter_oid_to_sx(_In_ sai_object_id_t        counter_oid,
                                               _Out_ sx_flow_counter_id_t *sx_counter_id)
{
    assert(sx_counter_id);

    return mlnx_acl_counter_oid_data_get(counter_oid, sx_counter_id, NULL, NULL, NULL);
}

static sai_status_t mlnx_acl_counter_oid_data_get(_In_ sai_object_id_t        counter_oid,
                                                  _Out_ sx_flow_counter_id_t *sx_counter_id,
                                                  _Out_ bool                 *byte_counter_flag,
                                                  _Out_ bool                 *packet_counter_flag,
                                                  _Out_ uint32_t             *table_db_index)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_counter_obj = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ACL_COUNTER, counter_oid, &mlnx_counter_obj);
    if (SAI_ERR(status)) {
        return status;
    }

    if (sx_counter_id) {
        *sx_counter_id = mlnx_counter_obj.id.flow_counter_id;
    }

    if (byte_counter_flag) {
        *byte_counter_flag = mlnx_counter_obj.ext.flow_counter_type.byte_flag;
    }

    if (packet_counter_flag) {
        *packet_counter_flag = mlnx_counter_obj.ext.flow_counter_type.packet_flag;
    }

    if (table_db_index) {
        *table_db_index = mlnx_counter_obj.ext.flow_counter_type.table_db_idx;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_counter_attr_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t status;
    uint32_t     table_db_idx;
    bool         byte_counter_flag, packet_counter_flag;

    SX_LOG_ENTER();

    assert((SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT == (int64_t)arg) ||
           (SAI_ACL_COUNTER_ATTR_TABLE_ID) == (int64_t)arg);

    status = mlnx_acl_counter_oid_data_get(key->key.object_id,
                                           NULL,
                                           &byte_counter_flag,
                                           &packet_counter_flag,
                                           &table_db_idx);
    if (SAI_ERR(status)) {
        goto out;
    }

    switch ((int64_t)arg) {
    case SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT:
        value->booldata = packet_counter_flag;
        break;

    case SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT:
        value->booldata = byte_counter_flag;
        break;

    case SAI_ACL_COUNTER_ATTR_TABLE_ID:
        status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, table_db_idx, NULL, &value->oid);
        if (SAI_ERR(status)) {
            goto out;
        }
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
    uint32_t                     acl_table_id;
    bool                         byte_counter_flag = false, packet_counter_flag = false;

    SX_LOG_ENTER();

    if (NULL == acl_counter_id) {
        SX_LOG_ERR("NULL acl counter id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_COUNTER,
                                    acl_counter_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_COUNTER, MAX_LIST_VALUE_STR_LEN, list_str);
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

    acl_db_table(acl_table_id).counter_ref++;

    status = mlnx_acl_counter_oid_create(sx_counter_id,
                                         byte_counter_flag,
                                         packet_counter_flag,
                                         acl_table_id,
                                         acl_counter_id);
    if (SAI_ERR(status)) {
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
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ACL_ENTRY, acl_entry_vendor_attribs, attr);
}
/*
 * Routine Description:
 *   Get ACL Entry attribute
 *
 * Arguments:
 *    [in] acl_entry_id - acl entry id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */

static sai_status_t mlnx_get_acl_entry_attribute(_In_ sai_object_id_t     acl_entry_id,
                                                 _In_ uint32_t            attr_count,
                                                 _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_entry_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_entry_key_to_str(acl_entry_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_ACL_ENTRY, acl_entry_vendor_attribs, attr_count,
                              attr_list);
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
    uint32_t     acl_entry_index, acl_table_index;

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

    status = mlnx_acl_db_entry_remove_from_table(acl_table_index, acl_entry_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_delete_acl_entry_data(acl_table_index, acl_entry_index);
    if (SAI_ERR(status)) {
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
    const sx_acl_type_t   acl_type = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    sx_acl_key_type_t     key_handle;
    sai_acl_stage_t       stage;
    uint32_t              table_index, group_references;
    bool                  is_ip_ident_used;

    SX_LOG_ENTER();

    acl_table_key_to_str(acl_table_id, key_str);
    SX_LOG_NTC("Delete ACL Table %s\n", key_str);

    status = extract_acl_table_index(acl_table_id, &table_index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_write_lock();
    acl_table_write_lock(table_index);

    if (0 != acl_db_table(table_index).created_entry_count) {
        SX_LOG_ERR("Attempt to delete table with entries\n");
        acl_table_unlock(table_index);
        sai_db_unlock();
        SX_LOG_EXIT();
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if (0 != acl_db_table(table_index).counter_ref) {
        SX_LOG_ERR("Attempt to delete table that referenced by %u counters\n", acl_db_table(table_index).counter_ref);
        acl_table_unlock(table_index);
        sai_db_unlock();
        SX_LOG_EXIT();
        return SAI_STATUS_OBJECT_IN_USE;
    }

    group_references = acl_db_table(table_index).group_references;

    if (0 != group_references) {
        SX_LOG_ERR("Table is member of %d group%c\n", group_references, (group_references > 1) ? 's' : ' ');
        acl_table_unlock(table_index);
        sai_db_unlock();
        SX_LOG_EXIT();
        return SAI_STATUS_OBJECT_IN_USE;
    }

    acl_global_lock();

    region_id = acl_db_table(table_index).region_id;
    region_size = acl_db_table(table_index).region_size;
    sx_acl_id = acl_db_table(table_index).table_id;
    stage = acl_db_table(table_index).stage;
    key_handle = acl_db_table(table_index).key_type;
    is_ip_ident_used = acl_db_table(table_index).is_ip_ident_used;
    acl_direction = acl_sai_stage_to_sx_dir(stage);

    /* destroy the ACL */
    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type = acl_type;
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

    sx_status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_DELETE, NULL, 0, &key_handle);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR(" Failed to delete flex keys - %s. \n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = mlnx_acl_entry_offset_del(table_index, ACL_SX_RULE_PRIO_GOTO_RULE, acl_db_table(
                                           table_index).def_rules_offset);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove default rule offset\n");
        goto out;
    }

    status = mlnx_acl_table_deinit(table_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to deinit ACL offset table\n");
        goto out;
    }

    if (is_ip_ident_used) {
        status = mlnx_acl_ip_ident_key_ref_remove();
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_acl_udf_group_list_references_del(acl_db_table(table_index).udf_group_list);
    if (SAI_ERR(status)) {
        goto out;
    }

    acl_db_table(table_index).is_used = false;

out:
    acl_global_unlock();
    acl_table_unlock(table_index);
    sai_db_unlock();

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
    sx_flow_counter_id_t   sx_counter_id;
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;
    bool                   is_byte_counter, is_packet_counter;
    sx_flow_counter_type_t counter_type;
    uint32_t               table_db_idx;

    SX_LOG_ENTER();

    acl_counter_key_to_str(acl_counter_id, key_str);
    SX_LOG_NTC("Delete ACL Counter %s\n", key_str);

    acl_global_lock();

    status = mlnx_acl_counter_oid_data_get(acl_counter_id,
                                           &sx_counter_id,
                                           &is_byte_counter,
                                           &is_packet_counter,
                                           &table_db_idx);
    if (SAI_ERR(status)) {
        goto out;
    }

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

    if (SAI_STATUS_SUCCESS !=
        (sx_status = sx_api_flow_counter_set(gh_sdk, SX_ACCESS_CMD_DESTROY, counter_type, &sx_counter_id))) {
        SX_LOG_ERR("Failed delete counter - %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    if (acl_db_table(table_db_idx).counter_ref == 0) {
        SX_LOG_ERR("Failed to decrease counter reference for table %d\n", table_db_idx);
    } else {
        acl_db_table(table_db_idx).counter_ref--;
    }

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

/*
 * It is safe to call this function if rule was inited with MLNX_ACL_SX_FLEX_RULE_EMPTY value
 */
static sai_status_t mlnx_acl_flex_rule_free(_In_ sx_flex_acl_flex_rule_t *rule)
{
    sx_status_t sx_status;

    if (MLNX_ACL_SX_FLEX_RULE_IS_EMPTY(rule)) {
        return SAI_STATUS_SUCCESS;
    }

    sx_status = sx_lib_flex_acl_rule_deinit(rule);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to deinit acl rule - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
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

static sai_status_t mlnx_acl_entry_sx_acl_rule_set(_In_ uint32_t                       acl_table_index,
                                                   _In_ uint32_t                       acl_entry_index,
                                                   _In_ const sx_flex_acl_flex_rule_t *sx_flex_rule)
{
    sx_status_t          sx_status;
    sx_acl_region_id_t   sx_region_id;
    sx_acl_rule_offset_t sx_rule_offset;

    assert(NULL != sx_flex_rule);
    assert(acl_table_index_check_range(acl_table_index));
    assert(acl_entry_index_check_range(acl_entry_index));

    sx_region_id = acl_db_table(acl_table_index).region_id;
    sx_rule_offset = acl_db_entry(acl_entry_index).offset;

    sx_status = sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, sx_region_id, &sx_rule_offset, sx_flex_rule, 1);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ACL rule - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_flex_rule_delete(_In_ uint32_t                 acl_table_index,
                                              _In_ sx_flex_acl_flex_rule_t *sx_rule,
                                              _In_ sx_acl_rule_offset_t     sx_acl_rule_offset)
{
    sx_status_t             sx_status;
    sx_flex_acl_flex_rule_t sx_flex_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_acl_region_id_t      sx_region_id;

    assert(sx_rule);
    assert(acl_table_index_check_range(acl_table_index));

    sx_region_id = acl_db_table(acl_table_index).region_id;

    sx_rule->valid = false;

    sx_status = sx_api_acl_flex_rules_set(gh_sdk,
                                          SX_ACCESS_CMD_DELETE,
                                          sx_region_id,
                                          &sx_acl_rule_offset,
                                          &sx_flex_rule,
                                          1);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete ACL rule (offset %d, region %d)- %s.\n",
                   sx_acl_rule_offset, sx_region_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_rule_mc_containers_remove(_In_ sx_flex_acl_flex_rule_t *sx_rule)
{
    sai_status_t         status;
    sx_mc_container_id_t rx_list = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_id_t tx_list = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_id_t egr_block = SX_MC_CONTAINER_ID_INVALID;

    assert(sx_rule);

    status = mlnx_acl_sx_rule_mc_containers_get(sx_rule, &rx_list, &tx_list, &egr_block);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_sx_mc_container_remove(rx_list);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Faield to destroy RX sx_mc_container %d\n", rx_list);
        return status;
    }

    status = mlnx_acl_sx_mc_container_remove(tx_list);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Faield to destroy TX sx_mc_container %d\n", tx_list);
        return status;
    }

    status = mlnx_acl_sx_mc_container_remove(egr_block);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Faield to destroy Egress block sx_mc_container %d\n", egr_block);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_delete_acl_entry_data(_In_ uint32_t table_index, _In_ uint32_t entry_index)
{
    sai_status_t              status = SAI_STATUS_SUCCESS;
    sx_flex_acl_flex_rule_t   sx_flex_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;
    sx_flex_acl_rule_offset_t rule_offset;
    sx_acl_direction_t        sx_direction;
    mlnx_acl_port_db_refs_t   refs;
    mlnx_acl_pbs_info_t       pbs_info;
    uint32_t                  sx_prio;

    SX_LOG_ENTER();

    assert(acl_table_index_check_range(table_index));
    assert(acl_entry_index_check_range(entry_index));

    sx_prio = acl_db_entry(entry_index).sx_prio;
    rule_offset = acl_db_entry(entry_index).offset;
    pbs_info = acl_db_entry(entry_index).pbs_info;
    sx_direction = mlnx_acl_table_sx_direction_get(&acl_db_table(table_index));

    status = mlnx_acl_entry_sx_acl_rule_get(table_index, entry_index, &sx_flex_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_sx_rule_port_refs_get(&sx_flex_rule, refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_clear(refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_flex_rule_delete(table_index, &sx_flex_rule, rule_offset);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_sx_rule_mc_containers_remove(&sx_flex_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_pbs_info_port_refs_get(pbs_info, refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_port_refs_clear(refs);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_pbs_info_delete(pbs_info);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_entry_offset_del(table_index, sx_prio, rule_offset);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_mirror_session_ref_dec(acl_db_entry(entry_index).sx_span_session, sx_direction);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_db_entry_delete(entry_index);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    mlnx_acl_flex_rule_free(&sx_flex_rule);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_db_entry_delete(_In_ uint32_t entry_index)
{
    uint32_t last_free_index;

    assert(acl_entry_index_check_range(entry_index));

    memset(&sai_acl_db->acl_entry_db[entry_index], 0, sizeof(sai_acl_db->acl_entry_db[entry_index]));

    last_free_index = sai_acl_db->acl_settings_tbl->entry_db_first_free_index;

    sai_acl_db->acl_entry_db[entry_index].next_entry_index = last_free_index;

    sai_acl_db->acl_settings_tbl->entry_db_first_free_index = entry_index;

    sai_acl_db->acl_entry_db[entry_index].is_used = false;

    sai_acl_db->acl_settings_tbl->entry_db_indexes_allocated--;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_db_entry_add_to_table(_In_ uint32_t table_index, _In_ uint32_t entry_index)
{
    sai_status_t status;
    uint32_t     old_head_table;

    assert(acl_table_index_check_range(table_index));
    assert(acl_entry_index_check_range(entry_index));

    old_head_table = acl_db_table(table_index).head_entry_index;

    if (old_head_table != ACL_INVALID_DB_INDEX) {
        assert(acl_db_entry(old_head_table).prev_entry_index == ACL_INVALID_DB_INDEX);
        acl_db_entry(old_head_table).prev_entry_index = entry_index;
    }

    acl_db_entry(entry_index).next_entry_index = old_head_table;
    acl_db_entry(entry_index).prev_entry_index = ACL_INVALID_DB_INDEX;
    acl_db_table(table_index).head_entry_index = entry_index;

    acl_db_table(table_index).created_entry_count++;

    status = mlnx_acl_table_optimize(table_index);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_db_entry_remove_from_table(_In_ uint32_t table_index, _In_ uint32_t entry_index)
{
    sai_status_t    status;
    acl_table_db_t *table;
    uint32_t        prev_entry_index, next_entry_index;

    assert(acl_table_index_check_range(table_index));
    assert(acl_entry_index_check_range(entry_index));

    table = &acl_db_table(table_index);

    if (0 == table->created_entry_count) {
        SX_LOG_ERR("Failed to remove acl entry (%d) from acl table (%d) - Table is empty\n",
                   entry_index, table_index);
        return SAI_STATUS_FAILURE;
    }

    prev_entry_index = acl_db_entry(entry_index).prev_entry_index;
    next_entry_index = acl_db_entry(entry_index).next_entry_index;

    if (prev_entry_index == ACL_INVALID_DB_INDEX) {
        table->head_entry_index = next_entry_index;
    } else {
        acl_db_entry(prev_entry_index).next_entry_index = next_entry_index;
    }

    if (next_entry_index != ACL_INVALID_DB_INDEX) {
        acl_db_entry(next_entry_index).prev_entry_index = prev_entry_index;
    }

    table->created_entry_count--;

    status = mlnx_acl_table_optimize(table_index);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sx_utils_status_t psort_notification_func(_In_ psort_notification_type_e notif_type,
                                                 _In_ void                     *data,
                                                 _In_ void                     *cookie)
{
    sx_utils_status_t    status = SX_UTILS_STATUS_SUCCESS;
    psort_shift_param_t *shift_param = (psort_shift_param_t*)data;
    uint32_t             acl_table_id = (uint32_t)(uintptr_t)cookie;

    SX_LOG_ENTER();

    switch (notif_type) {
    case PSORT_TABLE_SHIFT_E:
        if (SAI_STATUS_SUCCESS != mlnx_acl_sx_rule_offset_update(shift_param, acl_table_id)) {
            status = SX_UTILS_STATUS_ERROR;
        }
        break;

    case PSORT_TABLE_ALMOST_EMPTY_E:
        if (SAI_STATUS_SUCCESS != mlnx_acl_table_size_decrease(acl_table_id)) {
            status = SX_UTILS_STATUS_ERROR;
        }
        break;

    case PSORT_TABLE_ALMOST_FULL_E:
        if (SAI_STATUS_SUCCESS != mlnx_acl_table_size_increase(acl_table_id)) {
            status = SX_UTILS_STATUS_ERROR;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported type of pSort notification\n");
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_size_delta_get(_In_ uint32_t acl_table_index, _Out_ uint32_t *delta)
{
    uint32_t res;

    res = (uint32_t)(acl_db_table(acl_table_index).region_size * ACL_TABLE_SIZE_INC_PERCENT);
    res = MAX(res, ACL_TABLE_SIZE_MIN_DELTA);

    *delta = res;

    return SAI_STATUS_SUCCESS;
}

static sx_acl_direction_t mlnx_acl_table_sx_direction_get(_In_ const acl_table_db_t *table)
{
    const acl_bind_point_type_list_t *list;
    uint32_t                          ii;
    bool                              is_rif;

    assert(table);

    list = &table->bind_point_types;

    is_rif = false;
    for (ii = 0; ii < list->count; ii++) {
        if (list->types[ii] == SAI_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE) {
            is_rif = true;
            break;
        }
    }

    if (table->stage == SAI_ACL_STAGE_INGRESS) {
        if (is_rif) {
            return SX_ACL_DIRECTION_RIF_INGRESS;
        }

        return SX_ACL_DIRECTION_INGRESS;
    } else {
        if (is_rif) {
            return SX_ACL_DIRECTION_RIF_EGRESS;
        }

        return SX_ACL_DIRECTION_EGRESS;
    }
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

static sai_status_t mlnx_acl_rpc_call(_Inout_ acl_rpc_info_t *rpc_info)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    ssize_t   bytes;
    socklen_t sockaddr_len;

    SX_LOG_ENTER();

    if (!sai_acl_db->acl_settings_tbl->rpc_thread_start_flag) {
        SX_LOG_ERR("Failed to use RPC - RPC thread is not working\n");
        return SAI_STATUS_FAILURE;
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

uint32_t mlnx_acl_entry_max_prio_get(void)
{
    return ACL_SAI_ENTRY_MAX_PRIO;
}

uint32_t mlnx_acl_entry_min_prio_get(void)
{
    return ACL_SAI_ENTRY_MIN_PRIO;
}

/* SP2 */
static sai_status_t mlnx_acl_sp2_table_db_init(void)
{
    assert((!acl_sp2_table_db.is_inited));

    acl_sp2_table_db.tables = calloc(ACL_TABLE_DB_SIZE, sizeof(acl_sp2_table_db.tables[0]));
    if (!acl_sp2_table_db.tables) {
        SX_LOG_ERR("Failed to allocate memory for acl_sp2_table_db\n");
        return SAI_STATUS_NO_MEMORY;
    }

    acl_sp2_table_db.is_inited = true;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_init_sp2(_In_ uint32_t table_db_idx, _In_ bool is_table_dynamic, _In_ uint32_t size)
{
    mlnx_acl_sp2_table_t *table;
    uint32_t              ii;

    assert(acl_sp2_table_db.is_inited);
    assert(acl_table_index_check_range(table_db_idx));

    table = &acl_sp2_table_db.tables[table_db_idx];

    if (table->is_inited) {
        SX_LOG_ERR("Table %d in acl_sp2_table_db is ininted\n", table_db_idx);
        return SAI_STATUS_FAILURE;
    }

    table->offsets = calloc(size, sizeof(table->offsets[0]));
    if (!table->offsets) {
        SX_LOG_ERR("Failed to allocate memory for mlnx_acl_sp2_reg_offset_t\n");
        return SAI_STATUS_NO_MEMORY;
    }

    table->size = size;
    table->allocated = 0;
    table->is_inited = true;
    table->next_free_index = 0;

    for (ii = 0; ii < size - 1; ii++) {
        table->offsets[ii].next_free_offset_idx = ii + 1;
    }

    table->offsets[size - 1].next_free_offset_idx = ACL_INVALID_DB_INDEX;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_deinit_sp2(_In_ uint32_t table_db_idx)
{
    mlnx_acl_sp2_table_t *table;

    assert(acl_sp2_table_db.is_inited);

    table = &acl_sp2_table_db.tables[table_db_idx];

    if (!table->is_inited) {
        SX_LOG_ERR("Table %u in acl_sp2_table_db is not inited\n", table_db_idx);
        return SAI_STATUS_FAILURE;
    }

    if (table->allocated > 0) {
        SX_LOG_ERR("Table %u in acl_sp2_table_db is not empty, allocated offsets - %u\n",
                   table_db_idx,
                   table->allocated);
        return SAI_STATUS_FAILURE;
    }

    free(table->offsets);

    memset(table, 0, sizeof(*table));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_offset_get_sp2(_In_ uint32_t               table_db_idx,
                                                  _In_ uint32_t               entry_db_idx,
                                                  _In_ uint32_t               priority,
                                                  _Out_ sx_acl_rule_offset_t *sx_offset)
{
    sai_status_t          status;
    mlnx_acl_sp2_table_t *table;
    int32_t               free_offset;

    assert(acl_sp2_table_db.is_inited);

    table = &acl_sp2_table_db.tables[table_db_idx];

    if (!table->is_inited) {
        SX_LOG_ERR("Table %u in acl_sp2_table_db is not inited\n", table_db_idx);
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_acl_table_check_size_increase(table_db_idx);
    if (SAI_ERR(status)) {
        return status;
    }

    if (table->next_free_index == ACL_INVALID_DB_INDEX) {
        SX_LOG_ERR("Failed to allocate new offset - table %u is full\n", table_db_idx);
        return SAI_STATUS_FAILURE;
    }

    free_offset = table->next_free_index;
    table->next_free_index = table->offsets[free_offset].next_free_offset_idx;
    table->offsets[free_offset].next_free_offset_idx = ACL_INVALID_DB_INDEX;

    *sx_offset = free_offset;
    table->allocated++;

    SX_LOG_DBG("ACL table idx %d: added entry offset %u, allocated - %u, table size = %u\n", table_db_idx, free_offset,
               table->allocated, table->size);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_offset_del_sp2(_In_ uint32_t             table_db_idx,
                                                  _In_ uint32_t             priority,
                                                  _In_ sx_acl_rule_offset_t offset)
{
    mlnx_acl_sp2_table_t *table;
    uint32_t              next_free_offset;

    assert(acl_sp2_table_db.is_inited);

    table = &acl_sp2_table_db.tables[table_db_idx];

    if (!table->is_inited) {
        SX_LOG_ERR("Table %u in acl_sp2_table_db is not inited\n", table_db_idx);
        return SAI_STATUS_FAILURE;
    }

    if (table->allocated == 0) {
        SX_LOG_ERR("Attempt to free offset while table->allocated = 0\n");
        return SAI_STATUS_FAILURE;
    }

    if (table->size <= offset) {
        SX_LOG_ERR("Offset %u is out of range, table size - %u\n", offset, table->size);
        return SAI_STATUS_FAILURE;
    }

    next_free_offset = table->next_free_index;
    table->offsets[offset].next_free_offset_idx = next_free_offset;
    table->next_free_index = offset;

    table->allocated--;

    SX_LOG_DBG("ACL table idx %d: deinited entry offset %u, allocated - %u, table size = %u\n", table_db_idx, offset,
               table->allocated, table->size);

    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_acl_entry_prio_set_sp2(_In_ uint32_t table_db_idx,
                                                _In_ uint32_t entry_db_idx,
                                                _In_ uint32_t sx_prio)
{
    sai_status_t            status;
    sx_flex_acl_flex_rule_t sx_rule = MLNX_ACL_SX_FLEX_RULE_EMPTY;

    status = mlnx_acl_entry_sx_acl_rule_get(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_rule.priority = sx_prio;

    status = mlnx_acl_entry_sx_acl_rule_set(table_db_idx, entry_db_idx, &sx_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    mlnx_acl_flex_rule_free(&sx_rule);
    return status;
}

static sai_status_t mlnx_acl_deinit_sp2(void)
{
    uint32_t ii;

    if (!acl_sp2_table_db.is_inited) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < ACL_TABLE_DB_SIZE; ii++) {
        if (acl_sp2_table_db.tables[ii].is_inited) {
            free(acl_sp2_table_db.tables[ii].offsets);
        }
    }

    free(acl_sp2_table_db.tables);
    acl_sp2_table_db.is_inited = false;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_size_set_sp2(_In_ uint32_t table_db_idx, _In_ uint32_t size)
{
    mlnx_acl_sp2_table_t *table;
    uint32_t              ii, new_offsets_idx_start;

    assert(acl_sp2_table_db.is_inited);
    assert(acl_sp2_table_db.tables);

    table = &acl_sp2_table_db.tables[table_db_idx];

    /* Tables don't get decreased */
    if (size <= table->size) {
        return SAI_STATUS_SUCCESS;
    }

    table->offsets = realloc(table->offsets, size * sizeof(table->offsets[0]));
    if (!table->offsets) {
        SX_LOG_ERR("Failed to realloc table->offsets for table %d\n", table_db_idx);
        return SAI_STATUS_NO_MEMORY;
    }

    new_offsets_idx_start = table->size;

    /* Building a linked list of new free offsets */
    for (ii = new_offsets_idx_start; ii < size - 1; ii++) {
        table->offsets[ii].next_free_offset_idx = ii + 1;
    }

    table->offsets[size - 1].next_free_offset_idx = table->next_free_index;
    table->next_free_index = new_offsets_idx_start;

    table->size = size;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_rule_prio_set_sp2(_In_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t sx_prio)
{
    rule->priority = sx_prio;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_init_sp2(void)
{
    sai_status_t status;

    status = mlnx_acl_sp2_table_db_init();
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* SP1 */
static sai_status_t mlnx_acl_table_init_sp(_In_ uint32_t table_db_idx, _In_ bool is_table_dynamic, _In_ uint32_t size)
{
    sx_utils_status_t  sx_status;
    psort_init_param_t psort_init_param;

    if (!acl_table_index_check_range(table_db_idx)) {
        SX_LOG_ERR("Attempt to use invalid ACL Table DB index\n");
        return SAI_STATUS_FAILURE;
    }

    memset(&psort_init_param, 0, sizeof(psort_init_param));

    psort_init_param.table_size = size;
    psort_init_param.cookie = (void*)(intptr_t)table_db_idx;
    psort_init_param.delta_size = 1;
    psort_init_param.min_priority = ACL_PSORT_TABLE_MIN_PRIO;
    psort_init_param.max_priority = ACL_PSORT_TABLE_MAX_PRIO;
    psort_init_param.notif_callback = psort_notification_func;

    if (true == is_table_dynamic) {
        psort_init_param.table_almost_empty_precentage_threshold = PSORT_ALMOST_EMPTY_PERC_DYN;
        psort_init_param.table_almost_full_precentage_threshold = PSORT_ALMOST_FULL_PERC_DYN;
    } else {
        psort_init_param.table_almost_empty_precentage_threshold = PSORT_ALMOST_EMPTY_PERC_STATIC;
        psort_init_param.table_almost_full_precentage_threshold = PSORT_ALMOST_FULL_PERC_STATIC;
    }

    sx_status = psort_init(&acl_db_table(table_db_idx).psort_handle, &psort_init_param);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create psort table - %s\n", SX_UTILS_STATUS_MSG(sx_status));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_deinit_sp(_In_ uint32_t table_db_idx)
{
    sx_utils_status_t sx_status;
    psort_handle_t    psort_handle;

    if (!acl_table_index_check_range(table_db_idx)) {
        SX_LOG_ERR("Attempt to use invalid ACL Table DB index\n");
        return SAI_STATUS_FAILURE;
    }

    psort_handle = acl_db_table(table_db_idx).psort_handle;

    sx_status = psort_clear_table(psort_handle);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to delete psort table - %s\n", SX_UTILS_STATUS_MSG(sx_status));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_offset_get_sp(_In_ uint32_t               table_db_idx,
                                                 _In_ uint32_t               entry_db_idx,
                                                 _In_ uint32_t               priority,
                                                 _Out_ sx_acl_rule_offset_t *sx_offset)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sx_utils_status_t sx_status;
    psort_handle_t    psort_handle;
    psort_entry_t     psort_entry;

    assert(acl_table_index_check_range(table_db_idx));

    status = mlnx_acl_table_check_size_increase(table_db_idx);
    if (SAI_ERR(status)) {
        return status;
    }

    psort_handle = acl_db_table(table_db_idx).psort_handle;
    psort_entry.key = entry_db_idx;
    psort_entry.priority = priority;

    sx_status = psort_entry_set(psort_handle, SX_UTILS_CMD_ADD, &psort_entry);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get offset form pSort - %s\n", SX_UTILS_STATUS_MSG(sx_status));
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_DBG("Added psort entry (index %u, prio %u)\n", psort_entry.index, psort_entry.priority);

    *sx_offset = psort_entry.index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_offset_del_sp(_In_ uint32_t             table_db_idx,
                                                 _In_ uint32_t             priority,
                                                 _In_ sx_acl_rule_offset_t offset)
{
    sx_utils_status_t sx_status;
    psort_handle_t    psort_handle;
    psort_entry_t     psort_entry;

    if (!acl_table_index_check_range(table_db_idx)) {
        SX_LOG_ERR("Attempt to use invalid ACL Table DB index\n");
        return SAI_STATUS_FAILURE;
    }

    psort_handle = acl_db_table(table_db_idx).psort_handle;
    psort_entry.priority = priority;
    psort_entry.index = offset;

    sx_status = psort_entry_set(psort_handle, SX_UTILS_CMD_DELETE, &psort_entry);
    if (SX_UTILS_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to remove (index %u, prio %u) from psort - %s\n", offset, priority,
                   SX_UTILS_STATUS_MSG(sx_status));
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_DBG("Removed psort entry (index %u, prio %u)\n", priority, offset);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_prio_set_sp(_In_ uint32_t table_db_idx,
                                               _In_ uint32_t entry_db_idx,
                                               _In_ uint32_t sx_prio)
{
    sx_status_t          sx_status;
    sai_status_t         status;
    sx_acl_region_id_t   region_id;
    sx_acl_rule_offset_t new_rule_offset, old_rule_offset;
    uint32_t             old_sx_prio, table_size, table_entries_count;

    table_size = ACL_SX_REG_SIZE_TO_TABLE_SIZE(acl_db_table(table_db_idx).region_size);
    region_id = acl_db_table(table_db_idx).region_id;
    table_entries_count = acl_db_table(table_db_idx).created_entry_count;
    old_sx_prio = acl_db_entry(entry_db_idx).sx_prio;

    if (table_size < table_entries_count + 1) {
        SX_LOG_ERR("Impossible to change a priority for SAI ACL Entry since SAI ACL Table [%d] is full\n",
                   table_db_idx);
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_acl_entry_offset_get(table_db_idx, entry_db_idx, sx_prio, &new_rule_offset);
    if (SAI_ERR(status)) {
        return status;
    }

    /* It can be changed in mlnx_acl_entry_offset_get */
    old_rule_offset = acl_db_entry(entry_db_idx).offset;

    SX_LOG_DBG("Moving ACL table %u entry idx %u: %u -> %u\n",
               table_db_idx,
               entry_db_idx,
               old_rule_offset,
               new_rule_offset);

    sx_status = sx_api_acl_rule_block_move_set(gh_sdk, region_id, old_rule_offset, 1, new_rule_offset);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to move rule block - %s\n", SX_STATUS_MSG(sx_status));
        return status;
    }

    status = mlnx_acl_entry_offset_del(table_db_idx, old_sx_prio, old_rule_offset);
    if (SAI_ERR(status)) {
        return status;
    }

    acl_db_entry(entry_db_idx).offset = new_rule_offset;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_init_sp(void)
{
#ifndef _WIN32
    pthread_condattr_t cond_attr;

    if (0 != pthread_condattr_init(&cond_attr)) {
        SX_LOG_ERR("Failed to init condition variable attribute for ACL\n");
        return SAI_STATUS_NO_MEMORY;
    }

    if (0 != pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED)) {
        SX_LOG_ERR("Failed to set condition variable attribute for ACL - %s\n", strerror(errno));
        return SAI_STATUS_NO_MEMORY;
    }

    if (0 != pthread_cond_init(&sai_acl_db->acl_settings_tbl->psort_thread_init_cond, &cond_attr)) {
        SX_LOG_ERR("Failed to init condition variable for ACL - %s\n", strerror(errno));
        return SAI_STATUS_NO_MEMORY;
    }

    if (CL_SUCCESS != cl_thread_init(&psort_thread, psort_background_thread, NULL, NULL)) {
        SX_LOG_ERR("Failed to init psort thread\n");
        return SAI_STATUS_NO_MEMORY;
    }

    if (0 != pthread_condattr_destroy(&cond_attr)) {
        SX_LOG_ERR("Failed to destory condition variable attribute for ACL\n");
        return SAI_STATUS_FAILURE;
    }
#endif /* _WIN32 */

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_psort_opt_queue_create(void)
{
#ifndef _WIN32
    struct mq_attr mq_attributes;

    memset(&mq_attributes, 0, sizeof(mq_attributes));

    mq_attributes.mq_flags = 0;
    mq_attributes.mq_maxmsg = ACL_QUEUE_SIZE;
    mq_attributes.mq_msgsize = ACL_QUEUE_MSG_SIZE;
    mq_attributes.mq_curmsgs = 0;

    mq_unlink(ACL_QUEUE_NAME);

    psort_opt_queue_client = mq_open(ACL_QUEUE_NAME,
                                     O_CREAT | O_WRONLY | O_NONBLOCK,
                                     (S_IRWXU | S_IRWXG | S_IRWXO),
                                     &mq_attributes);
    if (ACL_QUEUE_INVALID_HANDLE == psort_opt_queue_client) {
        SX_LOG_ERR("Failed to open acl fg_mq - %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
#endif /* _WIN32 */

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_psort_opt_queue_client_create(void)
{
#ifndef _WIN32
    if (ACL_QUEUE_INVALID_HANDLE == psort_opt_queue_client) {
        psort_opt_queue_client = mq_open(ACL_QUEUE_NAME, O_WRONLY | O_NONBLOCK);
        if (ACL_QUEUE_INVALID_HANDLE == psort_opt_queue_client) {
            SX_LOG_ERR("Failed to open mq - %s\n", strerror(errno));
            return SAI_STATUS_FAILURE;
        }

        SX_LOG_DBG("Created psort_opt_queue_client - %d\n", psort_opt_queue_client);
    }
#endif /* _WIN32 */

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_psort_opt_queue_client_close(void)
{
#ifndef _WIN32
    if (ACL_QUEUE_INVALID_HANDLE != psort_opt_queue_client) {
        if (0 != mq_close(psort_opt_queue_client)) {
            SX_LOG_ERR("Failed to close ACL psort optimization queue - %s\n", strerror(errno));
            return SAI_STATUS_FAILURE;
        }

        SX_LOG_DBG("Removed psort_opt_queue_client - %d\n", psort_opt_queue_client);

        psort_opt_queue_client = ACL_QUEUE_INVALID_HANDLE;
    }
#endif /* _WIN32 */

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_psort_thread_wake(void)
{
#ifndef _WIN32
    /* Wake up ACL pSort optimizations thread */
    acl_cond_mutex_lock();
    sai_acl_db->acl_settings_tbl->psort_thread_start_flag = true;
    if (0 != pthread_cond_signal(&sai_acl_db->acl_settings_tbl->psort_thread_init_cond)) {
        SX_LOG_ERR("Failed to signal condition var to wake up ACL psort thread\n");
        acl_cond_mutex_unlock();
        return SAI_STATUS_FAILURE;
    }
    acl_cond_mutex_unlock();
#endif /* _WIN32 */

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_lazy_init_sp(void)
{
    sai_status_t status;

    status = mlnx_acl_psort_opt_queue_create();
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_psort_thread_wake();
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_deinit_sp(void)
{
    sai_status_t status;
    uint32_t     table_index;

    status = acl_psort_background_close();
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to close pSort background thread\n");
        return status;
    }

    status = mlnx_acl_psort_opt_queue_client_close();
    if (SAI_ERR(status)) {
        return status;
    }

    for (table_index = 0; table_index < ACL_TABLE_DB_SIZE; table_index++) {
        if (acl_db_table(table_index).is_used) {
            status = mlnx_acl_table_deinit_sp(table_index);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_size_set_sp(_In_ uint32_t table_db_idx, _In_ uint32_t size)
{
    sx_utils_status_t sx_utils_status;
    psort_handle_t    psort_handle;

    assert(acl_table_index_check_range(table_db_idx));

    psort_handle = acl_db_table(table_db_idx).psort_handle;

    sx_utils_status = psort_table_resize(psort_handle, size, false, NULL);
    if (SX_UTILS_STATUS_SUCCESS != sx_utils_status) {
        SX_LOG_ERR("Failed to resize a table[%d] %s.\n", table_db_idx, SX_UTILS_STATUS_MSG(sx_utils_status));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_optimize_sp(_In_ uint32_t table_db_idx)
{
#ifndef _WIN32
    sai_status_t status;

    if (!sai_acl_db->acl_settings_tbl->psort_thread_start_flag) {
        SX_LOG_ERR("Failed to optimize - ACL pSort thread is not working\n");
        return SAI_STATUS_FAILURE;
    }

    if (sai_acl_db->acl_settings_tbl->psort_thread_suspended) {
        SX_LOG_NTC("Failed to optimize - ACL pSort thread is suspended\n");
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_acl_psort_opt_queue_client_create();
    if (SAI_ERR(status)) {
        return status;
    }

    acl_db_table(table_db_idx).queued++;
    if (-1 == mq_send(psort_opt_queue_client, (const char*)&table_db_idx,
                      sizeof(table_db_idx), ACL_QUEUE_DEF_MSG_PRIO)) {
        if (EAGAIN == errno) {
            SX_LOG_NTC("Failed to enqueue table %d - queue is full\n", table_db_idx);
            acl_db_table(table_db_idx).queued--;
            return SAI_STATUS_SUCCESS;
        } else {
            SX_LOG_ERR("Failed to enqueue table %d - %s\n", table_db_idx, strerror(errno));
            acl_db_table(table_db_idx).queued--;
            return SAI_STATUS_FAILURE;
        }
    }

#endif
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_rule_prio_set_sp(_In_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t sx_prio)
{
    rule->priority = FLEX_ACL_INVALID_RULE_PRIORITY;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_init(_In_ uint32_t table_db_idx, _In_ bool is_table_dynamic, _In_ uint32_t size)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    assert(mlnx_acl_cb);

    if (is_init_process) {
        status = mlnx_acl_cb->table_init(table_db_idx, is_table_dynamic, size);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type = ACL_RPC_TABLE_INIT;
        rpc_info.args.table_id = table_db_idx;
        rpc_info.args.table_is_dynamic = is_table_dynamic;
        rpc_info.args.size = size;

        status = mlnx_acl_rpc_call(&rpc_info);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_table_deinit(_In_ uint32_t table_db_idx)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    assert(mlnx_acl_cb);

    if (is_init_process) {
        status = mlnx_acl_cb->table_deinit(table_db_idx);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type = ACL_RPC_TABLE_DELETE;
        rpc_info.args.table_id = table_db_idx;

        status = mlnx_acl_rpc_call(&rpc_info);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_offset_get(_In_ uint32_t                 table_db_idx,
                                              _In_ uint32_t                 entry_db_idx,
                                              _In_ uint32_t                 sx_prio,
                                              _Inout_ sx_acl_rule_offset_t *offset)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    assert(mlnx_acl_cb);

    if (is_init_process) {
        status = mlnx_acl_cb->entry_offset_get(table_db_idx, entry_db_idx, sx_prio, offset);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type = ACL_RPC_ENTRY_OFFSET_GET;
        rpc_info.args.table_id = table_db_idx;
        rpc_info.args.entry_id = entry_db_idx;
        rpc_info.args.entry_prio = sx_prio;

        status = mlnx_acl_rpc_call(&rpc_info);
        *offset = rpc_info.args.entry_offset;
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_offset_del(_In_ uint32_t             table_db_idx,
                                              _In_ uint32_t             sx_prio,
                                              _In_ sx_acl_rule_offset_t offset)
{
    sai_status_t   status;
    acl_rpc_info_t rpc_info;

    SX_LOG_ENTER();

    assert(mlnx_acl_cb);

    if (is_init_process) {
        status = mlnx_acl_cb->entry_offset_del(table_db_idx, sx_prio, offset);
    } else {
        memset(&rpc_info, 0, sizeof(rpc_info));
        rpc_info.type = ACL_RPC_ENTRY_OFFSET_DEL;
        rpc_info.args.table_id = table_db_idx;
        rpc_info.args.entry_prio = sx_prio;
        rpc_info.args.entry_offset = offset;

        status = mlnx_acl_rpc_call(&rpc_info);
    }

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_acl_entry_prio_set(_In_ uint32_t table_db_idx,
                                            _In_ uint32_t entry_db_idx,
                                            _In_ uint32_t sx_prio)
{
    assert(mlnx_acl_cb);

    return mlnx_acl_cb->entry_prio_set(table_db_idx, entry_db_idx, sx_prio);
}

static sai_status_t mlnx_acl_sx_rule_prio_set(_In_ sx_flex_acl_flex_rule_t *rule, _In_ uint32_t sx_prio)
{
    assert(mlnx_acl_cb);

    return mlnx_acl_cb->rule_prio_set(rule, sx_prio);
}

static sai_status_t mlnx_acl_table_check_size_increase(_In_ uint32_t table_db_idx)
{
    sai_status_t status;

    if ((acl_db_table(table_db_idx).created_entry_count + 1) >
        (ACL_SX_REG_SIZE_TO_TABLE_SIZE(acl_db_table(table_db_idx).region_size))) {
        status = mlnx_acl_table_size_increase(table_db_idx);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_acl_cb_table_init(void)
{
    sx_chip_types_t chip_type;

    chip_type = g_sai_db_ptr->sx_chip_type;

    switch (chip_type) {
    case SX_CHIP_TYPE_SPECTRUM:
    case SX_CHIP_TYPE_SPECTRUM_A1:
        mlnx_acl_cb = &mlnx_acl_cb_sp;
        break;

    case SX_CHIP_TYPE_SPECTRUM2:
        mlnx_acl_cb = &mlnx_acl_cb_sp2;
        break;

    case SX_CHIP_TYPE_SPECTRUM3:
        mlnx_acl_cb = &mlnx_acl_cb_sp2;
        break;

    default:
        SX_LOG_ERR("g_sai_db_ptr->sxd_chip_type = %s\n", SX_CHIP_TYPE_STR(chip_type));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_acl_init(void)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii;

    SX_LOG_ENTER();

    is_init_process = true;

    sai_acl_db->acl_settings_tbl->lazy_initialized = false;
    sai_acl_db->acl_settings_tbl->psort_thread_stop_flag = false;
    sai_acl_db->acl_settings_tbl->psort_thread_start_flag = false;
    sai_acl_db->acl_settings_tbl->rpc_thread_stop_flag = false;
    sai_acl_db->acl_settings_tbl->rpc_thread_start_flag = false;
    sai_acl_db->acl_settings_tbl->psort_thread_suspended = false;
    sai_acl_db->acl_settings_tbl->psort_thread_suspended_ack = false;

#ifndef _WIN32
    pthread_condattr_t  cond_attr;
    pthread_mutexattr_t mutex_attr;

    if (0 != pthread_condattr_init(&cond_attr)) {
        SX_LOG_ERR("Failed to init condition variable attribute for ACL\n");
        return SAI_STATUS_NO_MEMORY;
    }

    if (0 != pthread_mutexattr_init(&mutex_attr)) {
        SX_LOG_ERR("Failed to init condition variable attribute for ACL\n");
        return SAI_STATUS_NO_MEMORY;
    }

    if (0 != pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED)) {
        SX_LOG_ERR("Failed to set condition variable attribute for ACL - %s\n", strerror(errno));
        return SAI_STATUS_NO_MEMORY;
    }

    if (0 != pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED)) {
        SX_LOG_ERR("Failed to set condition variable attribute for ACL - %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    if (0 != pthread_mutex_init(&sai_acl_db->acl_settings_tbl->cond_mutex, &mutex_attr)) {
        SX_LOG_ERR("Failed to init mutex for ACL - %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    if (0 != pthread_cond_init(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond, &cond_attr)) {
        SX_LOG_ERR("Failed to init condition variable for ACL - %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    if (0 != pthread_mutexattr_destroy(&mutex_attr)) {
        SX_LOG_ERR("Failed to destory mutex attribute for ACL\n");
        return SAI_STATUS_FAILURE;
    }

    if (0 != pthread_condattr_destroy(&cond_attr)) {
        SX_LOG_ERR("Failed to destory condition variable attribute for ACL\n");
        return SAI_STATUS_FAILURE;
    }

    if (CL_SUCCESS != cl_plock_init_pshared(&sai_acl_db->acl_settings_tbl->lock)) {
        SX_LOG_ERR("Failed to init cl_plock for ACL\n");
        return SAI_STATUS_FAILURE;
    }

    if (0 != pthread_key_create(&pthread_sx_handle_key, NULL)) {
        SX_LOG_ERR("Failed to init pthread_key for ACL\n");
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    if (CL_SUCCESS != cl_thread_init(&rpc_thread, mlnx_acl_rpc_thread, NULL, NULL)) {
        SX_LOG_ERR("Failed to init acl req thread\n");
        return SAI_STATUS_FAILURE;
    }
#endif /* _WIN32 */

    /* Inint ACL entry db */
    sai_acl_db->acl_settings_tbl->entry_db_first_free_index = 0;

    for (ii = 0; ii < ACL_ENTRY_DB_SIZE - 1; ii++) {
        sai_acl_db->acl_entry_db[ii].is_used = false;
        sai_acl_db->acl_entry_db[ii].next_entry_index = ii + 1;
    }

    sai_acl_db->acl_entry_db[ACL_ENTRY_DB_SIZE - 1].is_used = false;
    sai_acl_db->acl_entry_db[ACL_ENTRY_DB_SIZE - 1].next_entry_index = ACL_INVALID_DB_INDEX;

    /* Platform-specific init */
    status = mlnx_acl_cb->init();
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_vxlan_srcport_acl_add(sai_object_id_t switch_id)
{
    sx_status_t               status;
    sx_flex_acl_flex_action_t action;
    sx_flex_acl_key_desc_t    key_desc;
    sx_acl_key_t              key;
    sx_acl_key_type_t         key_handle;
    sx_flex_acl_flex_rule_t   rule;
    sx_acl_region_id_t        region_id;
    sx_acl_region_group_t     region_group;
    sx_acl_id_t               acl_group, acl_id;
    sx_acl_rule_offset_t      offset[] = {0};


    action.type = SX_FLEX_ACL_ACTION_HASH;
    action.fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_XOR;
    action.fields.action_hash.hash_value = 1 << 7;
    if (mlnx_chip_is_spc()) {
        action.fields.action_hash.type = SX_ACL_ACTION_HASH_TYPE_LAG;
    } else if (mlnx_chip_is_spc2or3()) {
        action.fields.action_hash.type = SX_ACL_ACTION_HASH_TYPE_ECMP;
    }

    /* ACL key */
    if (mlnx_chip_is_spc()) {
        key_desc.key_id = FLEX_ACL_KEY_LAG_HASH;
        key_desc.key.lag_hash = 0;
        key_desc.mask.lag_hash = 1 << 7;
        key = FLEX_ACL_KEY_LAG_HASH;
    } else if (mlnx_chip_is_spc2or3()) {
        key_desc.key_id = FLEX_ACL_KEY_ECMP_HASH;
        key_desc.key.ecmp_hash = 0;
        key_desc.mask.ecmp_hash = 1 << 7;
        key = FLEX_ACL_KEY_ECMP_HASH;
    }

    status = sx_api_acl_flex_key_set(gh_sdk, SX_ACCESS_CMD_CREATE, &key, 1, &key_handle);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to create key %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* ACL region */
    status = sx_api_acl_region_set(gh_sdk,
                                   SX_ACCESS_CMD_CREATE,
                                   key_handle,
                                   SX_ACL_ACTION_TYPE_BASIC,
                                   1,
                                   &region_id);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to create ACL region %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    memset(&region_group, 0, sizeof(region_group));
    region_group.acl_type = SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC;
    region_group.regions.acl_packet_agnostic.region = region_id;

    status = sx_api_acl_set(gh_sdk,
                            SX_ACCESS_CMD_CREATE,
                            SX_ACL_TYPE_PACKET_TYPES_AGNOSTIC,
                            SX_ACL_DIRECTION_EGRESS,
                            &region_group,
                            &acl_id);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to create ACL %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* create ACL rule */
    status = sx_lib_flex_acl_rule_init(key_handle, 8, &rule);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to init ACL rule %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    rule.key_desc_list_p = &key_desc;
    rule.key_desc_count = 1;
    rule.action_list_p = &action;
    rule.action_count = 1;
    rule.valid = true;
    rule.priority = 10;

    status = sx_api_acl_flex_rules_set(gh_sdk, SX_ACCESS_CMD_SET, region_id, offset, &rule, 1);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to create ACL rule %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* ACL group create */
    status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, SX_ACL_DIRECTION_EGRESS, NULL, 0, &acl_group);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to create acl group - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }


    status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, SX_ACL_DIRECTION_EGRESS, &acl_id, 1, &acl_group);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to create ACL group - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    g_sai_db_ptr->vxlan_acl_id = acl_group;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_optimize(_In_ uint32_t table_db_idx)
{
    assert(mlnx_acl_cb);

    /* SP2 doesn't use pSort so there is no optimization */
    if (mlnx_acl_cb->table_optimize) {
        return mlnx_acl_cb->table_optimize(table_db_idx);
    }

    return SAI_STATUS_SUCCESS;
}

static sx_api_handle_t* mlnx_acl_sx_handle_get(void)
{
#ifndef _WIN32
    sx_api_handle_t *handle;

    handle = pthread_getspecific(pthread_sx_handle_key);
    if (handle) {
        return handle;
    }
#endif /* _WIN32 */
    return &gh_sdk;
}

static sai_status_t mlnx_acl_table_size_increase(_In_ uint32_t table_index)
{
    sai_status_t       status;
    sx_status_t        sx_status;
    sx_api_handle_t   *sx_api_handle = NULL;
    sx_acl_key_type_t  key_type;
    sx_acl_region_id_t region_id;
    sx_acl_size_t      old_size, new_size;
    uint32_t           delta;

    assert(acl_table_index_check_range(table_index));

    sx_api_handle = mlnx_acl_sx_handle_get();

    region_id = acl_db_table(table_index).region_id;
    key_type = acl_db_table(table_index).key_type;
    old_size = acl_db_table(table_index).region_size;

    status = mlnx_acl_table_size_delta_get(table_index, &delta);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get size delta for table %d\n", table_index);
        return status;
    }

    new_size = old_size + delta;

    SX_LOG_DBG("Resizing table %u: [%u, %u]\n", table_index,
               ACL_SX_REG_SIZE_TO_TABLE_SIZE(old_size), ACL_SX_REG_SIZE_TO_TABLE_SIZE(new_size));

    sx_status = sx_api_acl_region_set(*sx_api_handle, SX_ACCESS_CMD_EDIT, key_type,
                                      SX_ACL_ACTION_TYPE_BASIC, new_size, &region_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to resize a region[%u] - %s.\n", region_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_acl_cb->table_size_set(table_index, new_size);
    if (SAI_ERR(status)) {
        return status;
    }

    acl_db_table(table_index).region_size = new_size;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_table_size_decrease(_In_ uint32_t table_index)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    sx_status_t        sx_status;
    sx_api_handle_t   *sx_api_handle = NULL;
    sx_acl_key_type_t  key_type;
    sx_acl_region_id_t region_id;
    sx_acl_size_t      new_size, old_size;

    assert(acl_table_index_check_range(table_index));

    if (!acl_db_table(table_index).is_dynamic_sized) {
        return SAI_STATUS_SUCCESS;
    }

    sx_api_handle = mlnx_acl_sx_handle_get();

    region_id = acl_db_table(table_index).region_id;
    key_type = acl_db_table(table_index).key_type;
    old_size = acl_db_table(table_index).region_size;

    new_size = old_size / 2;
    new_size = MAX(new_size, ACL_TABLE_SIZE_TO_SX_REG_SIZE(ACL_DEFAULT_TABLE_SIZE));

    if (old_size <= new_size) {
        return SAI_STATUS_SUCCESS;
    }

    SX_LOG_DBG("Decreasing a size of a table %u: [%u -> %u]\n", table_index, old_size, new_size);

    status = mlnx_acl_cb->table_size_set(table_index, new_size);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_acl_region_set(*sx_api_handle, SX_ACCESS_CMD_EDIT, key_type, SX_ACL_ACTION_TYPE_BASIC,
                                      new_size, &region_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to resize a region[%d] - %s.\n", table_index, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl_db_table(table_index).region_size = new_size;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_sx_rule_offset_update(_In_ const psort_shift_param_t *shift_param,
                                                   _In_ uint32_t                   acl_table_index)
{
    sx_status_t          sx_status;
    sx_api_handle_t     *sx_api_handle = NULL;
    sx_acl_region_id_t   region_id;
    sx_acl_rule_offset_t old_offset;
    sx_acl_rule_offset_t new_offset;
    uint32_t             acl_entry_index;

    SX_LOG_ENTER();

    sx_api_handle = mlnx_acl_sx_handle_get();

    region_id = acl_db_table(acl_table_index).region_id;
    acl_entry_index = (uint32_t)shift_param->key;
    old_offset = shift_param->old_index;
    new_offset = shift_param->new_index;

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

    SX_LOG_DBG("Moving ACL table %u entry idx %u: %u -> %u %s\n", acl_table_index, acl_entry_index,
               old_offset, new_offset, (ACL_INVALID_DB_INDEX == acl_entry_index) ? "(default rule)" : " ");

    sx_status = sx_api_acl_rule_block_move_set(*sx_api_handle, region_id, old_offset, 1, new_offset);
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
    uint64_t          start_ms = 0, current_ms = 0;
    struct timeval    tv;
    boolean_t         is_complete = false;

    SX_LOG_ENTER();

    acl_table_write_lock(table_index);

    if (false == acl_db_table(table_index).is_used) {
        SX_LOG_DBG("Attempt to use deleted ACL Table DB index - %u\n", table_index);
        goto out;
    }

    if (0 == acl_db_table(table_index).created_entry_count) {
        goto out;
    }

    psort_handle = acl_db_table(table_index).psort_handle;

    gettimeofday(&tv, NULL);
    start_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    do {
        status = psort_background_worker(psort_handle, &is_complete);
        if (SX_UTILS_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to run psort bg\n");
            goto out;
        }

        gettimeofday(&tv, NULL);
        current_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    } while (!is_complete && ((current_ms - start_ms) <= (ACL_PSORT_OPT_MAX_TIME_MS / 2)));

out:
    acl_table_unlock(table_index);
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

    memcpy(table_data, &table_index, sizeof(table_index));

    status = mlnx_create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_index, table_data, entry_oid);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_acl_psort_thread_suspend(void)
{
    sai_status_t         status;
    const volatile bool *suspend_ack = &sai_acl_db->acl_settings_tbl->psort_thread_suspended_ack;

    if (false == sai_acl_db->acl_settings_tbl->psort_thread_start_flag) {
        SX_LOG_DBG("ACL pSort thread is not running - nothing to suspend\n");
        return SAI_STATUS_SUCCESS;
    }

    sai_acl_db->acl_settings_tbl->psort_thread_suspended = true;

    status = mlnx_acl_psort_thread_unblock();
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_psort_opt_queue_client_close();
    if (SAI_ERR(status)) {
        return status;
    }

    /* suspend_ack is volatile since otherwise compiler assumes that the following loop is infinite */
    while (!(*suspend_ack)) {
#ifndef _WIN32
        usleep(0);
#endif
    }

    SX_LOG_DBG("ACL pSort thread is now suspended\n");

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_acl_psort_thread_resume(void)
{
    sai_status_t status;

    if (!sai_acl_db->acl_settings_tbl->psort_thread_suspended) {
        SX_LOG_DBG("ACL pSort thread is not suspended - nothing to resume\n");
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_acl_psort_opt_queue_create();
    if (SAI_ERR(status)) {
        return status;
    }

    sai_acl_db->acl_settings_tbl->psort_thread_suspended = false;
    sai_acl_db->acl_settings_tbl->psort_thread_suspended_ack = false;

    status = mlnx_acl_psort_thread_wake();
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_DBG("ACL pSort thread is now resumed\n");

    return SAI_STATUS_SUCCESS;
}

static void mlnx_acl_psort_queue_drain(void)
{
#ifndef _WIN32
    mqd_t    mq;
    uint32_t table_idx, ii;

    mq = mq_open(ACL_QUEUE_NAME, O_RDONLY | O_NONBLOCK);
    if (ACL_QUEUE_INVALID_HANDLE == mq) {
        SX_LOG_ERR("Failed to open mqueue handle - %s\n", strerror(errno));
        return;
    }

    for (ii = 0; ii < ACL_QUEUE_SIZE; ii++) {
        if (-1 == mq_receive(mq, (char*)&table_idx, sizeof(table_idx), NULL)) {
            if (errno == EAGAIN) {
                break;
            }

            SX_LOG_ERR("Failed to drain pSort mqueue - %s\n", strerror(errno));
            break;
        }

        if (table_idx == ACL_QUEUE_UNBLOCK_MSG) {
            continue;
        }

        if (!acl_table_index_check_range(table_idx)) {
            SX_LOG_ERR("Attempt to use invalid ACL Table DB index while draining mqueue - %u\n", table_idx);
            continue;
        }

        acl_db_table(table_idx).queued = 0;
    }

    mq_close(mq);
#endif /* ifndef _WIN32 */
}

/* Thread can be in 3 states:
 * - not started (psort_thread_start_flag = false)
 * - running (psort_thread_start_flag = true, suspended = false)
 * - suspended (psort_thread_start_flag = true, suspended = true)
 *
 * The state is controlled via 'psort_thread_start_flag', 'psort_thread_stop_flag' and 'psort_thread_suspended'
 */
static void psort_background_thread(void *arg)
{
#ifndef _WIN32
    sx_status_t          sx_status;
    sx_api_handle_t      psort_sx_api;
    mqd_t                bg_mq;
    struct timespec      tm;
    int                  pthread_status;
    uint32_t             mq_message;
    uint32_t             last_used_table;
    bool                 timeout = false;
    const volatile bool *start = &sai_acl_db->acl_settings_tbl->psort_thread_start_flag;
    const volatile bool *stop = &sai_acl_db->acl_settings_tbl->psort_thread_stop_flag;
    const volatile bool *suspended = &sai_acl_db->acl_settings_tbl->psort_thread_suspended;
    volatile bool       *suspend_ack = &sai_acl_db->acl_settings_tbl->psort_thread_suspended_ack;

    SX_LOG_ENTER();

wait_restart:
    acl_cond_mutex_lock();
    while ((!(*start) || *suspended) && (!*stop)) {
        pthread_cond_wait(&sai_acl_db->acl_settings_tbl->psort_thread_init_cond, &acl_cond_mutex);
    }
    acl_cond_mutex_unlock();

    /* cond is triggered from resource_deinit() */
    if (*stop) {
        SX_LOG_DBG("Exiting psort_background_thread\n");
        return;
    }

    sx_status = sx_api_open(sai_log_cb, &psort_sx_api);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to open sx_api_handle_t for pSort thread - %s.\n", SX_STATUS_MSG(sx_status));
        return;
    }

    pthread_status = pthread_setspecific(pthread_sx_handle_key, &psort_sx_api);
    if (0 != pthread_status) {
        SX_LOG_ERR("Failed to set pthread_sx_handle_key value - %s\n", strerror(pthread_status));
        return;
    }

    bg_mq = mq_open(ACL_QUEUE_NAME, O_RDONLY);
    if (ACL_QUEUE_INVALID_HANDLE == bg_mq) {
        SX_LOG_ERR("Failed to open acl bg_mq - %s\n", strerror(errno));
        return;
    }

    last_used_table = ACL_INVALID_DB_INDEX;

    while (!(*stop) && !(*suspended)) {
        if (ACL_INVALID_DB_INDEX == last_used_table) {
            if (-1 == mq_receive(bg_mq, (char*)&mq_message, sizeof(mq_message), NULL)) {
                SX_LOG_ERR("Failed to read from mq in blocked mode - %s\n", strerror(errno));
                continue;
            }
        } else {
            clock_gettime(CLOCK_REALTIME, &tm);
            tm.tv_sec += ACL_QUEUE_TIMEOUT;

            if (-1 == mq_timedreceive(bg_mq, (char*)&mq_message, sizeof(mq_message), NULL, &tm)) {
                if (ETIMEDOUT == errno) {
                    timeout = true;
                } else {
                    SX_LOG_ERR("Failed to read from mq in timed mode - %s\n", strerror(errno));
                    continue;
                }
            }
        }

        if (mq_message == ACL_QUEUE_UNBLOCK_MSG) {
            continue;
        }

        if (timeout) {
            acl_psort_optimize_table(last_used_table);
            last_used_table = ACL_INVALID_DB_INDEX;
            timeout = false;
            continue;
        } else {
            if (!acl_table_index_check_range(mq_message)) {
                SX_LOG_ERR("Attempt to use invalid ACL Table DB index - %u\n", mq_message);
                continue;
            }

            if (acl_db_table(mq_message).queued == 0) {
                SX_LOG_ERR("Received a table idx %d with 'queued' = 0\n", mq_message);
                continue;
            }

            acl_db_table(mq_message).queued--;

            if (*suspended) {
                SX_LOG_DBG("Ignoring table idx %d while thread is in the suspended state\n", mq_message);
                continue;
            }

            if (ACL_INVALID_DB_INDEX == last_used_table) {
                last_used_table = mq_message;
                continue;
            }

            if (mq_message != last_used_table) {
                acl_psort_optimize_table(last_used_table);
                last_used_table = mq_message;
            }
        }
    }

    sx_status = sx_api_close(&psort_sx_api);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to close sx_api_handle_t for pSort thread - %s\n", SX_STATUS_MSG(sx_status));
    }

    if (0 != mq_close(bg_mq)) {
        SX_LOG_ERR("Failed to close bg_mq - %s\n", strerror(errno));
    }

    if (*suspended) {
        mlnx_acl_psort_queue_drain();
        if (0 != mq_unlink(ACL_QUEUE_NAME)) {
            SX_LOG_ERR("Failed to unlink message queue - %s\n", strerror(errno));
        }

        *suspend_ack = true;
        goto wait_restart;
    } else {
        if (0 != mq_unlink(ACL_QUEUE_NAME)) {
            SX_LOG_ERR("Failed to unlink message queue - %s\n", strerror(errno));
        }
    }

#endif /* ifndef _WIN32 */
    SX_LOG_EXIT();
}

static void mlnx_acl_rpc_thread(void *arg)
{
#ifndef _WIN32
    sai_status_t       status;
    acl_rpc_info_t     rpc_info;
    int                rpc_socket;
    struct sockaddr_un cl_sockaddr;
    socklen_t          sockaddr_len;
    ssize_t            bytes;
    bool               exit_request = false;

    SX_LOG_ENTER();

    acl_cond_mutex_lock();
    while (false == sai_acl_db->acl_settings_tbl->rpc_thread_start_flag) {
        pthread_cond_wait(&sai_acl_db->acl_settings_tbl->rpc_thread_init_cond, &acl_cond_mutex);
    }
    acl_cond_mutex_unlock();

    /* cond is triggered from resource_deinit() */
    if (true == sai_acl_db->acl_settings_tbl->rpc_thread_stop_flag) {
        goto out;
    }

    status = create_rpc_server(&rpc_socket);
    if (SAI_ERR(status)) {
        return;
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
        case ACL_RPC_TABLE_INIT:
            status = mlnx_acl_cb->table_init(rpc_info.args.table_id,
                                             rpc_info.args.table_is_dynamic,
                                             rpc_info.args.size);
            break;

        case ACL_RPC_TABLE_DELETE:
            status = mlnx_acl_cb->table_deinit(rpc_info.args.table_id);
            break;

        case ACL_RPC_ENTRY_OFFSET_GET:
            status = mlnx_acl_cb->entry_offset_get(
                rpc_info.args.table_id,
                rpc_info.args.entry_id,
                rpc_info.args.entry_prio,
                &rpc_info.args.entry_offset);
            break;

        case ACL_RPC_ENTRY_OFFSET_DEL:
            status = mlnx_acl_cb->entry_offset_del(rpc_info.args.table_id,
                                                   rpc_info.args.entry_prio,
                                                   rpc_info.args.entry_offset);
            break;

        case ACL_RPC_TERMINATE_THREAD:
            SX_LOG_NTC("Received exit message for rpc thread\n");
            exit_request = true;
            status = SAI_STATUS_SUCCESS;
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

    SX_LOG_EXIT();
#endif /* ifndef _WIN32 */
}

static sai_status_t mlnx_acl_sx_rule_mc_containers_get(_In_ const sx_flex_acl_flex_rule_t *rule,
                                                       _Out_ sx_mc_container_id_t         *rx_list,
                                                       _Out_ sx_mc_container_id_t         *tx_list,
                                                       _Out_ sx_mc_container_id_t         *egr_block)
{
    uint32_t ii;

    assert(rule);
    assert(rx_list);
    assert(tx_list);
    assert(egr_block);

    for (ii = 0; ii < rule->key_desc_count; ii++) {
        switch (rule->key_desc_list_p[ii].key_id) {
        case FLEX_ACL_KEY_RX_PORT_LIST:
            *rx_list = rule->key_desc_list_p[ii].key.rx_port_list.mc_container_id;
            break;

        case FLEX_ACL_KEY_TX_PORT_LIST:
            *tx_list = rule->key_desc_list_p[ii].key.tx_port_list.mc_container_id;
            break;

        default:
            continue;
        }
    }

    for (ii = 0; ii < rule->action_count; ii++) {
        switch (rule->action_list_p[ii].type) {
        case SX_FLEX_ACL_ACTION_PORT_FILTER:
            *egr_block = rule->action_list_p[ii].fields.action_port_filter.mc_container_id;
            break;

        default:
            continue;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_sx_mc_container_refs_get(_In_ sx_mc_container_id_t     sx_mc_container,
                                                            _Out_ mlnx_acl_port_db_refs_t refs)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sx_port_log_id_t *sx_ports = NULL;
    uint32_t          port_db_index, sx_ports_count = MAX_PORTS, ii;

    if (SX_MC_CONTAINER_ID_CHECK_RANGE(sx_mc_container)) {
        sx_ports = calloc(MAX_PORTS, sizeof(*sx_ports));
        if (!sx_ports) {
            SX_LOG_ERR("Failed to allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        status = mlnx_acl_sx_mc_container_sx_ports_get(sx_mc_container, sx_ports, &sx_ports_count);
        if (SAI_ERR(status)) {
            goto out;
        }

        for (ii = 0; ii < sx_ports_count; ii++) {
            status = mlnx_port_idx_by_log_id(sx_ports[ii], &port_db_index);
            if (SAI_ERR(status)) {
                goto out;
            }

            refs[port_db_index]++;
        }
    }

out:
    free(sx_ports);
    return status;
}

static sai_status_t mlnx_acl_entry_sx_rule_port_refs_get(_In_ const sx_flex_acl_flex_rule_t *rule,
                                                         _Out_ mlnx_acl_port_db_refs_t       refs)
{
    sai_status_t         status;
    sx_port_log_id_t     sx_port;
    sx_mc_container_id_t rx_list = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_id_t tx_list = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_id_t egr_block = SX_MC_CONTAINER_ID_INVALID;
    uint32_t             ii, port_db_index;

    memset(refs, 0, sizeof(mlnx_acl_port_db_refs_t));

    status = mlnx_acl_sx_rule_mc_containers_get(rule, &rx_list, &tx_list, &egr_block);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_entry_sx_mc_container_refs_get(rx_list, refs);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_entry_sx_mc_container_refs_get(tx_list, refs);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_entry_sx_mc_container_refs_get(egr_block, refs);
    if (SAI_ERR(status)) {
        return status;
    }

    for (ii = 0; ii < rule->key_desc_count; ii++) {
        sx_port = SX_INVALID_PORT;

        switch (rule->key_desc_list_p[ii].key_id) {
        case FLEX_ACL_KEY_SRC_PORT:
            sx_port = rule->key_desc_list_p[ii].key.src_port;
            break;

        case FLEX_ACL_KEY_DST_PORT:
            sx_port = rule->key_desc_list_p[ii].key.dst_port;
            break;

        default:
            continue;
        }

        if (sx_port != SX_INVALID_PORT) {
            status = mlnx_port_idx_by_log_id(sx_port, &port_db_index);
            if (SAI_ERR(status)) {
                return status;
            }

            refs[port_db_index]++;
        }
    }


    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_port_refs_apply(_In_ mlnx_acl_port_db_refs_t refs, _In_ bool clear)
{
    mlnx_port_config_t *port;
    uint32_t            ii;

    mlnx_port_foreach(port, ii) {
        if (refs[ii] == 0) {
            continue;
        }

        if (clear) {
            if (port->acl_refs == 0) {
                SX_LOG_ERR("Attempt to decrease an ACL ref while it is 0 for port idx %d (SAI OID %lx)\n",
                           ii,
                           port->saiport);
                return SAI_STATUS_FAILURE;
            }
            port->acl_refs--;
        } else {
            port->acl_refs++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_entry_port_refs_set(_In_ mlnx_acl_port_db_refs_t refs)
{
    return mlnx_acl_entry_port_refs_apply(refs, false);
}

static sai_status_t mlnx_acl_entry_port_refs_clear(_In_ mlnx_acl_port_db_refs_t refs)
{
    return mlnx_acl_entry_port_refs_apply(refs, true);
}

static sai_status_t mlnx_acl_entry_port_refs_update(_In_ mlnx_acl_port_db_refs_t old_refs,
                                                    _In_ mlnx_acl_port_db_refs_t new_refs)
{
    sai_status_t status;

    status = mlnx_acl_entry_port_refs_clear(old_refs);
    if (SAI_ERR(status)) {
        return status;
    }

    return mlnx_acl_entry_port_refs_set(new_refs);
}

static sai_status_t mlnx_acl_port_lag_event_handle(_In_ const mlnx_port_config_t *port,
                                                   _In_ acl_event_type_t          event,
                                                   _In_ bool                      is_acl_db_locked)
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

    if (false == sai_acl_db->acl_settings_tbl->lazy_initialized) {
        return SAI_STATUS_SUCCESS;
    }

    if (!is_acl_db_locked) {
        acl_global_lock();
    }

    sx_port_id = port->logical;

    switch (event) {
    case ACL_EVENT_TYPE_PORT_LAG_ADD:
    case ACL_EVENT_TYPE_LAG_MEMBER_DEL:
        sx_port_cmd = SX_ACCESS_CMD_ADD_PORTS;
        clean_bind_point = false;
        break;

    case ACL_EVENT_TYPE_PORT_LAG_DEL:
    case ACL_EVENT_TYPE_LAG_MEMBER_ADD:
        sx_port_cmd = SX_ACCESS_CMD_DELETE_PORTS;
        clean_bind_point = true;
        break;

    default:
        SX_LOG_ERR("ACL event [%d] is not supported\n", event);
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (0 != acl_db_flood_pbs().ref_counter) {
        memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));
        sx_pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
        sx_pbs_entry.port_num = 1;
        sx_pbs_entry.log_ports = &sx_port_id;

        sx_pbs_id = acl_db_flood_pbs().pbs_id;

        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, sx_port_cmd, sx_swid_id, &sx_pbs_entry, &sx_pbs_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to update ACL Flood PBS Entry %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
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
    if (!is_acl_db_locked) {
        acl_global_unlock();
    }
    return status;
}

sai_status_t mlnx_acl_port_lag_event_handle_locked(_In_ const mlnx_port_config_t *port, _In_ acl_event_type_t event)
{
    return mlnx_acl_port_lag_event_handle(port, event, true);
}

sai_status_t mlnx_acl_port_lag_event_handle_unlocked(_In_ const mlnx_port_config_t *port, _In_ acl_event_type_t event)
{
    return mlnx_acl_port_lag_event_handle(port, event, false);
}

static sai_status_t mlnx_acl_sai_ports_to_sx(_In_ const sai_object_id_t *ports,
                                             _In_ uint32_t               port_count,
                                             _Out_ sx_port_log_id_t     *sx_ports)
{
    sai_status_t        status;
    mlnx_port_config_t *port_config;
    uint32_t            ii;

    assert(ports);
    assert(sx_ports);

    if (port_count > (MAX_PORTS * 2)) {
        SX_LOG_ERR("Invalid port count %d, max allowed is %d\n", port_count, MAX_PORTS * 2);
        return SAI_STATUS_FAILURE;
    }

    for (ii = 0; ii < port_count; ii++) {
        status = mlnx_port_by_obj_id(ports[ii], &port_config);
        if (SAI_ERR(status)) {
            return status;
        }

        if (mlnx_port_is_lag_member(port_config)) {
            SX_LOG_ERR("SAI port %lx (sx %x) is a LAG member\n", port_config->saiport, port_config->logical);
            return SAI_STATUS_FAILURE;
        }

        sx_ports[ii] = port_config->logical;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_ports_entry_trivial_check(_In_ const sai_object_id_t *ports,
                                                           _In_ uint32_t               ports_count,
                                                           _Out_ mlnx_acl_pbs_info_t  *pbs_info,
                                                           _Out_ bool                 *is_trivial)
{
    sai_status_t status;
    uint32_t     port_db_index;

    assert(ports);
    assert(pbs_info);
    assert(is_trivial);

    if (ports_count != 1) {
        *is_trivial = false;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_port_idx_by_obj_id(ports[0], &port_db_index);
    if (SAI_ERR(status)) {
        return status;
    }

    pbs_info->type = MLNX_ACL_PBS_TYPE_MAP;
    pbs_info->idx = acl_pbs_port_idx_to_pbs_map_idx(port_db_index);

    *is_trivial = true;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_ports_to_map_key(_In_ const sai_object_id_t *ports,
                                                  _In_ uint32_t               ports_count,
                                                  _Out_ acl_pbs_map_key_t    *map_key)
{
    sai_status_t status;
    uint32_t     ii, port_db_index;

    assert(ports);
    assert(map_key);

    memset(map_key, 0, sizeof(*map_key));

    for (ii = 0; ii < ports_count; ii++) {
        status = mlnx_port_idx_by_obj_id(ports[ii], &port_db_index);
        if (SAI_ERR(status)) {
            return status;
        }

        array_bit_set(map_key->data, port_db_index);
    }

    return SAI_STATUS_SUCCESS;
}

static mlnx_acl_pbs_map_idx_t mlnx_acl_pbs_map_key_to_index(_In_ const acl_pbs_map_key_t *key, _In_ uint32_t step)
{
    uint32_t k = 0, ii;

    assert(key);

    for (ii = 0; ii < ARRAY_SIZE(key->data); ii++) {
        k ^= key->data[ii];
    }

    return (k + step * k) % g_sai_acl_db_pbs_map_size;
}

static bool mlnx_acl_pbs_map_key_is_equal(_In_ const acl_pbs_map_key_t *key1, _In_ const acl_pbs_map_key_t *key2)
{
    const uint32_t *key1_data, *key2_data;
    uint32_t        ii;

    assert(key1);
    assert(key2);

    key1_data = key1->data;
    key2_data = key2->data;

    for (ii = 0; ii < ARRAY_SIZE(key1->data); ii++) {
        if (key1_data[ii] != key2_data[ii]) {
            return false;
        }
    }

    return true;
}

static bool mlnx_acl_pbs_map_is_idx_deleted(_In_ mlnx_acl_pbs_map_idx_t map_idx)
{
    const acl_pbs_map_key_t *key;
    uint32_t                 ii;

    key = &acl_db_pbs_map(map_idx).key;

    for (ii = 0; ii < ARRAY_SIZE(key->data); ii++) {
        if (key->data[ii] != 0) {
            return true;
        }
    }

    return false;
}

static sai_status_t mlnx_acl_pbs_key_to_pbs_info(_In_ const acl_pbs_map_key_t *key,
                                                 _Out_ mlnx_acl_pbs_info_t    *pbs_info)
{
    mlnx_acl_pbs_map_idx_t map_index = ACL_PBS_MAP_INVALID_INDEX, first_deleted_index = ACL_PBS_MAP_INVALID_INDEX;
    uint32_t               ii;

    assert(key);
    assert(pbs_info);

    for (ii = ACL_PBS_MAP_HASH_INDEX_START; ii < g_sai_acl_db_pbs_map_size; ii++) {
        map_index = mlnx_acl_pbs_map_key_to_index(key, ii);

        if (mlnx_acl_pbs_map_key_is_equal(key, &acl_db_pbs_map(map_index).key)) {
            break;
        }

        if (0 == acl_db_pbs_map(map_index).entry.ref_counter) {
            if (mlnx_acl_pbs_map_is_idx_deleted(map_index)) {
                if (!ACL_PBS_MAP_INDEX_IS_VALID(first_deleted_index)) {
                    first_deleted_index = map_index;
                }

                continue;
            }

            /* End of probe sequence */
            break;
        }
    }

    if (ACL_PBS_MAP_INDEX_IS_VALID(first_deleted_index)) {
        map_index = first_deleted_index;
    }

    if ((g_sai_acl_db_pbs_map_size == ii) && !ACL_PBS_MAP_INDEX_IS_VALID(map_index)) {
        SX_LOG_ERR("ACL PBS Map is full");
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    acl_db_pbs_map(map_index).key = *key;

    pbs_info->type = MLNX_ACL_PBS_TYPE_MAP;
    pbs_info->idx = map_index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_ports_info_get(_In_ const sai_object_id_t *ports,
                                                _In_ uint32_t               ports_count,
                                                _Out_ mlnx_acl_pbs_info_t  *pbs_info)
{
    sai_status_t      status;
    acl_pbs_map_key_t map_key;
    bool              is_trivial;

    assert(ports);
    assert(pbs_info);

    status = mlnx_acl_pbs_ports_entry_trivial_check(ports, ports_count, pbs_info, &is_trivial);
    if (SAI_ERR(status)) {
        return status;
    }

    if (is_trivial) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_acl_pbs_ports_to_map_key(ports, ports_count, &map_key);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to generate PBS map key\n");
        return status;
    }

    return mlnx_acl_pbs_key_to_pbs_info(&map_key, pbs_info);
}

static sai_status_t mlnx_acl_bport_pbs_info_get(_In_ const mlnx_bridge_port_t *bport,
                                                _Out_ mlnx_acl_pbs_info_t     *pbs_info)
{
    assert(bport);
    assert(pbs_info);

    memset(pbs_info, 0, sizeof(*pbs_info));

    pbs_info->type = MLNX_ACL_PBS_TYPE_BPORT;
    pbs_info->idx = bport->index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_info_to_pbs_entry(_In_ mlnx_acl_pbs_info_t     pbs_info,
                                                   _Out_ mlnx_acl_pbs_entry_t **pbs_entry)
{
    sai_status_t        status;
    mlnx_bridge_port_t *bport;
    mlnx_l2mc_group_t  *l2mc_group;
    uint32_t            idx;

    assert(pbs_entry);

    if (pbs_info.type == MLNX_ACL_PBS_TYPE_INVALID) {
        SX_LOG_ERR("Invalid pbs info\n");
        return SAI_STATUS_FAILURE;
    }

    idx = pbs_info.idx;

    switch (pbs_info.type) {
    case MLNX_ACL_PBS_TYPE_MAP:
        *pbs_entry = &acl_db_pbs_map(idx).entry;
        break;

    case MLNX_ACL_PBS_TYPE_BPORT:
        status = mlnx_bridge_port_by_idx(idx, &bport);
        if (SAI_ERR(status)) {
            return status;
        }

        *pbs_entry = &bport->pbs_entry;
        break;

    case MLNX_ACL_PBS_TYPE_MCGROUP:
        status = mlnx_l2mc_group_pbs_info_to_group(pbs_info, &l2mc_group);
        if (SAI_ERR(status)) {
            return status;
        }

        *pbs_entry = &l2mc_group->pbs_entry;
        break;

    default:
        SX_LOG_ERR("Invalid pbs_info->type - %d\n", pbs_info.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_entry_port_init_or_use(_In_ mlnx_acl_pbs_entry_t *pbs_entry,
                                                        _In_ sx_port_log_id_t     *sx_ports,
                                                        _In_ uint32_t              ports_count,
                                                        _Out_ sx_acl_pbs_id_t     *sx_pbs_id)
{
    sx_status_t        sx_status;
    sx_acl_pbs_entry_t sx_pbs_entry;

    assert(pbs_entry);
    assert(sx_ports);
    assert(sx_pbs_id);

    if (0 != pbs_entry->ref_counter) {
        pbs_entry->ref_counter++;
        *sx_pbs_id = pbs_entry->pbs_id;
        return SAI_STATUS_SUCCESS;
    }

    memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));
    sx_pbs_entry.entry_type =
        (ports_count == 1) ? SX_ACL_PBS_ENTRY_TYPE_UNICAST : SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
    sx_pbs_entry.port_num = ports_count;
    sx_pbs_entry.log_ports = sx_ports;

    sx_status =
        sx_api_acl_policy_based_switching_set(gh_sdk,
                                              SX_ACCESS_CMD_ADD,
                                              DEFAULT_ETH_SWID,
                                              &sx_pbs_entry,
                                              sx_pbs_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create PBS %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    pbs_entry->pbs_id = *sx_pbs_id;
    pbs_entry->ref_counter = 1;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_bport_create_or_get(_In_ mlnx_bridge_port_t   *bport,
                                                     _Out_ sx_acl_pbs_id_t     *pbs_id,
                                                     _Out_ mlnx_acl_pbs_info_t *pbs_info)
{
    sai_status_t          status;
    mlnx_acl_pbs_info_t   pbs_info_tmp;
    mlnx_acl_pbs_entry_t *pbs_entry;

    status = mlnx_acl_bport_pbs_info_get(bport, &pbs_info_tmp);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_pbs_info_to_pbs_entry(pbs_info_tmp, &pbs_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_pbs_entry_port_init_or_use(pbs_entry, &bport->logical, 1, pbs_id);
    if (SAI_ERR(status)) {
        return status;
    }

    *pbs_info = pbs_info_tmp;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_ports_create_or_get(_In_ const sai_object_id_t *ports,
                                                     _In_ uint32_t               ports_count,
                                                     _Out_ sx_acl_pbs_id_t      *sx_pbs_id,
                                                     _Out_ mlnx_acl_pbs_info_t  *pbs_info)
{
    sai_status_t          status = SAI_STATUS_SUCCESS;
    mlnx_acl_pbs_info_t   pbs_info_tmp;
    mlnx_acl_pbs_entry_t *pbs_entry;
    sx_port_log_id_t     *sx_ports = NULL;

    assert(ports);
    assert(sx_pbs_id);
    assert(pbs_info);
    assert(!MLNX_ACL_PBS_INFO_IS_VALID(*pbs_info));

    status = mlnx_acl_pbs_ports_info_get(ports, ports_count, &pbs_info_tmp);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_acl_pbs_info_to_pbs_entry(pbs_info_tmp, &pbs_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_ports = calloc(ports_count, sizeof(*sx_ports));
    if (!sx_ports) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    status = mlnx_acl_sai_ports_to_sx(ports, ports_count, sx_ports);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_pbs_entry_port_init_or_use(pbs_entry, sx_ports, ports_count, sx_pbs_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    *pbs_info = pbs_info_tmp;

out:
    free(sx_ports);
    return status;
}

static sai_status_t mlnx_acl_flood_pbs_create_or_get(_Out_ sx_acl_pbs_id_t     *sx_pbs_id,
                                                     _Out_ mlnx_acl_pbs_info_t *pbs_info)
{
    sai_status_t          status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t   *port_config;
    sx_status_t           sx_status;
    sx_port_log_id_t     *sx_port_ids = NULL;
    sx_acl_pbs_entry_t    sx_pbs_entry;
    sx_swid_t             swid_id = DEFAULT_ETH_SWID;
    mlnx_acl_pbs_entry_t *flood_pbs_entry;
    uint32_t              port_count, ii;

    assert(sx_pbs_id);
    assert(pbs_info);

    flood_pbs_entry = &acl_db_flood_pbs();

    if (flood_pbs_entry->ref_counter > 0) {
        flood_pbs_entry->ref_counter++;
    } else {
        sx_port_ids = calloc(MAX_PORTS * 2, sizeof(*sx_port_ids));
        if (!sx_port_ids) {
            SX_LOG_ERR("Failed to allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        port_count = 0;
        mlnx_port_not_in_lag_foreach(port_config, ii) {
            sx_port_ids[port_count++] = port_config->logical;
        }

        memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));
        sx_pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
        sx_pbs_entry.port_num = port_count;
        sx_pbs_entry.log_ports = sx_port_ids;

        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_ADD, swid_id,
                                                          &sx_pbs_entry, sx_pbs_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create Flood PBS %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        flood_pbs_entry->pbs_id = *sx_pbs_id;
        flood_pbs_entry->ref_counter = 1;
    }

    *sx_pbs_id = flood_pbs_entry->pbs_id;
    pbs_info->type = MLNX_ACL_PBS_TYPE_MAP;
    pbs_info->idx = ACL_PBS_MAP_FLOOD_PBS_INDEX;

out:
    free(sx_port_ids);
    return status;
}

static sai_status_t mlnx_acl_pbs_info_delete(_In_ mlnx_acl_pbs_info_t pbs_info)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    mlnx_acl_pbs_entry_t *pbs_entry;
    const sx_swid_t       swid = DEFAULT_ETH_SWID;

    if (!MLNX_ACL_PBS_INFO_IS_VALID(pbs_info)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_acl_pbs_info_to_pbs_entry(pbs_info, &pbs_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    if (pbs_entry->ref_counter == 0) {
        SX_LOG_ERR("Attempt to delete PBS entry %d while it's ref_counter is 0\n", pbs_info.idx);
        return SAI_STATUS_FAILURE;
    }

    pbs_entry->ref_counter--;

    if (pbs_entry->ref_counter == 0) {
        sx_status =
            sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_DELETE, swid, NULL, &pbs_entry->pbs_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to delete PBS Entry %d (index %d) -  %s.\n",
                       pbs_entry->pbs_id, pbs_info.idx, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_info_port_refs_get(_In_ mlnx_acl_pbs_info_t      pbs_info,
                                                    _Out_ mlnx_acl_port_db_refs_t refs)
{
    mlnx_port_config_t *port;
    uint32_t            pbs_map_idx;
    acl_pbs_map_key_t   pbs_key;
    uint32_t            ii;

    memset(refs, 0, sizeof(mlnx_acl_port_db_refs_t));

    if (pbs_info.type != MLNX_ACL_PBS_TYPE_MAP) {
        return SAI_STATUS_SUCCESS;
    }

    pbs_map_idx = pbs_info.idx;

    if (!ACL_PBS_MAP_INDEX_IS_VALID(pbs_map_idx) || (ACL_PBS_MAP_FLOOD_PBS_INDEX == pbs_map_idx)) {
        return SAI_STATUS_SUCCESS;
    }

    if (ACL_PBS_MAP_INDEX_IS_TRIVIAL(pbs_map_idx)) {
        refs[acl_pbs_map_idx_to_port_idx(pbs_map_idx)] = 1;
        return SAI_STATUS_SUCCESS;
    }

    pbs_key = acl_db_pbs_map(pbs_map_idx).key;

    mlnx_port_foreach(port, ii) {
        if (array_bit_test(pbs_key.data, ii)) {
            refs[ii] = 1;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_map_sai_ports_get(_In_ mlnx_acl_pbs_map_idx_t pbs_map_idx,
                                                   _Out_ sai_object_id_t      *ports,
                                                   _Out_ uint32_t             *ports_count)
{
    mlnx_port_config_t *port;
    acl_pbs_map_key_t   pbs_key;
    uint32_t            ii, port_idx;

    assert(ports);
    assert(ports_count);

    if (!ACL_PBS_MAP_INDEX_IS_VALID(pbs_map_idx)) {
        SX_LOG_ERR("Invalid PBS index\n");
        return SAI_STATUS_FAILURE;
    }

    if (ACL_PBS_MAP_FLOOD_PBS_INDEX == pbs_map_idx) {
        SX_LOG_ERR("Attempt to get flood PBS ports\n");
        return SAI_STATUS_FAILURE;
    }

    if (ACL_PBS_MAP_INDEX_IS_TRIVIAL(pbs_map_idx)) {
        if (*ports_count < 1) {
            SX_LOG_ERR("Failed to get sai ports for pbs index %d - array is to small\n", pbs_map_idx);
            return SAI_STATUS_BUFFER_OVERFLOW;
        }

        port = mlnx_port_by_idx((uint8_t)acl_pbs_map_idx_to_port_idx(pbs_map_idx));

        ports[0] = port->saiport;
        *ports_count = 1;
        return SAI_STATUS_SUCCESS;
    }

    pbs_key = acl_db_pbs_map(pbs_map_idx).key;

    port_idx = 0;
    mlnx_port_foreach(port, ii) {
        if (array_bit_test(pbs_key.data, ii)) {
            if (*ports_count <= port_idx) {
                SX_LOG_ERR("Failed to get sai ports for pbs index %d - array is to small\n", pbs_map_idx);
                return SAI_STATUS_BUFFER_OVERFLOW;
            }

            ports[port_idx] = port->saiport;
            port_idx++;
        }
    }

    *ports_count = port_idx;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_info_to_sai_oid(_In_ mlnx_acl_pbs_info_t pbs_info, _Out_ sai_object_id_t     *oid)
{
    sai_status_t           status;
    mlnx_acl_pbs_map_idx_t map_idx;
    mlnx_bridge_port_t    *bport;
    mlnx_l2mc_group_t     *l2mc_group;
    mlnx_port_config_t    *port;
    uint32_t               port_db_idx;

    assert(oid);

    if (!MLNX_ACL_PBS_INFO_IS_VALID(pbs_info)) {
        SX_LOG_ERR("Invalid PBS index\n");
        return SAI_STATUS_FAILURE;
    }

    switch (pbs_info.type) {
    case MLNX_ACL_PBS_TYPE_MAP:
        map_idx = pbs_info.idx;
        if (!ACL_PBS_MAP_INDEX_IS_VALID(map_idx)) {
            SX_LOG_ERR("Invalid PBS map index\n");
            return SAI_STATUS_FAILURE;
        }

        if (!ACL_PBS_MAP_INDEX_IS_TRIVIAL(map_idx)) {
            SX_LOG_ERR("PBS map index %d represents a list of ports.\n", map_idx);
            return SAI_STATUS_FAILURE;
        }

        port_db_idx = acl_pbs_map_idx_to_port_idx(map_idx);
        port = mlnx_port_by_idx(port_db_idx);
        *oid = port->saiport;
        break;

    case MLNX_ACL_PBS_TYPE_BPORT:
        status = mlnx_bridge_port_by_idx(pbs_info.idx, &bport);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_bridge_port_to_oid(bport, oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case MLNX_ACL_PBS_TYPE_MCGROUP:
        status = mlnx_l2mc_group_pbs_info_to_group(pbs_info, &l2mc_group);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_l2mc_group_oid_create(l2mc_group, oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Invalid PBS type - %d\n", pbs_info.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_pbs_info_sai_ports_get(_In_ mlnx_acl_pbs_info_t pbs_info,
                                                    _Out_ sai_object_id_t   *ports,
                                                    _Out_ uint32_t          *ports_count)
{
    assert(ports);
    assert(ports_count);

    if (!MLNX_ACL_PBS_INFO_IS_VALID(pbs_info)) {
        SX_LOG_ERR("Invalid PBS index\n");
        return SAI_STATUS_FAILURE;
    }

    if (pbs_info.type != MLNX_ACL_PBS_TYPE_MAP) {
        SX_LOG_ERR("PBS idx %d doesn't represent a list of ports (can be bridge port or l2mc group)\n", pbs_info.idx);
        return SAI_STATUS_FAILURE;
    }

    return mlnx_acl_pbs_map_sai_ports_get(pbs_info.idx, ports, ports_count);
}

static sai_status_t mlnx_acl_range_attr_get_spc(_In_ sx_acl_port_range_id_t  sx_range_id,
                                                _In_ sai_attr_id_t           attr_id,
                                                _Out_ sai_attribute_value_t *value)
{
    sx_status_t               sx_status;
    sx_acl_port_range_entry_t sx_port_range_entry;

    assert((SAI_ACL_RANGE_ATTR_TYPE == attr_id) ||
           (SAI_ACL_RANGE_ATTR_LIMIT == attr_id));

    memset(&sx_port_range_entry, 0, sizeof(sx_port_range_entry));

    sx_status = sx_api_acl_l4_port_range_get(gh_sdk, sx_range_id, &sx_port_range_entry);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get range attributes - %s", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
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
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_ACL_RANGE_ATTR_LIMIT:
        value->u32range.min = sx_port_range_entry.port_range_min;
        value->u32range.max = sx_port_range_entry.port_range_max;
        break;

    default:
        SX_LOG_ERR(" Invalid attribute to get - %d\n", attr_id);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_attr_get_spc2(_In_ sx_acl_port_range_id_t  sx_range_id,
                                                 _In_ sai_attr_id_t           attr_id,
                                                 _Out_ sai_attribute_value_t *value)
{
    sx_status_t          sx_status;
    sx_acl_range_entry_t sx_acl_range_entry;

    assert((SAI_ACL_RANGE_ATTR_TYPE == attr_id) ||
           (SAI_ACL_RANGE_ATTR_LIMIT == attr_id));

    memset(&sx_acl_range_entry, 0, sizeof(sx_acl_range_entry));

    sx_status = sx_api_acl_range_get(gh_sdk, sx_range_id, &sx_acl_range_entry);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get range attributes - %s", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    switch (attr_id) {
    case SAI_ACL_RANGE_ATTR_TYPE:
        switch (sx_acl_range_entry.range_type) {
        case SX_ACL_RANGE_TYPE_L4_PORT_E:
            if (sx_acl_range_entry.direction == SX_ACL_PORT_DIRECTION_SOURCE) {
                value->s32 = SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE;
            } else if (sx_acl_range_entry.direction == SX_ACL_PORT_DIRECTION_DESTINATION) {
                value->s32 = SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE;
            } else {
                SX_LOG_ERR("Unexpected sx range direction %d\n", sx_acl_range_entry.direction);
                return SAI_STATUS_FAILURE;
            }
            break;

        case SX_ACL_RANGE_TYPE_IP_LENGTH_E:
            value->s32 = SAI_ACL_RANGE_TYPE_PACKET_LENGTH;
            break;

        default:
            SX_LOG_ERR("Unexpected sx range type - %d\n", sx_acl_range_entry.range_type);
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_ACL_RANGE_ATTR_LIMIT:
        value->u32range.min = sx_acl_range_entry.range_limits.min;
        value->u32range.max = sx_acl_range_entry.range_limits.max;
        break;

    default:
        SX_LOG_ERR(" Invalid attribute to get - %d\n", attr_id);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_attr_get_by_oid(_In_ sai_object_id_t           acl_range_oid,
                                                   _In_ sai_attr_id_t             attr_id,
                                                   _Inout_ sai_attribute_value_t *value)
{
    sai_status_t           status;
    sx_acl_port_range_id_t sx_port_range_id;
    uint32_t               object_range_id;

    assert((SAI_ACL_RANGE_ATTR_TYPE == attr_id) ||
           (SAI_ACL_RANGE_ATTR_LIMIT == attr_id));
    assert(value);
    assert(mlnx_acl_cb);

    status = mlnx_object_to_type(acl_range_oid, SAI_OBJECT_TYPE_ACL_RANGE, &object_range_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_port_range_id = object_range_id;

    return mlnx_acl_cb->range_attr_get(sx_port_range_id, attr_id, value);
}

static sai_status_t mlnx_acl_field_port_to_sx(_In_ sai_object_id_t sai_port, _Out_ sx_port_log_id_t *sx_port)
{
    sai_status_t        status;
    mlnx_port_config_t *port;

    assert(sx_port);

    status = mlnx_port_by_obj_id(sai_port, &port);
    if (SAI_ERR(status)) {
        return status;
    }

    *sx_port = port->logical;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_action_redirect_bport_create(_In_ sai_object_id_t             object_id,
                                                          _In_ uint32_t                    attr_index,
                                                          _Out_ mlnx_acl_pbs_info_t       *pbs_info,
                                                          _Out_ sx_flex_acl_flex_action_t *sx_action)
{
    sai_status_t        status;
    mlnx_bridge_port_t *bport;
    mlnx_bridge_rif_t  *brif;
    sx_acl_pbs_id_t     sx_pbs_id;

    status = mlnx_bridge_port_by_oid(object_id, &bport);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    switch (bport->port_type) {
    case SAI_BRIDGE_PORT_TYPE_PORT:
    case SAI_BRIDGE_PORT_TYPE_SUB_PORT:
        status = mlnx_acl_pbs_bport_create_or_get(bport, &sx_pbs_id, pbs_info);
        if (SAI_ERR(status)) {
            return status;
        }

        sx_action->type = SX_FLEX_ACL_ACTION_PBS;
        sx_action->fields.action_pbs.pbs_id = sx_pbs_id;
        break;


    case SAI_BRIDGE_PORT_TYPE_1D_ROUTER:
    case SAI_BRIDGE_PORT_TYPE_1Q_ROUTER:
        status = mlnx_bridge_rif_by_idx(bport->rif_index, &brif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup bridge rif by index %u\n", bport->rif_index);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }

        sx_action->type = SX_FLEX_ACL_ACTION_SET_ROUTER;
        sx_action->fields.action_set_router.vrid = brif->sx_data.vrf_id;
        break;

    case SAI_BRIDGE_PORT_TYPE_TUNNEL:
        sx_action->type = SX_FLEX_ACL_ACTION_NVE_TUNNEL_ENCAP;
        sx_action->fields.action_nve_tunnel_encap.tunnel_id =
            g_sai_tunnel_db_ptr->tunnel_entry_db[bport->tunnel_idx].sx_tunnel_id_ipv4;
        break;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_redirect_action_l2mc_create(_In_ sai_object_id_t             object_id,
                                                         _In_ uint32_t                    attr_index,
                                                         _Out_ mlnx_acl_pbs_info_t       *pbs_info,
                                                         _Out_ sx_flex_acl_flex_action_t *sx_action)
{
    sai_status_t       status;
    mlnx_l2mc_group_t *l2mc_group;

    assert(pbs_info);
    assert(sx_action);

    status = mlnx_l2mc_group_oid_to_sai(object_id, &l2mc_group);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_l2mc_group_pbs_use(l2mc_group);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_l2mc_group_to_pbs_info(l2mc_group, pbs_info);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_action->type = SX_FLEX_ACL_ACTION_PBS;
    sx_action->fields.action_pbs.pbs_id = l2mc_group->pbs_entry.pbs_id;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_acl_redirect_action_create(_In_ sai_object_id_t             object_id,
                                                        _In_ uint32_t                    attr_index,
                                                        _Out_ mlnx_acl_pbs_info_t       *pbs_info,
                                                        _Out_ sx_flex_acl_flex_action_t *sx_action)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sai_object_type_t object_type;
    sx_ecmp_id_t      sx_ecmp_id;
    sx_acl_pbs_id_t   sx_pbs_id;

    assert(pbs_info);
    assert(sx_action);
    assert(!MLNX_ACL_PBS_INFO_IS_VALID(*pbs_info));

    object_type = sai_object_type_query(object_id);

    switch (object_type) {
    case SAI_OBJECT_TYPE_PORT:
    case SAI_OBJECT_TYPE_LAG:
        status = mlnx_acl_pbs_ports_create_or_get(&object_id, 1, &sx_pbs_id, pbs_info);
        if (SAI_ERR(status)) {
            return status;
        }

        sx_action->type = SX_FLEX_ACL_ACTION_PBS;
        sx_action->fields.action_pbs.pbs_id = sx_pbs_id;
        break;

    case SAI_OBJECT_TYPE_NEXT_HOP:
    case SAI_OBJECT_TYPE_NEXT_HOP_GROUP:
        status = mlnx_object_to_type(object_id, object_type, &sx_ecmp_id, NULL);
        if (SAI_ERR(status)) {
            return status;
        }

        sx_action->type = SX_FLEX_ACL_ACTION_UC_ROUTE;
        sx_action->fields.action_uc_route.uc_route_type = SX_UC_ROUTE_TYPE_NEXT_HOP;
        sx_action->fields.action_uc_route.uc_route_param.ecmp_id = sx_ecmp_id;
        break;

    case SAI_OBJECT_TYPE_BRIDGE_PORT:
        return mlnx_acl_action_redirect_bport_create(object_id, attr_index, pbs_info, sx_action);

    case SAI_OBJECT_TYPE_L2MC_GROUP:
        return mlnx_acl_redirect_action_l2mc_create(object_id, attr_index, pbs_info, sx_action);

    default:
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
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
    indexes = group_bound_to->indexes;

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

    list->count = 0;
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
    sai_status_t      status;
    sai_object_type_t object_type;
    uint32_t          object_data;

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

        if ((acl_db_table(object_data).group_references > 0) &&
            (acl_db_table(object_data).group_type == SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL)) {
            SX_LOG_ERR("The table [%lx] is a member of sequential group\n", oid);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }
    }

    acl_index->acl_db_index = object_data;
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
    bind_point_types = mlnx_acl_table_or_group_bind_point_list_fetch(*acl_index);
    bind_point_stage = mlnx_acl_bind_point_type_to_sai_stage(bind_point_type);
    acl_stage = mlnx_acl_index_stage_get(*acl_index);

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

    if (false == sai_acl_db->acl_settings_tbl->lazy_initialized) {
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

    if (false == sai_acl_db->acl_settings_tbl->lazy_initialized) {
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
    ingress_data = &bind_point_port_lag->ingress_data;
    egress_data = &bind_point_port_lag->egress_data;

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
    index_count = group_bound_to->count;

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
    sx_group = bind_point_data->sx_group;

    status = mlnx_acl_bind_point_sx_bind_set(SX_ACCESS_CMD_DELETE, bind_point_data);
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
    bool                      need_to_bind = false;

    acl_group = sai_acl_db_group_ptr(group_index);
    sx_direction = bind_point_data->target_data.sx_direction;

    if (0 == acl_group->members_count) {
        status = mlnx_acl_bind_point_sx_group_remove(bind_point_data);
        if (SAI_ERR(status)) {
            return status;
        }

        /* if SAI Group is empty, and sx resources are not used - nothing to do*/
        return SAI_STATUS_SUCCESS;
    }

    if (false == bind_point_data->is_sx_group_created) {
        sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_direction, NULL, 0,
                                         &bind_point_data->sx_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create sx group\n");
            status = sdk_to_sai(sx_status);
            goto out;
        }

        bind_point_data->is_sx_group_created = true;
        need_to_bind = true;
    }

    if (SAI_ACL_TABLE_GROUP_TYPE_PARALLEL == acl_group->search_type) {
        group_members = acl_group->members;
        sx_acl_count = acl_group->members_count;

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
        sx_head_acl = acl_db_table(head_table_index).table_id;

        sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_direction,
                                         &sx_head_acl, 1, &bind_point_data->sx_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to update sx group (%x) - %s\n", bind_point_data->sx_group,
                       SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (need_to_bind) {
        status = mlnx_acl_bind_point_sx_bind_set(SX_ACCESS_CMD_ADD, bind_point_data);
        if (SAI_ERR(status)) {
            goto out;
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

    sx_acl_id = acl_db_table(table_index).table_id;
    sx_direction = bind_point_data->target_data.sx_direction;

    if (false == bind_point_data->is_sx_group_created) {
        sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_direction, NULL, 0,
                                         &bind_point_data->sx_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create sx group\n");
            return sdk_to_sai(sx_status);
        }

        bind_point_data->is_sx_group_created = true;

        sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_direction,
                                         &sx_acl_id, 1, &bind_point_data->sx_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to update sx group (%x)\n", bind_point_data->sx_group);
            return sdk_to_sai(sx_status);
        }

        status = mlnx_acl_bind_point_sx_bind_set(SX_ACCESS_CMD_ADD, bind_point_data);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_direction,
                                         &sx_acl_id, 1, &bind_point_data->sx_group);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to update sx group (%x)\n", bind_point_data->sx_group);
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
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

    index->type = mlnx_acl_bind_point_type_to_sai(bind_point_type);
    index->index = port_index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_rif_index_get(_In_ sai_object_id_t oid, _In_ acl_bind_point_index_t *index)
{
    sai_status_t          status;
    sx_router_interface_t rif_id;

    assert(index != NULL);

    status = mlnx_rif_oid_to_sdk_rif_id(oid, &rif_id);
    if (SAI_ERR(status)) {
        return status;
    }

    index->type = SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF;
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
        bind_point_data->target_data.sx_direction = mlnx_acl_bind_point_type_to_sx_direction(bind_point_type);
        bind_point_data->target_data.sx_port = g_sai_db_ptr->ports_db[index].logical;
        bind_point_data->target_data.is_set = true;
    }

    *data = bind_point_data;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_bind_point_rif_data_get(_In_ sai_object_id_t            oid,
                                                     _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                     _Out_ acl_bind_point_data_t   **data)
{
    sai_status_t           status;
    sx_router_interface_t  rif_id;
    acl_bind_point_data_t *bind_point_data;

    assert(data != NULL);

    status = mlnx_rif_oid_to_sdk_rif_id(oid, &rif_id);
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
        bind_point_data->target_data.sx_direction = mlnx_acl_bind_point_type_to_sx_direction(bind_point_type);
        bind_point_data->target_data.rif = rif_id;
        bind_point_data->target_data.is_set = true;
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
        sx_lag_id = mlnx_port_get_lag_id(&(mlnx_ports_db[port_index]));

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

    sx_port_id = bind_point_data->target_data.sx_port;
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

    sx_rif_id = bind_point_data->target_data.rif;
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
    sx_group_id = bind_point_data->sx_group;

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

    assert((SX_ACCESS_CMD_ADD == sx_cmd) || (SX_ACCESS_CMD_DELETE == sx_cmd));

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

    sx_lag_id = mlnx_port_get_lag_id(&(mlnx_ports_db[lag_member_index]));

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
        SX_LOG_ERR("Error getting ACL bind point data from target %" PRIx64 "\n", target);
        goto out;
    }

    status = mlnx_acl_bind_point_port_lag_rif_index_get(target, bind_point_type, &bind_point_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error getting ACL bind point index from target %" PRIx64 "\n", target);
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
            SX_LOG_ERR("Error setting ACL binding\n");
            goto out;
        }
    } else {
        status = mlnx_acl_bind_point_sx_update(bind_point_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Error updating ACL binding\n");
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

    found = false;
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

        acl_db_vlan_group(index).bind_data.target_data.is_set = true;
        acl_db_vlan_group(index).bind_data.target_data.vlan_group = acl_db_vlan_group(index).sx_vlan_group;
        acl_db_vlan_group(index).bind_data.target_data.sx_direction = sx_acl_direction;
        acl_db_vlan_group(index).bind_data.target_data.sai_bind_point_type = SAI_ACL_BIND_POINT_TYPE_VLAN;

        bind_point_index.index = index;
        bind_point_index.type = SAI_ACL_BIND_POINT_TYPE_VLAN;

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

    vlan_group = acl_db_vlan_group(vlan_group_index).sx_vlan_group;
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
        bind_point_index.type = SAI_ACL_BIND_POINT_TYPE_VLAN;
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

    sx_vlan_id = vlan_id;
    bind_point = &sai_acl_db->acl_bind_points->vlans[vlan_id];
    sx_acl_direction = mlnx_acl_bind_point_type_to_sx_direction(bind_point_type);
    unbind = is_acl_index_invalid(acl_index);

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
            bind_point->is_bound = true;
        } else {
            vlan_group_index = bind_point->vlan_group_index;
            if (mlnx_acl_indexes_is_equal(acl_db_vlan_group(vlan_group_index).bind_data.acl_index, acl_index)) {
                status = SAI_STATUS_SUCCESS;
                goto out;
            }

            if (1 == acl_db_vlan_group(vlan_group_index).vlan_count) {
                bind_point_index.index = vlan_group_index;
                bind_point_index.type = SAI_ACL_BIND_POINT_TYPE_VLAN;

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
    bool                       is_warmboot_init_stage = false;
    uint32_t                   port_db_idx;

    SX_LOG_ENTER();

    bind_point_type = (mlnx_acl_bind_point_type_t)arg;

    sai_db_read_lock();
    acl_global_lock();

    status = mlnx_acl_bind_point_attrs_check_and_fetch(value->oid, bind_point_type, 0, &acl_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* Store Ingress ACL and Egress ACL to SAI port DB if LAG is not yet created by SAI API
     * during ISSU initialization stage */
    is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                             (!g_sai_db_ptr->issu_end_called);
    if (is_warmboot_init_stage) {
        if ((MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG == bind_point_type) ||
            (MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG == bind_point_type)) {
            status = mlnx_port_idx_by_obj_id(key->key.object_id, &port_db_idx);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Error getting port idx from log id %" PRIx64 "\n", key->key.object_id);
                goto out;
            }
            if (0 == mlnx_ports_db[port_db_idx].logical) {
                if (MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG == bind_point_type) {
                    mlnx_ports_db[port_db_idx].issu_lag_attr.lag_ingress_acl_oid = value->oid;
                    mlnx_ports_db[port_db_idx].issu_lag_attr.lag_ingress_acl_oid_changed = true;
                } else if (MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG == bind_point_type) {
                    mlnx_ports_db[port_db_idx].issu_lag_attr.lag_egress_acl_oid = value->oid;
                    mlnx_ports_db[port_db_idx].issu_lag_attr.lag_egress_acl_oid_changed = true;
                }
                status = SAI_STATUS_SUCCESS;
                goto out;
            }
        }
    }

    status = mlnx_acl_bind_point_set_impl(key->key.object_id, bind_point_type, acl_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set ACL bind point on SAI obj %" PRIx64 "\n", key->key.object_id);
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
    bool                       is_warmboot_init_stage = false;
    uint32_t                   port_db_idx;

    SX_LOG_ENTER();

    sai_db_read_lock();
    acl_global_lock();

    bind_point_type = (mlnx_acl_bind_point_type_t)arg;
    target = key->key.object_id;

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
        is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                 (!g_sai_db_ptr->issu_end_called);
        if (is_warmboot_init_stage) {
            status = mlnx_port_idx_by_obj_id(key->key.object_id, &port_db_idx);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Error getting port idx from log id %" PRIx64 "\n", key->key.object_id);
                goto out;
            }
            if (0 == mlnx_ports_db[port_db_idx].logical) {
                if (MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG == bind_point_type) {
                    value->oid = mlnx_ports_db[port_db_idx].issu_lag_attr.lag_ingress_acl_oid;
                } else if (MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG == bind_point_type) {
                    value->oid = mlnx_ports_db[port_db_idx].issu_lag_attr.lag_egress_acl_oid;
                }
                status = SAI_STATUS_SUCCESS;
                goto out;
            }
        }
        status = mlnx_acl_bind_point_port_lag_rif_data_get(target, bind_point_type, &bind_point_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Error getting acl bind point for target %" PRIx64 "\n", target);
            goto out;
        }
        break;

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
            status = SAI_STATUS_SUCCESS;
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
        status = SAI_STATUS_SUCCESS;
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
    sx_acl_id_t        sx_group_id, sx_acl_id;

    assert(acl_db_table(table_index).wrapping_group.created == false);

    sx_acl_direction = acl_sai_stage_to_sx_dir(acl_db_table(table_index).stage);
    sx_acl_id = acl_db_table(table_index).table_id;

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_acl_direction, NULL, 0, &sx_group_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to create sx wrapping group - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_SET, sx_acl_direction, &sx_acl_id, 1, &sx_group_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to update sx group (%x) - %s\n", sx_group_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl_db_table(table_index).wrapping_group.created = true;
    acl_db_table(table_index).wrapping_group.sx_group_id = sx_group_id;

    SX_LOG_DBG("Created wrapping group sx_id[%u] for table[%u]\n", sx_group_id, table_index);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_wrapping_group_delete(_In_ uint32_t table_index)
{
    sx_status_t        sx_status;
    sx_acl_direction_t sx_acl_direction;
    sx_acl_id_t        sx_group_id;

    SX_LOG_DBG("Removing wrapping group sx_id[%u] for table[%u]\n", acl_db_table(
                   table_index).wrapping_group.sx_group_id,
               table_index);

    assert(acl_db_table(table_index).wrapping_group.created);

    sx_group_id = acl_db_table(table_index).wrapping_group.sx_group_id;
    sx_acl_direction = acl_sai_stage_to_sx_dir(acl_db_table(table_index).stage);

    sx_status = sx_api_acl_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, sx_acl_direction, NULL, 0, &sx_group_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to remove sx wrapping group - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    acl_db_table(table_index).wrapping_group.created = false;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_def_rule_port_list_fill(_In_ sx_acl_key_t sx_key, _Out_ sx_flex_acl_flex_rule_t *sx_rule)
{
    sx_status_t                  sx_status;
    sx_mc_container_attributes_t sx_mc_container_attributes;
    acl_def_rule_mc_container_t *def_mc_container;

    assert((sx_key == FLEX_ACL_KEY_RX_PORT_LIST) || (sx_key == FLEX_ACL_KEY_TX_PORT_LIST));
    assert(sx_rule);

    def_mc_container = &sai_acl_db->acl_settings_tbl->def_mc_container;

    if (!def_mc_container->is_created) {
        memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));

        sx_mc_container_attributes.type = SX_MC_CONTAINER_TYPE_PORT;

        sx_status = sx_api_mc_container_set(gh_sdk,
                                            SX_ACCESS_CMD_CREATE,
                                            &def_mc_container->mc_container,
                                            NULL,
                                            0,
                                            &sx_mc_container_attributes);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create sx_mc_container - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        SX_LOG_DBG("Created mc container %d\n", def_mc_container->mc_container);

        def_mc_container->is_created = true;
    }

    switch (sx_key) {
    case FLEX_ACL_KEY_RX_PORT_LIST:
        sx_rule->key_desc_list_p[0].key.rx_port_list.match_type = SX_ACL_PORT_LIST_MATCH_POSITIVE;
        sx_rule->key_desc_list_p[0].key.rx_port_list.mc_container_id = def_mc_container->mc_container;
        sx_rule->key_desc_list_p[0].mask.rx_port_list = false;
        break;

    case FLEX_ACL_KEY_TX_PORT_LIST:
        sx_rule->key_desc_list_p[0].key.tx_port_list.match_type = SX_ACL_PORT_LIST_MATCH_POSITIVE;
        sx_rule->key_desc_list_p[0].key.tx_port_list.mc_container_id = def_mc_container->mc_container;
        sx_rule->key_desc_list_p[0].mask.tx_port_list = false;
        break;

    default:
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_def_rule_key_fill(_In_ sx_acl_key_t sx_key, _Out_ sx_flex_acl_flex_rule_t *sx_rule)
{
    sai_status_t            status;
    sx_flex_acl_key_desc_t *sx_key_desc;

    assert(sx_rule);

    sx_rule->key_desc_count = 1;
    sx_rule->key_desc_list_p[0].key_id = sx_key;
    sx_key_desc = &sx_rule->key_desc_list_p[0];

    switch (sx_key) {
    case FLEX_ACL_KEY_SIP:
        sx_key_desc->key.sip.version = SX_IP_VERSION_IPV4;
        sx_key_desc->mask.sip.version = SX_IP_VERSION_IPV4;
        break;

    case FLEX_ACL_KEY_INNER_SIP:
        sx_key_desc->key.inner_sip.version = SX_IP_VERSION_IPV4;
        sx_key_desc->mask.inner_sip.version = SX_IP_VERSION_IPV4;
        break;

    case FLEX_ACL_KEY_DIP:
        sx_key_desc->key.dip.version = SX_IP_VERSION_IPV4;
        sx_key_desc->mask.dip.version = SX_IP_VERSION_IPV4;
        break;

    case FLEX_ACL_KEY_INNER_DIP:
        sx_key_desc->key.inner_dip.version = SX_IP_VERSION_IPV4;
        sx_key_desc->mask.inner_dip.version = SX_IP_VERSION_IPV4;
        break;

    case FLEX_ACL_KEY_DIPV6:
        sx_key_desc->key.dipv6.version = SX_IP_VERSION_IPV6;
        sx_key_desc->mask.dipv6.version = SX_IP_VERSION_IPV6;
        break;

    case FLEX_ACL_KEY_SIPV6:
        sx_key_desc->key.sipv6.version = SX_IP_VERSION_IPV6;
        sx_key_desc->mask.sipv6.version = SX_IP_VERSION_IPV6;
        break;

    case FLEX_ACL_KEY_INNER_SIPV6:
        sx_key_desc->key.inner_sipv6.version = SX_IP_VERSION_IPV6;
        sx_key_desc->mask.inner_sipv6.version = SX_IP_VERSION_IPV6;
        break;

    case FLEX_ACL_KEY_INNER_DIPV6:
        sx_key_desc->key.inner_dipv6.version = SX_IP_VERSION_IPV6;
        sx_key_desc->mask.inner_dipv6.version = SX_IP_VERSION_IPV6;
        break;

    case FLEX_ACL_KEY_RX_PORT_LIST:
    case FLEX_ACL_KEY_TX_PORT_LIST:
        status = mlnx_acl_def_rule_port_list_fill(sx_key, sx_rule);
        if (SAI_ERR(status)) {
            return status;
        }

    default:
        break;
    }

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

    key_type = acl_db_table(src_table_index).key_type;
    key = acl_db_table(src_table_index).def_rule_key;
    rule_offset = acl_db_table(src_table_index).def_rules_offset;
    region_id = acl_db_table(src_table_index).region_id;

    sx_status = sx_lib_flex_acl_rule_init(key_type, 1, &default_rule);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to init default rule - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_acl_def_rule_key_fill(key, &default_rule);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_sx_rule_prio_set(&default_rule, ACL_SX_RULE_PRIO_GOTO_RULE);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (invalidate) {
        default_rule.valid = false;
    } else {
        assert(acl_db_table(dst_table_index).wrapping_group.created);
        sx_target_group_id = acl_db_table(dst_table_index).wrapping_group.sx_group_id;

        default_rule.valid = true;
        default_rule.action_count = 1;
        default_rule.action_list_p[0].type = SX_FLEX_ACL_ACTION_GOTO;
        default_rule.action_list_p[0].fields.action_goto.goto_action_cmd = SX_ACL_ACTION_GOTO_JUMP;
        default_rule.action_list_p[0].fields.action_goto.acl_group_id = sx_target_group_id;
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
    index_count = group_bound_to->count;
    stage = sai_acl_db_group_ptr(group_index)->stage;

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
    char                       bind_point_type_str[LINE_LENGTH] = {0};

    group_bind_point_type_count = sai_acl_db_group_ptr(group_index)->bind_point_types.count;
    group_bind_point_types = sai_acl_db_group_ptr(group_index)->bind_point_types.types;
    table_bind_point_type_count = acl_db_table(table_index).bind_point_types.count;
    table_bind_point_types = acl_db_table(table_index).bind_point_types.types;

    for (ii = 0; ii < group_bind_point_type_count; ii++) {
        for (jj = 0; jj < table_bind_point_type_count; jj++) {
            if (group_bind_point_types[ii] == table_bind_point_types[jj]) {
                break;
            }
        }

        if (jj == table_bind_point_type_count) {
            sai_serialize_acl_bind_point_type(bind_point_type_str, group_bind_point_types[ii]);
            SX_LOG_ERR("ACL Group's bind point type (%s) is not supported for ACL Table (%d)\n",
                       bind_point_type_str, table_index);
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

    group_type = sai_acl_db_group_ptr(group_index)->search_type;
    group_members = sai_acl_db_group_ptr(group_index)->members;
    group_members_count = sai_acl_db_group_ptr(group_index)->members_count;

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
            group_members[ii].table_prio = table_priority;
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
            group_members[0].table_index = table_index;
            group_members[0].table_prio = table_priority;
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

    acl_db_table(table_index).group_references++;
    acl_db_table(table_index).group_type = group_type;

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
    group_members = sai_acl_db_group_ptr(group_index)->members;

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
                status = mlnx_acl_wrapping_group_delete(new_head_table_index);
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

    acl_db_table(table_index).group_references--;

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

    oid_data = table_index & 0xFFFF;
    oid_data |= (group_index & 0xFFFF) << 16;
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
        *table_priority = oid_extra_data[0];
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
        bind_point_types = sai_acl_db_group_ptr(group_index)->bind_point_types.types;

        if (value->s32list.count < bind_point_type_count) {
            if (0 == value->s32list.count) {
                status = MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST;
            } else {
                status = SAI_STATUS_BUFFER_OVERFLOW;
            }
            SX_LOG(((0 == value->s32list.count) ? SX_LOG_NOTICE : SX_LOG_ERROR),
                   " Re-allocate list size as list size is not large enough \n");
            value->s32list.count = bind_point_type_count;
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

static sai_status_t mlnx_acl_group_member_list_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    sai_status_t              status;
    const acl_group_member_t *group_members;
    sai_object_id_t          *group_members_oids = NULL;
    uint32_t                  group_index, group_members_count, ii;

    SX_LOG_ENTER();

    acl_global_lock();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &group_index, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    group_members = sai_acl_db_group_ptr(group_index)->members;
    group_members_count = sai_acl_db_group_ptr(group_index)->members_count;

    group_members_oids = calloc(group_members_count, sizeof(group_members[0]));
    if (!group_members_oids) {
        SX_LOG_ERR("Failed to acllocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (ii = 0; ii < group_members_count; ii++) {
        status = mlnx_acl_group_member_oid_create(&group_members_oids[ii], group_members[ii].table_index,
                                                  group_index, group_members[ii].table_prio);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_fill_objlist(group_members_oids, group_members_count, &value->objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    acl_global_unlock();
    free(group_members_oids);
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

        range_type = range_type_value.s32;
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

        sx_port_range_id = (sx_acl_port_range_id_t)object_data;
        sx_acl_range->port_range_list[ii] = sx_port_range_id;
    }

    is_range_types_unique = mlnx_acl_range_type_list_is_unique(range_list_types, range_list->count);
    if (false == is_range_types_unique) {
        return SAI_STATUS_FAILURE;
    }

    sx_acl_range->port_range_cnt = range_list->count;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_create_spc(_In_ sai_acl_range_type_t     type,
                                              _In_ const sai_u32_range_t   *range,
                                              _Out_ sx_acl_port_range_id_t *sx_range_id)
{
    sx_status_t               sx_status;
    sx_acl_port_range_entry_t sx_port_range_entry;

    assert(range);
    assert(sx_range_id);

    memset(&sx_port_range_entry, 0, sizeof(sx_port_range_entry));
    sx_port_range_entry.port_range_ip_length = false;
    sx_port_range_entry.port_range_ip_header = SX_ACL_PORT_RANGE_IP_HEADER_OUTER;

    switch (type) {
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
        SX_LOG_ERR("Range type %d is not supported\n", type);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    sx_port_range_entry.port_range_min = range->min;
    sx_port_range_entry.port_range_max = range->max;

    sx_status = sx_api_acl_l4_port_range_set(gh_sdk, SX_ACCESS_CMD_ADD, &sx_port_range_entry, sx_range_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create range %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_create_spc2(_In_ sai_acl_range_type_t     type,
                                               _In_ const sai_u32_range_t   *range,
                                               _Out_ sx_acl_port_range_id_t *sx_range_id)
{
    sx_status_t          sx_status;
    sx_acl_range_entry_t sx_acl_range_entry;

    assert(range);
    assert(sx_range_id);

    memset(&sx_acl_range_entry, 0, sizeof(sx_acl_range_entry));
    sx_acl_range_entry.ip_version = SX_IP_VERSION_IPV4_IPV6;
    sx_acl_range_entry.outer_inner = SX_ACL_PORT_RANGE_IP_HEADER_OUTER;

    switch (type) {
    case SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE:
        sx_acl_range_entry.direction = SX_ACL_PORT_DIRECTION_SOURCE;
        sx_acl_range_entry.range_type = SX_ACL_RANGE_TYPE_L4_PORT_E;
        sx_acl_range_entry.l4_protocol = SX_ACL_L4_TYPE_TCP_UDP;
        break;

    case SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE:
        sx_acl_range_entry.direction = SX_ACL_PORT_DIRECTION_DESTINATION;
        sx_acl_range_entry.range_type = SX_ACL_RANGE_TYPE_L4_PORT_E;
        sx_acl_range_entry.l4_protocol = SX_ACL_L4_TYPE_TCP_UDP;
        break;

    /*
     *  case SAI_ACL_RANGE_TYPE_OUTER_VLAN:
     *   break;
     *
     *  case SAI_ACL_RANGE_TYPE_INNER_VLAN:
     *   break;
     */
    case SAI_ACL_RANGE_TYPE_PACKET_LENGTH:
        sx_acl_range_entry.range_type = SX_ACL_RANGE_TYPE_IP_LENGTH_E;
        sx_acl_range_entry.l4_protocol = SX_ACL_L4_TYPE_INVALID;
        break;

    default:
        SX_LOG_ERR("Range type %d is not supported\n", type);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    sx_acl_range_entry.range_limits.min = range->min;
    sx_acl_range_entry.range_limits.max = range->max;

    sx_status = sx_api_acl_range_set(gh_sdk, SX_ACCESS_CMD_ADD, &sx_acl_range_entry, sx_range_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create range %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_remove_spc(_In_ sx_acl_port_range_id_t sx_range_id)
{
    sx_status_t               sx_status;
    sx_acl_port_range_entry_t sx_port_range_entry;

    memset(&sx_port_range_entry, 0, sizeof(sx_port_range_entry));

    sx_status = sx_api_acl_l4_port_range_set(gh_sdk, SX_ACCESS_CMD_DELETE, &sx_port_range_entry, &sx_range_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete range %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_acl_range_remove_spc2(_In_ sx_acl_port_range_id_t sx_range_id)
{
    sx_status_t          sx_status;
    sx_acl_range_entry_t sx_acl_range_entry;

    memset(&sx_acl_range_entry, 0, sizeof(sx_acl_range_entry));

    sx_status = sx_api_acl_range_set(gh_sdk, SX_ACCESS_CMD_DELETE, &sx_acl_range_entry, &sx_range_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete range %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

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
    sx_acl_port_range_id_t       sx_port_range_id;
    const sai_attribute_value_t *range_type, *range_limit;
    uint32_t                     range_type_index, range_limit_index;
    uint32_t                     range_min, range_max;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];

    SX_LOG_ENTER();

    /* make sure that sx_port_range_id won't get truncated */
    assert(sizeof(sx_port_range_id) <= sizeof(uint32_t));
    assert(mlnx_acl_cb);

    if (NULL == acl_range_id) {
        SX_LOG_ERR("NULL object id value\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_RANGE,
                                    acl_range_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_RANGE, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Range, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_RANGE_ATTR_TYPE, &range_type, &range_type_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_RANGE_ATTR_LIMIT, &range_limit, &range_limit_index);
    assert(SAI_STATUS_SUCCESS == status);

    range_min = range_limit->u32range.min;
    range_max = range_limit->u32range.max;

    if (range_min > range_max) {
        SX_LOG_ERR("Invalid range value - min[%d] > max[%d]\n", range_min, range_max);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + range_limit_index;
        goto out;
    }

    status = mlnx_acl_cb->range_create(range_type->s32, &range_limit->u32range, &sx_port_range_id);
    if (SAI_ERR(status)) {
        goto out;
    }

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
    sai_status_t           status;
    uint32_t               object_range_id;
    sx_acl_port_range_id_t sx_port_range_id;
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    assert(mlnx_acl_cb);

    acl_range_key_to_str(acl_range_id, key_str);
    SX_LOG_NTC("Delete ACL Range %s\n", key_str);

    status = mlnx_object_to_type(acl_range_id, SAI_OBJECT_TYPE_ACL_RANGE, &object_range_id, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_port_range_id = object_range_id;

    status = mlnx_acl_cb->range_remove(sx_port_range_id);
    if (SAI_ERR(status)) {
        goto out;
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
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ACL_RANGE, acl_range_vendor_attribs, attr);
}

/**
 * Routine Description:
 *   @brief Get ACL range attribute
 *
 * Arguments:
 *    @param[in] acl_range_id - acl range id
 *    @param[in] attr_count - number of attributes
 *    @param[inout] attr_list - array of attributes
 *
 * Return Values:
 *    @return  SAI_STATUS_SUCCESS on success
 *             Failure status code on error
 */
static sai_status_t mlnx_get_acl_range_attribute(_In_ sai_object_id_t     acl_range_id,
                                                 _In_ uint32_t            attr_count,
                                                 _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_range_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_range_key_to_str(acl_range_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_ACL_RANGE, acl_range_vendor_attribs, attr_count,
                              attr_list);
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

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_TABLE_GROUP,
                                    acl_group_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create ACL Group, %s\n", list_str);

    group_type = SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL;

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_GROUP_ATTR_TYPE, &group_attr_type, &attr_index);
    if (!SAI_ERR(status)) {
        group_type = group_attr_type->s32;
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

    sai_acl_db_group_ptr(group_index)->members_count = 0;
    sai_acl_db_group_ptr(group_index)->search_type = group_type;
    sai_acl_db_group_ptr(group_index)->stage = group_stage;
    sai_acl_db_group_ptr(group_index)->bind_point_types = group_bind_point_types;

    group_bound_to = sai_acl_db_group_bount_to(group_index);
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

    if (sai_acl_db_group_ptr(group_index)->members_count > 0) {
        SX_LOG_ERR("Group [%lx] is not empty\n", acl_table_group_id);
        status = SAI_STATUS_OBJECT_IN_USE;
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
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, acl_group_vendor_attribs, attr);
}

/**
 * @brief Get ACL table group attribute
 *
 * @param[in] acl_table_group_id ACL table group id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_acl_table_group_attribute(_In_ sai_object_id_t     acl_table_group_id,
                                                       _In_ uint32_t            attr_count,
                                                       _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_table_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_group_key_to_str(acl_table_group_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_ACL_TABLE_GROUP,
                              acl_group_vendor_attribs,
                              attr_count,
                              attr_list);
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

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER,
                                    acl_group_member_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count,
                         attr_list,
                         SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER,
                         MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create ACL Group member, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID,
                                 &group_id, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_object_to_type(group_id->oid, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, &group_index, NULL);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    sai_db_read_lock();
    if (false == acl_group_index_check_range(group_index)) {
        SX_LOG_ERR("Invalid acl group object id (%lx)\n", group_id->oid);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        sai_db_unlock();
        goto out;
    }
    sai_db_unlock();

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

    if (false == acl_table_index_check_range(table_index)) {
        SX_LOG_ERR("Invalid acl group object id (%lx)\n", table_id->oid);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out_unlock;
    }

    if ((acl_db_table(table_index).group_references > 0) &&
        (acl_db_table(table_index).group_type == SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL)) {
        SX_LOG_ERR("Table [%d] is a member of sequential group\n", table_index);
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

    if (0 == acl_db_table(table_index).group_references) {
        SX_LOG_ERR("Table [%d] is not a member of any group\n", table_index);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out_unlock;
    }

    status = mlnx_acl_group_del_table(group_index, table_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

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
    return sai_set_attribute(&key,
                             key_str,
                             SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER,
                             acl_group_member_vendor_attribs,
                             attr);
}

/**
 * @brief Get ACL table group member attribute
 *
 * @param[in] acl_table_group_id ACL table group member id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_acl_table_group_member_attribute(_In_ sai_object_id_t     acl_table_group_member_id,
                                                              _In_ uint32_t            attr_count,
                                                              _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = acl_table_group_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    acl_group_member_key_to_str(acl_table_group_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER,
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
