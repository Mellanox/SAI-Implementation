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

#if !defined (__MLNXSAI_H_)
#define __MLNXSAI_H_

#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_acl.h>
#include <sx/sdk/sx_api_bfd.h>
#include <sx/sdk/sx_api_bridge.h>
#include <sx/sdk/sx_api_bulk_counter.h>
#include <sx/sdk/sx_api_cos.h>
#include <sx/sdk/sx_api_cos_redecn.h>
#include <sx/sdk/sx_api_dbg.h>
#include <sx/sdk/sx_api_fdb.h>
#include <sx/sdk/sx_api_flex_acl.h>
#include <sx/sdk/sx_api_flex_parser.h>
#include <sx/sdk/sx_api_flow_counter.h>
#include <sx/sdk/sx_api_host_ifc.h>
#include <sx/sdk/sx_api_init.h>
#include <sx/sdk/sx_api_issu.h>
#include <sx/sdk/sx_api_lag.h>
#include <sx/sdk/sx_api_mc_container.h>
#include <sx/sdk/sx_api_mstp.h>
#include <sx/sdk/sx_api_policer.h>
#include <sx/sdk/sx_api_port.h>
#include <sx/sdk/sx_api_router.h>
#include <sx/sdk/sx_api_span.h>
#include <sx/sdk/sx_api_topo.h>
#include <sx/sdk/sx_api_tunnel.h>
#include <sx/sdk/sx_api_vlan.h>
#include <sx/sdk/sx_lib_flex_acl.h>
#include <sx/sdk/sx_lib_host_ifc.h>
#include <sx/sdk/sx_api_register.h>
#include <sx/sdk/sx_acl.h>
#include <resource_manager/resource_manager.h>
#include <sx/sxd/sxd_access_register.h>
#include <sx/sxd/sxd_command_ifc.h>
#include <sx/sxd/sxd_dpt.h>
#include <sx/sxd/sxd_status.h>
#include <complib/cl_event.h>
#include <complib/cl_passivelock.h>
#ifndef _WIN32
#include <pthread.h>
#include <semaphore.h>
#endif
#include <sx/utils/psort.h>
#include <sai.h>
#include <saiextensions.h>
#include <infiniband/mad.h>
#include "config.h"
#include <infiniband/iba/ib_types.h>

#ifdef _WIN32
#define PACKED(__decl, __inst) __pragma(pack(push, 1)) __decl __inst __pragma(pack(pop))
#else
#define PACKED(__decl, __inst) __decl __attribute__((__packed__)) __inst
#endif

#ifdef _WIN32
#define PACKED_ENUM
#else
#define PACKED_ENUM __attribute__((__packed__))
#endif

#define MLNX_SYSLOG_FMT "[%s.%s] "
#define MLNX_LOG_FMT    "%s[%d]- %s: "


inline static char * mlnx_severity_to_syslog(sx_log_severity_t severity)
{
    switch (severity) {
    case SX_LOG_NOTICE:
        return "NOTICE";

    case SX_LOG_INFO:
        return "INFO";

    case SX_LOG_ERROR:
        return "ERR";

    case SX_LOG_WARNING:
        return "WARNING";

    case SX_LOG_FUNCS:
    case SX_LOG_FRAMES:
    case SX_LOG_DEBUG:
    case SX_LOG_ALL:
    default:
        return "DEBUG";
    }
}

#define mlnx_syslog(level, module, fmt, ...)                                    \
    do {                                                                        \
        int __mlnx_sai_verbosity_level__ = 0;                                   \
        SEVERITY_LEVEL_TO_VERBOSITY_LEVEL(level, __mlnx_sai_verbosity_level__); \
                                                                                \
        syslog(VERBOSITY_LEVEL_TO_SYSLOG_LEVEL(__mlnx_sai_verbosity_level__),   \
               MLNX_SYSLOG_FMT fmt,                                             \
               module, mlnx_severity_to_syslog(level),                          \
               ## __VA_ARGS__);                                                 \
    } while (0)

#ifdef CONFIG_SYSLOG
#define MLNX_SAI_LOG_IMPL(level, fmt, ...)                    \
    mlnx_syslog(level, QUOTEME(__MODULE__), MLNX_LOG_FMT fmt, \
                __FILE__, __LINE__, __FUNCTION__,             \
                ## __VA_ARGS__)
#else
#define MLNX_SAI_LOG_IMPL(level, fmt, ...) printf(fmt, ## __VA_ARGS__)
#endif

#define MLNX_SAI_LOG(level, fmt, ...)                                                \
    do {                                                                             \
        if (gh_sdk) {                                                                \
            SX_LOG(level, fmt, ## __VA_ARGS__);                                      \
        } else {                                                                     \
            sx_verbosity_level_t __verbosity_level = 0;                              \
            SEVERITY_LEVEL_TO_VERBOSITY_LEVEL(level, __verbosity_level);             \
            if (LOG_VAR_NAME(__MODULE__) >= __verbosity_level) {                     \
                MLNX_SAI_LOG_IMPL(level, "%s[%d]- %s: " fmt,                         \
                                  __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__); \
            }                                                                        \
        }                                                                            \
    } while (0)

#define MLNX_SAI_LOG_DBG(fmt, ...) MLNX_SAI_LOG(SX_LOG_DEBUG, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_INF(fmt, ...) MLNX_SAI_LOG(SX_LOG_INFO, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_WRN(fmt, ...) MLNX_SAI_LOG(SX_LOG_WARNING, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_ERR(fmt, ...) MLNX_SAI_LOG(SX_LOG_ERROR, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_NTC(fmt, ...) MLNX_SAI_LOG(SX_LOG_NOTICE, fmt, ## __VA_ARGS__)

#define SAI_ERR(status) ((status) != SAI_STATUS_SUCCESS)
#define SAI_OK(status)  ((status) == SAI_STATUS_SUCCESS)
#define SX_ERR(status)  ((status) != SX_STATUS_SUCCESS)

#define MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST SAI_STATUS_CODE(0x01000000L)

#ifndef _WIN32
#define UNREFERENCED_PARAMETER(X)
#define _Inout_opt_
#define _Out_opt_
#define _Success_(X)
#define _Out_writes_(X)
#else
#define PRId64 "lld"
unsigned int if_nametoindex(const char *ifname);
char * if_indextoname(unsigned int ifindex, char *ifname);
void * mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
cl_status_t cl_plock_init_pshared(IN cl_plock_t * const p_lock);
int msync(void *addr, size_t length, int flags);
#define PROT_READ  1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_FAILED (void*)-1
#define MS_SYNC    4
#endif

extern sx_api_handle_t            gh_sdk;
extern sai_service_method_table_t g_mlnx_services;
extern rm_resources_t             g_resource_limits;
extern sx_log_cb_t                sai_log_cb;

sai_status_t sdk_to_sai(sx_status_t status);

extern const sai_switch_api_t mlnx_switch_api;
extern const sai_port_api_t   mlnx_port_api;

#define DEFAULT_IB_SWID 0

#define FIRST_PORT                        (0x10000 | (1 << 8))
#define PORT_MAC_BITMASK_QTM              (~0x0)
#define PORT_SPEED_800                    800000
#define PORT_SPEED_400                    400000
#define PORT_SPEED_200                    200000
#define PORT_SPEED_100                    100000
#define PORT_SPEED_50                     50000
#define PORT_SPEED_25                     25000
#define PORT_SPEED_56                     56000
#define PORT_SPEED_40                     40000
#define PORT_SPEED_20                     20000
#define PORT_SPEED_10                     10000
#define PORT_SPEED_1                      1000
#define PORT_SPEED_100M                   100
#define PORT_SPEED_10M                    10
#define PORT_SPEED_0                      0
#define PORT_SPEED_SDR                    2500
#define PORT_SPEED_DDR                    5000
#define PORT_SPEED_QDR                    10000
#define PORT_SPEED_FDR                    14000
#define PORT_SPEED_EDR                    25000
#define PORT_SPEED_HDR                    50000
#define PORT_SPEED_NDR                    100000
#define PORT_SPEED_XDR                    200000
#define MAX_NUM_PORT_SPEEDS               14
#define CPU_PORT                          0
#define SX_DEVICE_ID                      1
#define SX_INVALID_DEVICE_ID              0
#define DEFAULT_DEVICE_ID                 255
#define PORT_STATE_DOWN_BY_SIGNAL_DEGRADE 9

#define safe_free(var) \
    if (var) {         \
        free(var);     \
        var = NULL;    \
    }                  \

#define ARRAY_SIZE(_x) (sizeof(_x) / sizeof(_x[0]))

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define EXTENDED_DATA_SIZE                     2
#define MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS 2

PACKED(struct _mlnx_object_id_t {
    sai_uint8_t object_type;
    PACKED(struct {
        uint8_t sub_type: 3;
        uint8_t swid: 5;
    }, field);
    union {
        sai_uint8_t bytes[EXTENDED_DATA_SIZE];
    } ext;
    union {
        bool is_created;
        sai_uint32_t u32;
    } id;
}, );

typedef struct _mlnx_object_id_t mlnx_object_id_t;

typedef sai_status_t (*mlnx_availability_get_fn)(_In_ sai_object_id_t switch_id, _In_ uint32_t attr_count,
                                                 _In_ const sai_attribute_t *attr_list, _Out_ uint64_t *count);

typedef struct _mlnx_sai_attr_t {
    bool                   found;
    uint32_t               index;
    sai_attribute_value_t *value;
} mlnx_sai_attr_t;

#define SAI_TYPE_CHECK_RANGE(type) ((sai_object_type_extensions_t)type < SAI_OBJECT_TYPE_EXTENSIONS_RANGE_END)
extern const char* sai_metadata_sai_object_type_t_enum_values_short_names[];
#define SAI_TYPE_STR(type)                                                                      \
    SAI_TYPE_CHECK_RANGE(type) ? sai_metadata_sai_object_type_t_enum_values_short_names[type] : \
    "Unknown object type"

typedef sai_status_t (*sai_attribute_set_fn)(_In_ const sai_object_key_t *key, _In_ const sai_attribute_value_t *value,
                                             void *arg);

typedef struct _mlnx_fdb_cache_t {
    sx_port_id_t               log_port;    /**< Logical port */
    sx_fdb_uc_mac_entry_type_t entry_type;  /**< FDB Entry Type */
    sx_fdb_action_t            action;
    sx_ip_addr_t               endpoint_ip;
    bool                       fdb_cache_set;
} mlnx_fdb_cache_t;

typedef union {
    mlnx_fdb_cache_t fdb_cache;
} vendor_cache_t;

typedef sai_status_t (*sai_attribute_get_fn)(_In_ const sai_object_key_t *key, _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t attr_index, _Inout_ vendor_cache_t *cache, void *arg);
typedef struct _sai_vendor_attribute_entry_t {
    sai_attr_id_t        id;
    bool                 is_implemented[SAI_COMMON_API_MAX];
    bool                 is_supported[SAI_COMMON_API_MAX];
    sai_attribute_get_fn getter;
    void                *getter_arg;
    sai_attribute_set_fn setter;
    void                *setter_arg;
} sai_vendor_attribute_entry_t;

#define END_FUNCTIONALITY_ATTRIBS_ID 0xFFFFFFFF

typedef enum {
    /* TODO: IS_PHY_NONE_MEMBER */
    ATTR_PORT_IS_ENABLED = 1 << 0,
    /* TODO: IS_PHY_NONE_MEMBER_OR_LAG */
    ATTR_PORT_IS_LAG_ENABLED = 1 << 1,
    /* TODO: IS_PHY_OR_LAG_MEMBER */
    ATTR_PORT_IS_IN_LAG_ENABLED = 1 << 2,
} attr_port_type_check_t;
typedef sai_status_t (*mlnx_attr_enum_info_fn)(int32_t *attrs, uint32_t *count);
typedef sai_status_t (*mlnx_attr_stats_capability_info_fn)(sai_stat_capability_list_t* capa_list);
typedef sai_status_t (*mlnx_bulk_object_get_stats_fn)(sai_object_id_t         switch_id,
                                                      uint32_t                object_count,
                                                      const sai_object_key_t *object_key,
                                                      uint32_t                number_of_counters,
                                                      const sai_stat_id_t    *counter_ids,
                                                      sx_access_cmd_t         cmd,
                                                      sai_status_t           *object_statuses,
                                                      uint64_t               *counters);
typedef sai_status_t (*mlnx_bulk_object_clear_stats_fn)(sai_object_id_t         switch_id,
                                                        uint32_t                object_count,
                                                        const sai_object_key_t *object_key,
                                                        uint32_t                number_of_counters,
                                                        const sai_stat_id_t    *counter_ids,
                                                        sx_access_cmd_t         cmd,
                                                        sai_status_t           *object_statuses);
typedef struct _mlnx_attr_enum_info_t {
    int32_t               *attrs;
    uint32_t               count;
    bool                   all;
    mlnx_attr_enum_info_fn fn;
} mlnx_attr_enum_info_t;
typedef struct _mlnx_obj_type_attrs_enum_infos_t {
    const mlnx_attr_enum_info_t *info;
    uint32_t                     count;
} mlnx_obj_type_attrs_enums_info_t;
typedef struct _mlnx_obj_type_stats_capability_infos_t {
    const sai_stat_capability_t       *info;
    uint32_t                           count;
    mlnx_attr_stats_capability_info_fn capability_fn;
} mlnx_obj_type_stats_capability_info_t;
typedef struct _mlnx_obj_type_attrs_info_t {
    const sai_vendor_attribute_entry_t         *vendor_data;
    const mlnx_obj_type_attrs_enums_info_t      enums_info;
    const mlnx_obj_type_stats_capability_info_t stats_capability;
} mlnx_obj_type_attrs_info_t;

#define bulk_context_cond_mutex_lock(mutex)                           \
    do { if (pthread_mutex_lock(&mutex) != 0) {                       \
             /*SX_LOG_ERR("Failed to lock bulk counter mutex\n");*/ } \
    } while (0)

#define bulk_context_cond_mutex_unlock(mutex)                           \
    do { if (pthread_mutex_unlock(&mutex) != 0) {                       \
             /*SX_LOG_ERR("Failed to unlock bulk counter mutex\n");*/ } \
    } while (0)

typedef struct _sai_bulk_counter_event {
#ifndef _WIN32
    pthread_cond_t  cond;
    pthread_mutex_t mutex;
#endif
    int32_t  read_done;
    bool     in_use;
    uint32_t message_id;        /* Message id used to distinguish different transactions */
} sai_bulk_counter_event_t;

typedef enum _sai_bulk_counter_type {
    MLNX_BULK_TYPE_PORT,
    MLNX_BULK_TYPE_FLOW,
    MLNX_BULK_TYPE_SHARED_BUFFER,
    MLNX_BULK_TYPE_HEADROOM,
    MLNX_BULK_TYPE_ELEPHANT,
    MLNX_BULK_TYPE_MAX_BULK_COUNTER_TYPE,
} sai_bulk_counter_type;

typedef struct _sai_bulk_counter_info {
    sai_bulk_counter_event_t events[MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS];
    cl_plock_t               event_lock;
    cl_plock_t               per_type_locks[MLNX_BULK_TYPE_MAX_BULK_COUNTER_TYPE];
    uint32_t                 last_message_id;
} sai_bulk_counter_info_t;

/*
 * For queue/PG shared buffer stats, SDK allows to read stats per port.
 * To avoid calling sx_api_bulk_counter_transaction_get
 * too often, we cache per port shared buffer stats in this structure
 */
typedef struct _sai_bulk_counter_stats {
    sx_port_log_id_t    port_num;
    sx_bulk_cntr_data_t data;
    sai_status_t        status; /* set to error status if sx_api_bulk_counter_transaction_get failed */
} sai_bulk_counter_stats;

sai_status_t mlnx_prepare_bulk_counter_read(_In_ sai_bulk_counter_type      bulk_type,
                                            _In_ sx_access_cmd_t            cmd,
                                            _In_ sx_bulk_cntr_buffer_key_t *bulk_read_key,
                                            _Out_ sx_bulk_cntr_buffer_t    *bulk_read_buff);
sai_status_t mlnx_deallocate_sx_bulk_buffer(_In_ sx_bulk_cntr_buffer_t *bulk_read_buff);
sai_status_t mlnx_exhaust_bulk_counter_trasaction_sem();
sai_status_t mlnx_fillup_bulk_counter_trasaction_sem();
sai_status_t mlnx_notify_bulk_counter_readable(_In_ uint32_t cookie, _In_ int32_t read_status);

/* A set of macros that allows to define a number of values passed to the macro
 * Example PP_NARG(a, b, c) gives 3.
 */
#ifndef _WIN32
#define PP_NARG(...) \
    PP_NARG_(__VA_ARGS__, PP_RSEQ_N())
#define PP_NARG_(...) \
    PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N(                                         \
        _1, _2, _3, _4, _5, _6, _7, _8, _9, _10,          \
        _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, \
        _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, \
        _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, \
        _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, \
        _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, \
        _61, _62, _63,  N, ...) N
#define PP_RSEQ_N()                         \
    63, 62, 61, 60,                         \
    59, 58, 57, 56, 55, 54, 53, 52, 51, 50, \
    49, 48, 47, 46, 45, 44, 43, 42, 41, 40, \
    39, 38, 37, 36, 35, 34, 33, 32, 31, 30, \
    29, 28, 27, 26, 25, 24, 23, 22, 21, 20, \
    19, 18, 17, 16, 15, 14, 13, 12, 11, 10, \
    9, 8, 7, 6, 5, 4, 3, 2, 1, 0
#else
#define EXPAND(x) x
#define PP_NARG(...) \
    EXPAND(_xPP_NARGS_IMPL(__VA_ARGS__, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
#define _xPP_NARGS_IMPL(x1,  \
                        x2,  \
                        x3,  \
                        x4,  \
                        x5,  \
                        x6,  \
                        x7,  \
                        x8,  \
                        x9,  \
                        x10, \
                        x11, \
                        x12, \
                        x13, \
                        x14, \
                        x15, \
                        x16, \
                        x17, \
                        x18, \
                        x19, \
                        x20, \
                        x21, \
                        x22, \
                        x23, \
                        x24, \
                        x25, \
                        x26, \
                        x27, \
                        x28, \
                        x29, \
                        x30, \
                        N,   \
                        ...) N
#endif /* ifndef _WIN32 */
#define ATTR_ARR_LEN(...) PP_NARG(__VA_ARGS__)

#define ATTR_ENUM_VALUES_LIST(...)                                \
    {.attrs = (int32_t[ATTR_ARR_LEN(__VA_ARGS__)]) {__VA_ARGS__}, \
     .count = ATTR_ARR_LEN(__VA_ARGS__),                          \
     .all = false,                                                \
     .fn = NULL }
#define ATTR_ENUM_VALUES_ALL() \
    {.attrs = NULL,            \
     .count = 0,               \
     .fn = NULL,               \
     .all = true }
#define ATTR_ENUM_VALUES_FN(f) \
    {.attrs = NULL,            \
     .count = 0,               \
     .all = false,             \
     .fn = f}

#define ATTR_ENUM_INFO_IS_VALID(info) ((((info)->all) ^ ((info)->fn != NULL)) || ((info)->count > 0))
#define OBJ_ATTRS_ENUMS_INFO(enum_info_arr) \
    {.info = enum_info_arr, .count = ARRAY_SIZE(enum_info_arr)}
#define OBJ_ATTRS_ENUMS_INFO_EMPTY() \
    {.info = NULL, .count = 0}
#define OBJ_STAT_CAP_INFO(stats_cap_arr) \
    {.info = stats_cap_arr, .count = ARRAY_SIZE(stats_cap_arr), .capability_fn = NULL}
#define OBJ_STAT_CAP_FN(f) \
    {.capability_fn = f}
#define OBJ_STAT_CAP_INFO_EMPTY() \
    {.info = NULL, .count = 0, .capability_fn = NULL}

bool mlnx_chip_is_qtm(void);
bool mlnx_chip_is_qtm2(void);
bool mlnx_chip_is_qtm3(void);
bool mlnx_chip_is_sib2(void);

sai_status_t check_port_type_attr(const sai_object_id_t *ports,
                                  uint32_t               count,
                                  attr_port_type_check_t check,
                                  sai_attr_id_t          attr_id,
                                  uint32_t               idx);
sai_status_t check_attribs_metadata(_In_ uint32_t                            attr_count,
                                    _In_ const sai_attribute_t              *attr_list,
                                    _In_ sai_object_type_t                   object_type,
                                    _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                    _In_ sai_common_api_t                    oper);
sai_status_t find_attrib_in_list(_In_ uint32_t                       attr_count,
                                 _In_ const sai_attribute_t         *attr_list,
                                 _In_ sai_attr_id_t                  attrib_id,
                                 _Out_ const sai_attribute_value_t **attr_value,
                                 _Out_ uint32_t                     *index);
void find_attrib(_In_ uint32_t               attr_count,
                 _In_ const sai_attribute_t *attr_list,
                 _In_ sai_attr_id_t          attrib_id,
                 _Out_ mlnx_sai_attr_t      *attr);
sai_status_t sai_set_attribute(_In_ const sai_object_key_t             *key,
                               _In_ const char                         *key_str,
                               _In_ sai_object_type_t                   object_type,
                               _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                               _In_ const sai_attribute_t              *attr);
sai_status_t sai_get_attributes(_In_ const sai_object_key_t             *key,
                                _In_ const char                         *key_str,
                                _In_ sai_object_type_t                   object_type,
                                _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                _In_ uint32_t                            attr_count,
                                _Inout_ sai_attribute_t                 *attr_list);
sai_status_t mlnx_bulk_attrs_validate(_In_ uint32_t                 object_count,
                                      _In_ const uint32_t          *attr_count,
                                      _In_ const sai_attribute_t  **attr_list_for_create,
                                      sai_attribute_t             **attr_list_for_get,
                                      _In_ const sai_attribute_t   *attr_list_for_set,
                                      _In_ sai_bulk_op_error_mode_t mode,
                                      _In_ sai_status_t            *object_statuses,
                                      _In_ sai_common_api_t         api,
                                      _Out_ bool                   *stop_on_error);
sai_status_t mlnx_bulk_create_attrs_validate(_In_ uint32_t                 object_count,
                                             _In_ const uint32_t          *attr_count,
                                             _In_ const sai_attribute_t  **attr_list,
                                             _In_ sai_bulk_op_error_mode_t mode,
                                             _In_ sai_status_t            *object_statuses,
                                             _Out_ bool                   *stop_on_error);
sai_status_t mlnx_bulk_remove_attrs_validate(_In_ uint32_t                 object_count,
                                             _In_ sai_bulk_op_error_mode_t mode,
                                             _In_ sai_status_t            *object_statuses,
                                             _Out_ bool                   *stop_on_error);
sai_status_t mlnx_bulk_statuses_print(_In_ const char         *object_type_str,
                                      _In_ const sai_status_t *object_statuses,
                                      _In_ uint32_t            object_count,
                                      _In_ sai_common_api_t    api);
sai_status_t mlnx_sai_query_attribute_capability_impl(_In_ sai_object_id_t         switch_id,
                                                      _In_ sai_object_type_t       object_type,
                                                      _In_ sai_attr_id_t           attr_id,
                                                      _Out_ sai_attr_capability_t *attr_capability);
sai_status_t mlnx_sai_query_attribute_enum_values_capability_impl(_In_ sai_object_id_t    switch_id,
                                                                  _In_ sai_object_type_t  object_type,
                                                                  _In_ sai_attr_id_t      attr_id,
                                                                  _Inout_ sai_s32_list_t *enum_values_capability);
sai_status_t mlnx_sai_query_stats_capability_impl(_In_ sai_object_id_t                switch_id,
                                                  _In_ sai_object_type_t              object_type,
                                                  _Inout_ sai_stat_capability_list_t *stats_capability);

#define MAX_KEY_STR_LEN        100
#define MAX_VALUE_STR_LEN      100
#define MAX_LIST_VALUE_STR_LEN 1000

sai_status_t sai_attr_list_to_str(_In_ uint32_t               attr_count,
                                  _In_ const sai_attribute_t *attr_list,
                                  _In_ sai_object_type_t      object_type,
                                  _In_ uint32_t               max_length,
                                  _Out_ char                 *list_str);
sai_status_t sai_ipprefix_to_str(_In_ sai_ip_prefix_t value, _In_ uint32_t max_length, _Out_ char *value_str);
sai_status_t sai_ipaddr_to_str(_In_ sai_ip_address_t value,
                               _In_ uint32_t         max_length,
                               _Out_ char           *value_str,
                               _Out_opt_ int        *chars_written);
sai_status_t mlnx_object_to_type(sai_object_id_t   object_id,
                                 sai_object_type_t type,
                                 uint32_t         *data,
                                 uint8_t           extended_data[]);

sai_status_t mlnx_object_id_to_sai(sai_object_type_t type, mlnx_object_id_t *mlnx_object_id,
                                   sai_object_id_t *object_id);
sai_status_t sai_to_mlnx_object_id(sai_object_type_t type, sai_object_id_t object_id,
                                   mlnx_object_id_t *mlnx_object_id);

sai_status_t mlnx_create_object(sai_object_type_t type,
                                uint32_t          data,
                                uint8_t           extended_data[],
                                sai_object_id_t  *object_id);

sai_status_t mlnx_object_to_log_port(sai_object_id_t object_id, sx_port_log_id_t *port_id);

sai_status_t mlnx_port_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_switch_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_switch_common_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_utils_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_object_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_object_eth_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_issu_storage_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_interfacequery_log_set(sx_verbosity_level_t level);

sai_status_t mlnx_fill_objlist(const sai_object_id_t *data, uint32_t count, sai_object_list_t *list);
sai_status_t mlnx_fill_u8list(const uint8_t *data, uint32_t count, sai_u8_list_t *list);
sai_status_t mlnx_fill_s8list(const int8_t *data, uint32_t count, sai_s8_list_t *list);
sai_status_t mlnx_fill_u16list(const uint16_t *data, uint32_t count, sai_u16_list_t *list);
sai_status_t mlnx_fill_s16list(const int16_t *data, uint32_t count, sai_s16_list_t *list);
sai_status_t mlnx_fill_u32list(const uint32_t *data, uint32_t count, sai_u32_list_t *list);
sai_status_t mlnx_fill_s32list(const int32_t *data, uint32_t count, sai_s32_list_t *list);
sai_status_t mlnx_fill_saistatcapabilitylist(const sai_stat_capability_t *data,
                                             uint32_t                     count,
                                             sai_stat_capability_list_t  *list);
sai_status_t mlnx_attribute_value_list_size_check(_Inout_ uint32_t *out_size, _In_ uint32_t in_size);

#define MLNX_U32BITARRAY_SIZE(bits) (((bits) / 32) + 1)

static inline void array_bit_set(uint32_t *bit_array, uint32_t bit)
{
    bit_array[bit / 32] |= 1 << (bit % 32);
}

static inline void array_bit_clear(uint32_t *bit_array, uint32_t bit)
{
    bit_array[bit / 32] &= ~(1 << (bit % 32));
}

static inline uint32_t array_bit_test(const uint32_t *bit_array, uint32_t bit)
{
    return ((bit_array[bit / 32] & (1 << (bit % 32))) != 0);
}

typedef struct _sa_port_counters {
    uint64_t xmit_data_bytes;
    uint64_t rcv_data_bytes;
    uint64_t xmit_pkts;
    uint64_t rcv_pkts;
    uint32_t xmit_wait;
    uint16_t symbol_err_cnt;
    uint16_t rcv_err;
    uint16_t xmit_discards;
    uint16_t vl15_dropped;
    uint8_t  xmit_constraint_err;
} sa_port_counters_t;

#define MAX_PORTS             (g_resource_limits.port_ext_num_max)
#define MAX_LOGICAL_PORTS     MAX_PORTS + 1
#define MAX_PORTS_DB          256
#define MAX_LANES_IB          4
#define MAX_SWID_ID           7
#define CONN_TYPE_FRONT_PANEL 2

typedef enum _mlnx_port_breakout_capability_t {
    MLNX_PORT_BREAKOUT_CAPABILITY_NONE     = 0,
    MLNX_PORT_BREAKOUT_CAPABILITY_TWO      = 1,
    MLNX_PORT_BREAKOUT_CAPABILITY_FOUR     = 2,
    MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR = 3
} mlnx_port_breakout_capability_t;


typedef enum _mlnx_port_autoneg_type_t {
    AUTO_NEG_DISABLE,
    AUTO_NEG_ENABLE,
    AUTO_NEG_DEFAULT
} mlnx_port_autoneg_type_t;

#define MAX_PORT_ATTR_ADV_SPEEDS_NUM 10
#define MAX_PORT_HW_LANES            8
#define NUM_OF_HW_LANES_IN_MODULE    8

typedef struct _mlnx_port_config_t {
    uint8_t                         index;
    uint32_t                        module;
    uint32_t                        width;
    uint32_t                        hw_lanes_list[MAX_PORT_HW_LANES];
    mlnx_port_breakout_capability_t breakout_modes;
    sx_port_speed_t                 speed_bitmap;
    sx_port_log_id_t                logical;
    sai_object_id_t                 saiport;
    bool                            is_split;
    uint8_t                         split_count;
    sx_port_mapping_t               port_map;
    bool                            is_present;
    bool                            admin_state;
    uint32_t                        speed;
    uint32_t                        adv_speeds[MAX_PORT_ATTR_ADV_SPEEDS_NUM];
    uint32_t                        adv_speeds_num;
    mlnx_port_autoneg_type_t        auto_neg;
    uint8_t                         swid_id;
    uint8_t                         label_port;
    uint8_t                         split_index;
    uint8_t                         ib_port;
    bool                            sdk_port_added;
    uint8_t                         label_index;
    bool                            down_by_signal_degrade;
    sa_port_counters_t              counters_cache;
    bool                            is_fnm;
    bool                            is_maf;
    int32_t                         protocol;
    int32_t                         conn_type;
    int32_t                         remote_id;
} mlnx_port_config_t;

/**
 * @brief Port Add/Delete Event
 */
typedef enum _sai_port_event_t {
    /** Create a new active port */
    MLNX_PORT_EVENT_ADD,

    /** Delete/Invalidate an existing port */
    MLNX_PORT_EVENT_DELETE,
} mlnx_port_event_t;

#define mlnx_port_local_foreach(port, idx)    \
    for (idx = 0; idx < MAX_PORTS &&          \
         (port = &mlnx_ports_db[idx]); idx++) \
    if (port->logical)

#define mlnx_port_phy_foreach(port, idx)      \
    for (idx = 0; idx < MAX_LOGICAL_PORTS &&  \
         (port = &mlnx_ports_db[idx]); idx++) \
    if (port->is_present && port->logical)

#define mlnx_port_foreach(port, idx)                  \
    for (idx = 0; idx < (MAX_PORTS * 2) &&            \
         (port = &mlnx_ports_db[idx]); idx++)         \
    if ((port->is_present || port->sdk_port_added) && \
        (port->logical || ((idx >= (MAX_PORTS)) && port->sdk_port_added)))

typedef enum {
    BOOT_TYPE_REGULAR,
    BOOT_TYPE_WARM,
    BOOT_TYPE_FAST
} mlnx_sai_boot_type_t;

typedef enum mlnx_platform_type {
    MLNX_PLATFORM_TYPE_INVALID = 0,
    MLNX_PLATFORM_TYPE_7800    = 7800,
    MLNX_PLATFORM_TYPE_8700    = 8700,
    MLNX_PLATFORM_TYPE_9700    = 9700
} mlnx_platform_type_t;
mlnx_platform_type_t mlnx_platform_type_get(void);

#ifndef PATH_MAX
#define PATH_MAX 256
#endif /* PATH_MAX */

typedef struct _mlnx_dump_configuration_t {
    char     path[SX_API_DUMP_PATH_LEN_LIMIT];
    uint32_t max_events_to_store;
} mlnx_dump_configuration_t;

/* ib static var */
typedef enum sys_swid_profile {
    SYS_SWID_PROFILE_IB_SINGLE_SWID,
    SYS_SWID_PROFILE_IB_MULTI_SWID,
    SYS_SWID_PROFILE_IB_NAR_SINGLE_SWID,
    SYS_SWID_PROFILE_MIN = SYS_SWID_PROFILE_IB_SINGLE_SWID,
    SYS_SWID_PROFILE_MAX = SYS_SWID_PROFILE_IB_NAR_SINGLE_SWID,
    SYS_SWID_PROFILE_UNKNWON,
} sys_swid_profile_t;

typedef struct swidapi_ctx {
    int                swid_num;
    struct ibmad_port* sport;
} swidapi_t;

typedef struct sai_db {
    cl_plock_t                p_lock;
    sx_mac_addr_t             base_mac_addr;
    char                      dev_mac[18];
    uint32_t                  ports_number;
    uint32_t                  ports_configured;
    mlnx_port_config_t        ports_db[MAX_PORTS_DB * 2];
    sx_user_channel_t         callback_channel;
    bool                      issu_enabled;
    uint32_t                  acl_divider;
    mlnx_sai_boot_type_t      boot_type;
    sx_chip_types_t           sx_chip_type;
    mlnx_platform_type_t      platform_type;
    mlnx_dump_configuration_t dump_configuration;
    uint32_t                  pbhash_gre;
    bool                      breakout_mode_en;
    uint32_t                  num_of_swids;
    sys_swid_profile_t        profile;
    bool                      adaptive_routing_en;
    uint32_t                  adaptive_routing_group_cap;
    bool                      ib_routing_en;
    sai_switch_type_t         switch_type;
    swidapi_t                *swidapi_handles[MAX_SWID_ID];
    char                      ib_node_description[SX_IB_NODE_DESCRIPTION_LEN];
    uint64_t                  ib_system_image_guid;
    bool                      ib_operation_mode;
#ifndef _WIN32
    sem_t dfw_sem;
#endif
} sai_db_t;

extern sai_db_t *g_sai_db_ptr;

#define mlnx_ports_db (g_sai_db_ptr->ports_db)

mlnx_port_config_t * mlnx_port_by_idx(uint16_t id);
mlnx_port_config_t * mlnx_port_by_local_id(uint16_t local_port);

#define sai_db_read_lock()  cl_plock_acquire(&g_sai_db_ptr->p_lock)
#define sai_db_write_lock() cl_plock_excl_acquire(&g_sai_db_ptr->p_lock)
#define sai_db_unlock()     cl_plock_release(&g_sai_db_ptr->p_lock)
#define sai_db_sync()       msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC)

/* DB read lock is needed */
sai_status_t mlnx_port_by_log_id_soft(sx_port_log_id_t log_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_port_by_log_id(sx_port_log_id_t log_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_lag_by_log_id(sx_port_log_id_t log_id, mlnx_port_config_t **lag);
/* DB read lock is needed */
sai_status_t mlnx_port_by_obj_id(sai_object_id_t obj_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_port_idx_by_log_id(sx_port_log_id_t log_port_id, uint32_t *index);
/* DB read lock is needed */
sai_status_t mlnx_port_idx_by_obj_id(sai_object_id_t obj_id, uint32_t *index);
/* DB read lock is needed */
uint32_t mlnx_port_idx_get(const mlnx_port_config_t *port);

/* DB read lock is needed */
sai_status_t mlnx_port_add(mlnx_port_config_t *port);
sai_status_t mlnx_port_del(mlnx_port_config_t *port);
sai_status_t mlnx_port_config_init_mandatory(mlnx_port_config_t *port);
sai_status_t mlnx_port_config_init(mlnx_port_config_t *port);
sai_status_t mlnx_port_config_uninit(mlnx_port_config_t *port);

uint8_t mlnx_port_mac_mask_get(void);

/* DB read lock is needed */
sai_status_t mlnx_switch_get_mac(sx_mac_addr_t *mac);

#define KV_DEVICE_MAC_ADDRESS     "DEVICE_MAC_ADDRESS"
#define SAI_KEY_DUMP_STORE_PATH   "SAI_DUMP_STORE_PATH"
#define SAI_KEY_DUMP_STORE_AMOUNT "SAI_DUMP_STORE_AMOUNT"

sai_status_t mlnx_port_cb_table_init(void);

#define LINE_LENGTH 120

sai_status_t wait_for_sem(sem_t *sem_to_wait, uint32_t wait_seconds);
void SAI_dump_port(_In_ FILE *file);
sx_chip_types_t convert_chip_sxd_to_sx(sxd_chip_types_t chip_type);

sai_status_t mlnx_prm_api_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_swid_api_log_set(sx_verbosity_level_t level);

#endif /* __MLNXSAI_H_ */
