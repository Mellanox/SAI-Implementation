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
#include <sx/sdk/sx_api_adaptive_routing.h>
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
#include "config.h"

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

#ifdef ACS_OS
    #define MLNX_ACL_SKIP_EXTRA_KEYS
    #define MLNX_ACL_L3_TYPE_REDUCED
#endif

#ifdef ACS_OS
    #define MLNX_HASH_INNER_IP_PROTO_ENABLE
#endif

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

extern uint64_t test_sx_api_init_set_ms;
uint64_t time_ms_get(void);

extern sx_api_handle_t            gh_sdk;
extern sai_service_method_table_t g_mlnx_services;
extern rm_resources_t             g_resource_limits;
extern sx_log_cb_t                sai_log_cb;

sai_status_t sdk_to_sai(sx_status_t status);

extern const sai_route_api_t            mlnx_route_api;
extern const sai_virtual_router_api_t   mlnx_router_api;
extern const sai_switch_api_t           mlnx_switch_api;
extern const sai_bridge_api_t           mlnx_bridge_api;
extern const sai_port_api_t             mlnx_port_api;
extern const sai_fdb_api_t              mlnx_fdb_api;
extern const sai_neighbor_api_t         mlnx_neighbor_api;
extern const sai_next_hop_api_t         mlnx_next_hop_api;
extern const sai_next_hop_group_api_t   mlnx_next_hop_group_api;
extern const sai_router_interface_api_t mlnx_router_interface_api;
extern const sai_vlan_api_t             mlnx_vlan_api;
extern const sai_hostif_api_t           mlnx_host_interface_api;
extern const sai_acl_api_t              mlnx_acl_api;
extern const sai_qos_map_api_t          mlnx_qos_maps_api;
extern const sai_wred_api_t             mlnx_wred_api;
extern const sai_policer_api_t          mlnx_policer_api;
extern const sai_buffer_api_t           mlnx_buffer_api;
extern const sai_queue_api_t            mlnx_queue_api;
extern const sai_scheduler_api_t        mlnx_scheduler_api;
extern const sai_hash_api_t             mlnx_hash_api;
extern const sai_lag_api_t              mlnx_lag_api;
extern const sai_scheduler_group_api_t  mlnx_scheduler_group_api;
extern const sai_mirror_api_t           mlnx_mirror_api;
extern const sai_samplepacket_api_t     mlnx_samplepacket_api;
extern const sai_tunnel_api_t           mlnx_tunnel_api;
extern const sai_stp_api_t              mlnx_stp_api;
extern const sai_udf_api_t              mlnx_udf_api;
extern const sai_l2mc_group_api_t       mlnx_l2mc_group_api;
extern const sai_bmtor_api_t            mlnx_bmtor_api;
extern const sai_debug_counter_api_t    mlnx_debug_counter_api;
extern const sai_bfd_api_t              mlnx_bfd_api;
extern const sai_counter_api_t          mlnx_counter_api;
extern const sai_isolation_group_api_t  mlnx_isolation_group_api;

#define DEFAULT_ETH_SWID 0
#define DEFAULT_VRID     0
#define DEFAULT_RIF_MTU  1500

#define DEFAULT_MULTICAST_TTL_THRESHOLD 1
#define PORT_SPEED_800                  800000
#define PORT_SPEED_400                  400000
#define PORT_SPEED_200                  200000
#define PORT_SPEED_100                  100000
#define PORT_SPEED_50                   50000
#define PORT_SPEED_25                   25000
#define PORT_SPEED_56                   56000
#define PORT_SPEED_40                   40000
#define PORT_SPEED_20                   20000
#define PORT_SPEED_10                   10000
#define PORT_SPEED_1                    1000
#define PORT_SPEED_100M                 100
#define PORT_SPEED_10M                  10
#define PORT_SPEED_0                    0
#define PORT_SPEED_MAX_SP               PORT_SPEED_100
#define PORT_SPEED_MAX_SP2              PORT_SPEED_200
#define PORT_SPEED_MAX_SP3              PORT_SPEED_400
#define PORT_SPEED_MAX_SP4              PORT_SPEED_800
#define MAX_NUM_PORT_SPEEDS             14
#define MAX_NUM_PORT_INTFS              SAI_PORT_INTERFACE_TYPE_MAX
#define CPU_PORT                        0
#define ECMP_MAX_PATHS                  64
#define FG_ECMP_MAX_PATHS               4096
#define FG_ECMP_MAX_GROUPS_COUNT        (MLNX_NHG_DB_SIZE)
#define SX_DEVICE_ID                    1
#define DEFAULT_DEVICE_ID               255
#define DEFAULT_VLAN                    1
/* vlan for vports mapped to dummy .1D bridge */
#define MLNX_SAI_DUMMY_1D_VLAN_ID (1)
#define DEFAULT_TRAP_GROUP_PRIO   SX_TRAP_PRIORITY_LOW
#define DEFAULT_TRAP_GROUP_ID     0
#define RECV_ATTRIBS_NUM          4
#define FDB_NOTIF_ATTRIBS_NUM     3
#define FDB_SAVED_ACTIONS_NUM     100

#define SAI_INVALID_STP_INSTANCE (SX_MSTP_INST_ID_MAX + 1)

#define MLNX_UDF_GROUP_SIZE_MAX   (3) /* max of extraction points in one custom bytes set */
#define MLNX_UDF_GROUP_LENGTH_MAX (g_resource_limits.acl_custom_bytes_set_size_max)
#define MLNX_UDF_GROUP_COUNT_MAX  (g_resource_limits.acl_custom_bytes_set_max)
#define MLNX_UDF_GP_REG_COUNT     (g_resource_limits.gp_register_num_max)
#define MLNX_UDF_COUNT_MAX        (MLNX_UDF_GROUP_SIZE_MAX * MLNX_UDF_GROUP_COUNT_MAX)
#define MLNX_UDF_MATCH_COUNT_MAX  (MLNX_UDF_COUNT_MAX)
#define MLNX_UDF_OFFSET_MAX       (g_resource_limits.acl_custom_bytes_extraction_point_offset_max)

#define MLNX_UDF_DB_UDF_GROUP_SIZE \
    (sizeof(mlnx_udf_group_t) +    \
     sizeof(sx_acl_key_t) * MLNX_UDF_GROUP_LENGTH_MAX)
#define MLNX_UDF_DB_UDF_GROUPS_SIZE      (MLNX_UDF_DB_UDF_GROUP_SIZE * MLNX_UDF_GROUP_COUNT_MAX)
#define MLNX_UDF_DB_UDF_GROUP_UDFS_SIZE  (sizeof(mlnx_udf_list_t) + sizeof(uint32_t) * MLNX_UDF_GROUP_SIZE_MAX)
#define MLNX_UDF_DB_UDF_GROUPS_UDFS_SIZE (MLNX_UDF_DB_UDF_GROUP_UDFS_SIZE * MLNX_UDF_GROUP_COUNT_MAX)
#define MLNX_UDF_DB_UDFS_SIZE            (sizeof(mlnx_udf_t) * MLNX_UDF_COUNT_MAX)
#define MLNX_UDF_DB_MATCHES_SIZE         (sizeof(mlnx_match_t) * MLNX_UDF_MATCH_COUNT_MAX)

#define MLNX_UDF_GROUP_MASK_EMPTY (0)

#define MLNX_UDF_ACL_ATTR_COUNT  (10)
#define MLNX_UDF_ACL_ATTR_MAX_ID (MLNX_UDF_ACL_ATTR_COUNT - 1)

#define MLNX_EXT_POINT_MAX_NUM (4)

#define MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS 2

#define MLNX_COUNTER_MAX_HOSTIF_TRAPS 60
#define MLNX_COUNTERS_DB_SIZE         1000

#define MLNX_MIRROR_SAMPLE_RATE_DISABLE_SAMPLING (1)
#define MLNX_MIRROR_SAMPLE_RATE_STOP_MIRRORING   (0)
#define MLNX_MIRROR_SAMPLE_RATE_MAX              (0xFFFFFF)
#define mlnx_udf_db                              (g_sai_acl_db_ptr->udf_db)
#define udf_db_group_ptr(index)                         \
    ((mlnx_udf_group_t*)((uint8_t*)mlnx_udf_db.groups + \
                         (MLNX_UDF_DB_UDF_GROUP_SIZE * index)))
#define udf_db_group_udfs_ptr(index)                        \
    ((mlnx_udf_list_t*)((uint8_t*)mlnx_udf_db.groups_udfs + \
                        (MLNX_UDF_DB_UDF_GROUP_UDFS_SIZE * index)))
#define udf_db_udf(index)   (mlnx_udf_db.udfs[index])
#define udf_db_match(index) (mlnx_udf_db.matches[index])

typedef uint64_t udf_group_mask_t;

#define MLNX_SX_GP_REG_TO_FLEX_ACL_KEY(reg)                            \
    ((((int32_t)(reg) - SX_GP_REGISTER_0_E) > MLNX_UDF_GP_REG_COUNT) ? \
     (FLEX_ACL_KEY_GP_REGISTER_LAST + 1) :                             \
     ((int32_t)(reg) - SX_GP_REGISTER_0_E + FLEX_ACL_KEY_GP_REGISTER_0))

#define MLNX_FLEX_ACL_KEY_TO_SX_GP_REG(key)                                      \
    ((((((int32_t)(key) - FLEX_ACL_KEY_GP_REGISTER_0) < SX_GP_REGISTER_0_E) ||   \
       ((int32_t)(key) - FLEX_ACL_KEY_GP_REGISTER_0) > MLNX_UDF_GP_REG_COUNT)) ? \
     (SX_GP_REGISTER_LAST_E) :                                                   \
     ((int32_t)(key) - FLEX_ACL_KEY_GP_REGISTER_0))

#define safe_free(var) \
    if (var) {         \
        free(var);     \
        var = NULL;    \
    }                  \

#define ARRAY_SIZE(_x) (sizeof(_x) / sizeof(_x[0]))

/* TODO: Remove it, this is really common thing to have a vendor specific name */
#define MLNX_SAI_ARRAY_LEN(_x) (sizeof(_x) / sizeof(_x[0]))

#define INVALID_INDEX (-1)

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define EXTENDED_DATA_SIZE 2

typedef enum {
    MLNX_SHM_RM_ARRAY_TYPE_INVALID,
    MLNX_SHM_RM_ARRAY_TYPE_MIN,
    MLNX_SHM_RM_ARRAY_TYPE_RIF = MLNX_SHM_RM_ARRAY_TYPE_MIN,
    MLNX_SHM_RM_ARRAY_TYPE_BRIDGE,
    MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER,
    MLNX_SHM_RM_ARRAY_TYPE_BFD_SESSION,
    MLNX_SHM_RM_ARRAY_TYPE_GP_REG,
    MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP,
    MLNX_SHM_RM_ARRAY_TYPE_COUNTER,
    MLNX_SHM_RM_ARRAY_TYPE_NHG,
    MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER,
    MLNX_SHM_RM_ARRAY_TYPE_ECMP_NHG_MAP,
    MLNX_SHM_RM_ARRAY_TYPE_POLICER,
    MLNX_SHM_RM_ARRAY_TYPE_MAX = MLNX_SHM_RM_ARRAY_TYPE_POLICER,
    MLNX_SHM_RM_ARRAY_TYPE_SIZE
} mlnx_shm_rm_array_type_t;
typedef sai_status_t (*mlnx_shm_rm_size_get_fn)(_Out_ size_t *size);
typedef bool (*mlnx_shm_rm_array_cmp_fn)(_In_ const void *elem, _In_ const void *data);
typedef struct _mlnx_shm_rm_array_info_t {
    size_t elem_size;
    size_t elem_count; /* initialized via elem_count_fn()*/
    size_t offset_to_head;
} mlnx_shm_rm_array_info_t;
typedef struct _mlnx_shm_rm_array_init_info_t {
    size_t                  elem_size;
    mlnx_shm_rm_size_get_fn elem_count_fn;
    size_t                  elem_count; /* initialized via elem_count_fn()*/
} mlnx_shm_rm_array_init_info_t;
typedef uint16_t mlnx_shm_array_canary_t;
typedef struct _mlnx_shm_array_t {
    bool                    is_used;
    mlnx_shm_array_canary_t canary;
} mlnx_shm_array_hdr_t;

PACKED(struct _mlnx_shm_rm_array_idx_t {
    mlnx_shm_rm_array_type_t type: 6;
    uint32_t idx: 26;
}, );
typedef struct _mlnx_shm_rm_array_idx_t mlnx_shm_rm_array_idx_t;
#define MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED                                    \
    ((mlnx_shm_rm_array_idx_t) {.type = MLNX_SHM_RM_ARRAY_TYPE_INVALID, .idx = \
                                    0})
#define MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(rm_idx)    \
    (((rm_idx).type == MLNX_SHM_RM_ARRAY_TYPE_INVALID) && \
     ((rm_idx).idx == 0))

#define MLNX_SHM_RM_ARRAY_IDX_EQUAL(a, b) \
    ((a.type == b.type) && (a.idx == b.idx))

sai_status_t mlnx_shm_rm_idx_validate(_In_ mlnx_shm_rm_array_idx_t idx);
sai_status_t mlnx_shm_rm_array_alloc(_In_ mlnx_shm_rm_array_type_t  type,
                                     _Out_ mlnx_shm_rm_array_idx_t *idx,
                                     _Out_ void                   **elem);
sai_status_t mlnx_shm_rm_array_free(_In_ mlnx_shm_rm_array_idx_t idx);
uint32_t mlnx_shm_rm_array_free_entries_count(_In_ mlnx_shm_rm_array_type_t type);
sai_status_t mlnx_shm_rm_array_find(_In_ mlnx_shm_rm_array_type_t  type,
                                    _In_ mlnx_shm_rm_array_cmp_fn  cmp_fn,
                                    _In_ mlnx_shm_rm_array_idx_t   start_idx,
                                    _In_ const void               *data,
                                    _Out_ mlnx_shm_rm_array_idx_t *idx,
                                    _Out_ void                   **elem);
sai_status_t mlnx_shm_rm_array_idx_to_ptr(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ void                   **elem);
sai_status_t mlnx_shm_rm_array_type_idx_to_ptr(_In_ mlnx_shm_rm_array_type_t type,
                                               _In_ uint32_t                 idx,
                                               _Out_ void                  **elem);
sai_status_t mlnx_shm_rm_array_type_ptr_to_idx(_In_ mlnx_shm_rm_array_type_t  type,
                                               _In_ const void               *ptr,
                                               _Out_ mlnx_shm_rm_array_idx_t *idx);
uint32_t mlnx_shm_rm_array_size_get(_In_ mlnx_shm_rm_array_type_t type);

static inline sx_router_ecmp_hash_type_t ecmp_hash_type_sai_2_sx(int32_t sai_type)
{
    if (sai_type == SAI_HASH_ALGORITHM_CRC_CCITT) {
        return SX_ROUTER_ECMP_HASH_TYPE_CRC2;
    } else {
        return (sx_router_ecmp_hash_type_t)sai_type;
    }
}

static inline int32_t ecmp_hash_type_sx_2_sai(sx_router_ecmp_hash_type_t sx_type)
{
    if (sx_type == SX_ROUTER_ECMP_HASH_TYPE_CRC2) {
        return SAI_HASH_ALGORITHM_CRC_CCITT;
    } else {
        return (int32_t)sx_type;
    }
}

static inline sx_lag_hash_type_t lag_hash_type_sai_2_sx(int32_t sai_type)
{
    if (sai_type == SAI_HASH_ALGORITHM_CRC_CCITT) {
        return SX_LAG_HASH_TYPE_CRC2;
    } else {
        return (sx_lag_hash_type_t)sai_type;
    }
}

static inline int32_t lag_hash_type_sx_2_sai(sx_lag_hash_type_t sx_type)
{
    if (sx_type == SX_LAG_HASH_TYPE_CRC2) {
        return SAI_HASH_ALGORITHM_CRC_CCITT;
    } else {
        return (int32_t)sx_type;
    }
}

sx_status_t get_chip_type(enum sx_chip_types* chip_type);

sai_status_t wait_for_sem(sem_t *sem_to_wait, uint32_t wait_seconds);

#define MLNX_SHM_POOL_ELEM_FX_HANDLE_SIZE 524552

typedef struct _mlnx_shm_pool_data_t {
    uint8_t fx_handle_mem[MLNX_SHM_POOL_ELEM_FX_HANDLE_SIZE];
} mlnx_shm_pool_t;

#define HOSTIF_TABLE_ENTRY_HOSTIF_IDX_BITS (13)
PACKED(struct _mlnx_object_id_t {
    sai_uint8_t object_type;
    PACKED(struct {
        uint8_t sub_type: 3;
        uint8_t swid: 5;
    }, field);
    union {
        sai_uint8_t bytes[EXTENDED_DATA_SIZE];
        PACKED(struct {
            uint16_t lag_id;
        }, lag);
        PACKED(struct {
            uint16_t id;
        }, stp);
        PACKED(struct {
            uint16_t id;
        }, vlan);
        PACKED(struct {
            uint16_t id;
        }, trap);
        PACKED(struct {
            uint16_t type;
        }, bridge_port);
        PACKED(union {
            sx_bridge_id_t sx_bridge_id;
        }, bridge);
        PACKED(struct {
            uint16_t byte_flag: 1;
            uint16_t packet_flag: 1;
            uint16_t table_db_idx: 14;
        }, flow_counter_type);
        PACKED(union {
            uint16_t db_idx;
        }, l2mc_group_member);
        PACKED(union {
            uint16_t is_db_entry;
        }, nexthop_db);
        PACKED(struct {
            uint16_t isolation_group_db_idx;
        }, isolation_group_member);
        PACKED(struct {
            uint16_t channel_type: 3;
            uint16_t hostif_db_idx: HOSTIF_TABLE_ENTRY_HOSTIF_IDX_BITS;
        }, hostif_table_entry);
    } ext;
    union {
        bool is_created;
        sx_router_id_t router_id;
        sx_port_log_id_t log_port_id;
        sx_mstp_inst_id_t stp_inst_id;
        uint16_t vlan_id;
        sai_uint32_t u32;
        sai_uint32_t bridge_rif_idx;
        sx_flow_counter_id_t flow_counter_id;
        mlnx_shm_rm_array_idx_t rif_db_idx;
        mlnx_shm_rm_array_idx_t bridge_db_idx;
        mlnx_shm_rm_array_idx_t debug_counter_db_idx;
        mlnx_shm_rm_array_idx_t bfd_db_idx;
        mlnx_shm_rm_array_idx_t encap_nexthop_db_idx;
        mlnx_shm_rm_array_idx_t counter_db_idx;
        mlnx_shm_rm_array_idx_t nhg_db_idx;
        mlnx_shm_rm_array_idx_t nhgm_db_idx;
        mlnx_shm_rm_array_idx_t policer_db_idx;
        uint32_t isolation_group_db_idx;
        PACKED(struct {
            uint32_t db_idx;
        }, l2mc_group);
        PACKED(struct {
            uint16_t port_vlan_db_idx;
            uint16_t trap_db_idx;
        }, hostif_table_entry);
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
typedef enum mlnx_acl_pbs_type {
    MLNX_ACL_PBS_TYPE_INVALID,
    MLNX_ACL_PBS_TYPE_MAP,
    MLNX_ACL_PBS_TYPE_BPORT,
    MLNX_ACL_PBS_TYPE_MCGROUP,
} mlnx_acl_pbs_type_t;
typedef struct _mlnx_acl_pbs_entry_t {
    sx_acl_pbs_id_t pbs_id;
    uint32_t        ref_counter;
} mlnx_acl_pbs_entry_t;
/* Used in case RIF type bridge */
typedef enum mlnx_rif_type_ {
    MLNX_RIF_TYPE_DEFAULT,
    MLNX_RIF_TYPE_BRIDGE,
} mlnx_rif_type_t;
typedef struct _mlnx_rif_sx_data_t {
    sx_router_interface_t  rif_id;
    sx_router_id_t         vrf_id;
    sx_router_counter_id_t counter;
} mlnx_rif_sx_data_t;
typedef struct _mlnx_rif_mac_data_t {
    bool          additional_mac_is_used;
    sx_mac_addr_t additional_mac_addr;
} mlnx_rif_mac_data_t;
typedef struct _mlnx_rif_db_t {
    mlnx_shm_array_hdr_t mlnx_array;
    mlnx_rif_sx_data_t   sx_data;
    mlnx_rif_mac_data_t  mac_data;
} mlnx_rif_db_t;

extern bool g_additional_mac_enabled;

sai_status_t mlnx_bmtor_rif_event_add(_In_ sx_router_interface_t sx_rif);
sai_status_t mlnx_bmtor_rif_event_del(_In_ sx_router_interface_t sx_rif);

/* This DB structure is for the special type of router interface - bridge router interface,
 * if in case it will be needed to store any kind of RIF in the DB then it is better to rename
 * it to the mlnx_rif_t and use it */
typedef struct mlnx_bridge_rif_ {
    sx_interface_attributes_t   intf_attribs;
    sx_router_interface_param_t intf_params;
    sx_router_interface_state_t intf_state;
    sx_bridge_id_t              bridge_id;
    bool                        is_created;  /* if rif is created via SDK (bridged) */
    bool                        is_used;
    mlnx_rif_sx_data_t          sx_data;
    uint32_t                    index;
    mlnx_rif_mac_data_t         mac_data;
} mlnx_bridge_rif_t;
typedef struct mlnx_bridge_port_ {
    uint32_t               index;
    bool                   is_present;
    bool                   admin_state;
    sx_port_log_id_t       parent;
    sx_port_log_id_t       logical;
    uint32_t               tunnel_idx;
    sx_bridge_id_t         bridge_id;
    sai_bridge_port_type_t port_type;
    uint16_t               rif_index;
    sx_vlan_id_t           vlan_id;
    uint16_t               vlans;
    uint32_t               fdbs;
    uint16_t               stps;
    mlnx_acl_pbs_entry_t   pbs_entry;
    uint32_t               l2mc_group_ref;
} mlnx_bridge_port_t;

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

#define MLNX_QOS_MAP_COLOR_MAX       2
#define MLNX_QOS_MAP_TYPES_MAX       10
#define MLNX_QOS_MAP_CODES_MAX       (SX_COS_PORT_DSCP_MAX + 1)
#define MLNX_QOS_MAP_PFC_PG_INDEX    0
#define MLNX_QOS_MAP_PFC_QUEUE_INDEX 1

/* TODO: Add MPLS support here */
typedef union {
    sx_cos_priority_color_t prio_color[MLNX_QOS_MAP_CODES_MAX];
    sx_cos_pcp_dei_t        pcp_dei[MLNX_QOS_MAP_CODES_MAX];
    sx_cos_dscp_t           dscp[MLNX_QOS_MAP_CODES_MAX];
    sx_cos_traffic_class_t  queue[MLNX_QOS_MAP_CODES_MAX];
    uint8_t                 pg[MLNX_QOS_MAP_CODES_MAX];
    uint8_t                 pfc[MLNX_QOS_MAP_CODES_MAX];
} mlnx_qos_map_params_t;
typedef struct _mlnx_qos_map_t {
    sai_qos_map_type_t    type;
    mlnx_qos_map_params_t from;
    mlnx_qos_map_params_t to;
    uint8_t               count;
    bool                  is_used;
    bool                  is_set;
} mlnx_qos_map_t;
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
typedef size_t (*key_printer_fn)(const sai_object_key_t *, char *, size_t);
typedef struct _mlnx_obj_type_attrs_info_t {
    const sai_vendor_attribute_entry_t         *vendor_data;
    const mlnx_obj_type_attrs_enums_info_t      enums_info;
    const mlnx_obj_type_stats_capability_info_t stats_capability;
    key_printer_fn                              printer;
} mlnx_obj_type_attrs_info_t;

#define bulk_context_cond_mutex_lock(mutex)                                    \
    do { if (pthread_mutex_lock(&mutex) != 0) {                                \
             /*SX_LOG_ERR("Failed to lock bulk counter mutex\n");*/ exit(1); } \
    } while (0)

#define bulk_context_cond_mutex_unlock(mutex)                                    \
    do { if (pthread_mutex_unlock(&mutex) != 0) {                                \
             /*SX_LOG_ERR("Failed to unlock bulk counter mutex\n");*/ exit(1); } \
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
#define PP_NARG(...)                                                                                                    \
    EXPAND(_xPP_NARGS_IMPL(__VA_ARGS__, 30, 29, 28, 27, 26, 25, 25, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, \
                           10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
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

bool mlnx_chip_is_spc(void);
bool mlnx_chip_is_spc2(void);
bool mlnx_chip_is_spc3(void);
bool mlnx_chip_is_spc4(void);
bool mlnx_chip_is_spc2or3(void);
bool mlnx_chip_is_spc2or3or4(void);
bool mlnx_chip_is_spc1or2or3(void);

typedef struct _mlnx_counter_t {
    mlnx_shm_array_hdr_t array_hdr;
    sx_flow_counter_id_t sx_flow_counter;
    sai_object_id_t      hostif_trap_ids[MLNX_COUNTER_MAX_HOSTIF_TRAPS];
    uint32_t             hostif_trap_ids_cnt;
} mlnx_counter_t;

sai_status_t sai_attribute_short_name_fetch(_In_ sai_object_type_t object_type,
                                            _In_ sai_attr_id_t     attr_id,
                                            _Out_ const char     **attr_short_name);
sai_status_t check_port_type_attr(const sai_object_id_t *ports,
                                  uint32_t               count,
                                  attr_port_type_check_t check,
                                  sai_attr_id_t          attr_id,
                                  uint32_t               idx);
sai_status_t check_attribs_on_create_without_oid(_In_ uint32_t               attr_count,
                                                 _In_ const sai_attribute_t *attr_list,
                                                 _In_ sai_object_type_t      object_type);
sai_status_t check_attribs_on_create(_In_ uint32_t               attr_count,
                                     _In_ const sai_attribute_t *attr_list,
                                     _In_ sai_object_type_t      object_type,
                                     _In_ sai_object_id_t       *oid);
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
sai_status_t sai_set_attribute(_In_ const sai_object_key_t *key,
                               _In_ sai_object_type_t       object_type,
                               _In_ const sai_attribute_t  *attr);
sai_status_t sai_get_attributes(_In_ const sai_object_key_t *key,
                                _In_ sai_object_type_t       object_type,
                                _In_ uint32_t                attr_count,
                                _Inout_ sai_attribute_t     *attr_list);
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

#define MAX_KEY_STR_LEN        150
#define MAX_VALUE_STR_LEN      100
#define MAX_LIST_VALUE_STR_LEN 1000

sai_status_t sai_attr_list_to_str(_In_ uint32_t               attr_count,
                                  _In_ const sai_attribute_t *attr_list,
                                  _In_ sai_object_type_t      object_type,
                                  _In_ uint32_t               max_length,
                                  _Out_ char                 *list_str);
sai_status_t sai_ipprefix_to_str(_In_ sai_ip_prefix_t value, _In_ uint32_t max_length, _Out_ char *value_str);
sai_status_t sai_ipv4_to_str(_In_ sai_ip4_t value,
                             _In_ uint32_t  max_length,
                             _Out_ char    *value_str,
                             _Out_opt_ int *chars_written);
sai_status_t sai_ipv6_to_str(_In_ sai_ip6_t value,
                             _In_ uint32_t  max_length,
                             _Out_ char    *value_str,
                             _Out_opt_ int *chars_written);
sai_status_t sai_ipaddr_to_str(_In_ sai_ip_address_t value,
                               _In_ uint32_t         max_length,
                               _Out_ char           *value_str,
                               _Out_opt_ int        *chars_written);
sai_status_t sai_qos_map_to_str(_In_ const sai_qos_map_list_t *qos_map,
                                _In_ sai_qos_map_type_t        type,
                                _In_ uint32_t                  max_length,
                                _Out_ char                    *value_str);
sai_status_t mlnx_translate_sai_trap_action_to_sdk(sai_int32_t       action,
                                                   sx_trap_action_t *trap_action,
                                                   uint32_t          param_index,
                                                   bool              is_l2_trap);
sai_status_t mlnx_translate_sai_router_action_to_sdk(sai_int32_t         action,
                                                     sx_router_action_t *router_action,
                                                     uint32_t            param_index);
sai_status_t mlnx_translate_sdk_router_action_to_sai(sx_router_action_t   router_action,
                                                     sai_packet_action_t *sai_action);
sai_status_t mlnx_translate_sai_stats_mode_to_sdk(sai_stats_mode_t sai_mode, sx_access_cmd_t *sdk_mode);

sai_status_t mlnx_translate_sai_action_to_sdk(sai_int32_t                  action,
                                              sx_fdb_uc_mac_addr_params_t *mac_entry,
                                              uint32_t                     param_index);

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

sai_status_t mlnx_log_port_to_object(sx_port_log_id_t port_id, sai_object_id_t *object_id);

bool mlnx_ip_addr_are_equal(_In_ const sai_ip_addr_family_t family1,
                            _In_ const sai_ip_addr_t       *addr1,
                            _In_ const sai_ip_addr_family_t family2,
                            _In_ const sai_ip_addr_t       *addr2);

bool mlnx_is_valid_ip_address(const sai_ip_address_t *sai_addr);
bool mlnx_is_ip_zero(const sai_ip_address_t *sai_addr);
bool sdk_is_valid_ip_address(const sx_ip_addr_t *sdk_addr);

bool mlnx_route_entries_are_equal(_In_ const sai_route_entry_t *u1, _In_ const sai_route_entry_t *u2);
bool mlnx_neighbor_entries_are_equal(_In_ const sai_neighbor_entry_t *u1, _In_ const sai_neighbor_entry_t *u2);

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sai_ip_address_to_sdk(_In_ const sai_ip_address_t *sai_addr, _Out_ sx_ip_addr_t *sdk_addr);
_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sdk_ip_address_to_sai(_In_ const sx_ip_addr_t *sdk_addr, _Out_ sai_ip_address_t *sai_addr);
_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sai_ip_prefix_to_sdk(_In_ const sai_ip_prefix_t *sai_prefix,
                                                 _Out_ sx_ip_prefix_t       *sdk_prefix);
_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sdk_ip_prefix_to_sai(_In_ const sx_ip_prefix_t *sdk_prefix,
                                                 _Out_ sai_ip_prefix_t     *sai_prefix);

sai_status_t mlnx_qos_map_set_default(_Inout_ mlnx_qos_map_t *qos_map);
_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_qos_map_get_by_id(_In_ sai_object_id_t obj_id, _Out_ mlnx_qos_map_t **qos_map);

sai_status_t mlnx_port_qos_map_apply(_In_ const sai_object_id_t    port,
                                     _In_ const sai_object_id_t    qos_map_id,
                                     _In_ const sai_qos_map_type_t qos_map_type);

sai_status_t mlnx_get_hostif_packet_data(sx_receive_info_t *receive_info, uint32_t *attr_num, sai_attribute_t *attr);

sai_status_t mlnx_netdev_restore(void);

sai_status_t mlnx_fdb_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_host_interface_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_neighbor_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_nexthop_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_nexthop_group_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_port_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_rif_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_route_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_router_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_switch_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_utils_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_utils_eth_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_vlan_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_acl_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_qos_map_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_wred_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_queue_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_policer_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_scheduler_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_hash_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_lag_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_scheduler_group_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_mirror_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_tunnel_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_samplepacket_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_stp_log_set(sx_verbosity_level_t severity);
sai_status_t mlnx_bridge_log_set(sx_verbosity_level_t severity);
sai_status_t mlnx_udf_log_set(sx_verbosity_level_t severity);
sai_status_t mlnx_l2mc_group_log_set(sx_verbosity_level_t severity);
sai_status_t mlnx_bmtor_log_set(sx_verbosity_level_t severity);
sai_status_t mlnx_debug_counter_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_bfd_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_counter_log_set(sx_verbosity_level_t level);
sai_status_t mlnx_isolation_group_log_set(sx_verbosity_level_t level);
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
sai_status_t mlnx_fill_vlanlist(const sai_vlan_id_t *data, uint32_t count, sai_vlan_list_t *list);
sai_status_t mlnx_fill_aclresourcelist(const sai_acl_resource_t *data, uint32_t count, sai_acl_resource_list_t *list);
sai_status_t mlnx_fill_saistatcapabilitylist(const sai_stat_capability_t *data,
                                             uint32_t                     count,
                                             sai_stat_capability_list_t  *list);
sai_status_t mlnx_attribute_value_list_size_check(_Inout_ uint32_t *out_size, _In_ uint32_t in_size);

sai_status_t mlnx_wred_apply_to_queue_oid(_In_ sai_object_id_t wred_id, _In_ sai_object_id_t queue_oid);
sai_status_t mlnx_wred_init();

sai_status_t mlnx_scheduler_to_queue_apply(sai_object_id_t scheduler_id, sai_object_id_t queue_id);

sai_status_t mlnx_scheduler_to_port_apply_unlocked(sai_object_id_t scheduler_id, sai_object_id_t port_id);
sai_status_t mlnx_scheduler_to_port_apply(sai_object_id_t scheduler_id, sai_object_id_t port_id);
/* DB write lock is needed */
sai_status_t mlnx_scheduler_to_group_apply(sai_object_id_t scheduler_id, sai_object_id_t group_id);

sai_status_t mlnx_create_queue_object(_In_ sx_port_log_id_t port_id, _In_ uint8_t index, _Out_ sai_object_id_t *id);
_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_queue_parse_id(_In_ sai_object_id_t id, _Out_ sx_port_log_id_t *port_id, _Out_ uint8_t *queue_index);
sai_status_t mlnx_create_sched_group(_In_ sx_port_log_id_t  port_id,
                                     _In_ uint8_t           level,
                                     _In_ uint8_t           index,
                                     _Out_ sai_object_id_t *id);
_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_sched_group_parse_id(_In_ sai_object_id_t    id,
                                       _Out_ sx_port_log_id_t *port_id_ptr,
                                       _Out_ uint8_t          *level_ptr,
                                       _Out_ uint8_t          *index_ptr);

sai_status_t mlnx_sched_group_parent_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);

sai_status_t mlnx_sched_group_parent_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);

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

sai_status_t mlnx_fdb_action_save(_In_ const sai_fdb_entry_t *entry, _In_ sai_packet_action_t action);
void mlnx_fdb_action_clear(_In_ const sai_fdb_entry_t *entry);
void mlnx_fdb_route_action_clear_unlocked(_In_ sai_object_type_t type, _In_ const void        *entry);
void mlnx_fdb_action_fetch(_In_ const sai_fdb_entry_t *entry, _Out_ void *entry_action);

bool mlnx_is_mac_empty(_In_ const sai_mac_t mac);
typedef enum _mlnx_acl_bind_point_type_t {
    MLNX_ACL_BIND_POINT_TYPE_INGRESS_DEFAULT,
    MLNX_ACL_BIND_POINT_TYPE_EGRESS_DEFAULT,
    MLNX_ACL_BIND_POINT_TYPE_INGRESS_PORT,
    MLNX_ACL_BIND_POINT_TYPE_EGRESS_PORT,
    MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG,
    MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG,
    MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE,
    MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE,
    MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN,
    MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN,
} mlnx_acl_bind_point_type_t;
typedef enum _acl_event_type_t {
    ACL_EVENT_TYPE_PORT_LAG_ADD,
    ACL_EVENT_TYPE_PORT_LAG_DEL,
    ACL_EVENT_TYPE_LAG_MEMBER_ADD,
    ACL_EVENT_TYPE_LAG_MEMBER_DEL,
} acl_event_type_t;
typedef struct _acl_index_t {
    sai_object_type_t acl_object_type;
    uint32_t          acl_db_index;
} acl_index_t;

sai_status_t mlnx_acl_init(void);
sai_status_t mlnx_vxlan_udp_srcport_acl_add(uint32_t tunnel_db_idx);
sai_status_t mlnx_vxlan_udp_srcport_acl_update(uint32_t tunnel_db_idx);
sai_status_t mlnx_vxlan_udp_srcport_acl_remove(uint32_t tunnel_db_idx);
sai_status_t mlnx_vxlan_srcport_config_update(bool on_create_set, uint32_t tunnel_db_idx,
                                              sai_tunnel_vxlan_udp_sport_mode_t src_port_mode,
                                              int32_t src_port_base, int8_t src_port_mask);
sai_status_t mlnx_vxlan_srcport_user_defined_set(uint32_t tunnel_db_idx, int32_t sport_base,
                                                 int8_t sport_mask, bool acl_created);

sai_status_t mlnx_acl_deinit(void);
sai_status_t mlnx_acl_disconnect(void);
sai_status_t mlnx_acl_bind_point_set(_In_ const sai_object_key_t      *key,
                                     _In_ const sai_attribute_value_t *value,
                                     void                             *arg);
sai_status_t mlnx_acl_bind_point_attrs_check_and_fetch(_In_ sai_object_id_t            acl_object_id,
                                                       _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                       _In_ uint32_t                   attr_index,
                                                       _Out_ acl_index_t              *acl_index);
sai_status_t mlnx_acl_port_lag_rif_bind_point_set(_In_ sai_object_id_t            target,
                                                  _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                                  _In_ acl_index_t                acl_index);
sai_status_t mlnx_acl_vlan_bind_point_set(_In_ sai_object_id_t            vlan_oid,
                                          _In_ mlnx_acl_bind_point_type_t bind_point_type,
                                          _In_ acl_index_t                acl_index);
sai_status_t mlnx_acl_rif_bind_point_clear(_In_ sai_object_id_t rif);
sai_status_t mlnx_acl_vlan_bind_point_clear(_In_ sai_object_id_t vlan_oid);
sai_status_t mlnx_acl_bind_point_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg);
uint32_t mlnx_acl_action_types_count_get(void);
sai_status_t mlnx_acl_stage_action_types_list_get(_In_ sai_acl_stage_t stage, _Out_ sai_s32_list_t *list);
sai_status_t mlnx_acl_db_free_entries_get(_In_ sai_object_type_t resource_type, _Out_ uint32_t         *free_entries);
sai_status_t mlnx_acl_mirror_action_policer_update(_In_ sx_span_session_id_t sx_span_session_id);
sai_status_t mlnx_acl_mirror_action_sample_rate_update(_In_ sx_span_session_id_t sx_span_session_id,
                                                       uint32_t                  sample_rate);
sai_status_t mlnx_acl_isolation_group_update(_In_ sai_object_id_t         acl_entry_id,
                                             _In_ const sx_port_log_id_t *log_port_list,
                                             _In_ const uint32_t          log_port_count);
sai_status_t mlnx_acl_isolation_group_update_not_locked(_In_ sai_object_id_t         acl_entry_id,
                                                        _In_ const sx_port_log_id_t *log_port_list,
                                                        _In_ const uint32_t          log_port_count);
#define acl_global_lock()   cl_plock_excl_acquire(&g_sai_acl_db_ptr->acl_settings_tbl->lock)
#define acl_global_unlock() cl_plock_release(&g_sai_acl_db_ptr->acl_settings_tbl->lock)
sai_status_t mlnx_bulk_counter_init(void);
sai_status_t mlnx_bulk_counter_deinit(void);


typedef struct _mlnx_mstp_inst_t {
    bool     is_used;
    uint32_t vlan_count;
} mlnx_mstp_inst_t;

sai_status_t mlnx_hash_initialize(void);
bool mlnx_sai_hash_check_optimized_hash_use_case(uint32_t hash_index, uint32_t fields_num);

bool mlnx_stp_is_initialized();
sai_status_t mlnx_stp_preinitialize();
sai_status_t mlnx_stp_initialize();
sai_status_t mlnx_stp_port_state_set_impl(_In_ sx_port_log_id_t          port,
                                          _In_ sx_mstp_inst_port_state_t state,
                                          _In_ sx_mstp_inst_id_t         mstp_instance);

sai_status_t sai_fx_uninitialize(void);

/* Helper for mlnx_mstp_inst_db */
mlnx_mstp_inst_t * get_stp_db_entry(sx_mstp_inst_id_t sx_stp_id);
#define END_TRAP_INFO_ID 0xFFFFFFFF

sai_status_t mlnx_translate_sdk_trap_to_sai(_In_ sx_trap_id_t      sdk_trap_id,
                                            _Out_ const char     **trap_name,
                                            _Out_ sai_object_id_t *trap_oid);
#define MAX_SDK_TRAPS_PER_SAI_TRAP 6
sai_status_t mlnx_translate_sai_trap_to_sdk(_In_ sai_object_id_t trap_oid,
                                            _Out_ uint8_t       *sdk_traps_num,
                                            _Out_ sx_trap_id_t(*sx_trap_id)[MAX_SDK_TRAPS_PER_SAI_TRAP]);

bool is_action_trap(sai_packet_action_t action);
bool is_action_forward(sai_packet_action_t action);

sai_status_t mlnx_get_user_defined_trap_by_prio(sai_object_type_t  type,
                                                sx_trap_priority_t prio,
                                                sai_object_id_t   *trap_oid);
sai_status_t mlnx_get_user_defined_trap_acl_sx_trap_id(sai_object_id_t trap, sx_trap_id_t *sx_trap_id);

bool mlnx_is_hostif_trap_valid(sai_object_id_t trap);
bool mlnx_is_hostif_user_defined_trap_valid_for_set(sai_object_type_t obj_type, sai_object_id_t trap);

sai_status_t mlnx_trap_refcount_decrease(sai_object_id_t trap);
sai_status_t mlnx_trap_refcount_increase(sai_object_id_t trap);

sai_status_t mlnx_get_user_defined_trap_prio(sai_object_type_t type, sai_object_id_t trap, sx_trap_priority_t *prio);
sai_status_t mlnx_trap_refcount_decrease_by_prio(sai_object_type_t obj_type, sx_trap_priority_t trap_prio);

typedef struct _mlnx_trap_info_t {
    uint32_t            trap_type;
    uint8_t             sdk_traps_num;
    sx_trap_id_t        sdk_trap_ids[MAX_SDK_TRAPS_PER_SAI_TRAP];
    sai_packet_action_t action;
    const char         *trap_name;
    sai_object_type_t   object_type;
    bool                is_l2_trap;
} mlnx_trap_info_t;
extern const mlnx_trap_info_t mlnx_traps_info[];

#define MLNX_L2_TRAP     true
#define MLNX_NON_L2_TRAP false

#define MAX_SCHED_LEVELS       2
#define MAX_SCHED_CHILD_GROUPS 8
#define MAX_ETS_ELEMENTS       (g_resource_limits.cos_port_ets_elements_num)

#define MAX_VLANS (SXD_VID_MAX + 1)

#define PG0_PORT_IDX          (0)
#define PG9_PORT_IDX          (9)
#define MAX_PGS_INTERNAL_CONF (2)

/* PG9 default value differs for port with 8 lanes and port with less than 8 lanes */
#define PG9_VAL_IDX_LESS_8_LANES (0)
#define PG9_VAL_IDX_8_LANES      (1)
#define MAX_PG9_VAL_NUMBER       (2)

#define MAX_PORTS           (g_resource_limits.port_ext_num_max)
#define MAX_PORTS_DB        258
#define MAX_BRIDGES_1D      1000
#define MAX_VPORTS          (MAX_BRIDGES_1D * MAX_PORTS_DB)
#define MAX_BRIDGE_1Q_PORTS (MAX_PORTS_DB * 2) /* Ports and LAGs */
#define MAX_BRIDGE_RIFS     550 /* 256 for VXLAN VNETs + some spare */
#define MAX_BRIDGE_PORTS    (MAX_VPORTS + MAX_BRIDGE_1Q_PORTS + MAX_BRIDGE_RIFS)
#define MAX_LANES_SPC1_2    4
#define MAX_LANES_SPC3_4    8
#define MAX_HOSTIFS         1000
#define MAX_TRAP_GROUPS     32
#define MIN_SX_BRIDGE_ID    0x1000

#define HEALTH_COUNTER_PATH "/sys/module/sx_core/health_check_running_counter"

#define SENTINEL_BUFFER_DB_ENTRY_INDEX 0

#define MLNX_FDB_LEARNING_NO_LIMIT_VALUE (0)
#define MLNX_FDB_IS_LEARNING_LIMIT_EXISTS(limit) ((limit) != MLNX_FDB_LEARNING_NO_LIMIT_VALUE)

#define MLNX_FDB_LIMIT_SAI_TO_SX(limit) (MLNX_FDB_IS_LEARNING_LIMIT_EXISTS(limit) ? (limit) : SX_FDB_UC_NO_LIMIT)
#define MLNX_FDB_LIMIT_SX_TO_SAI(sx_limit) \
    (SX_FDB_IS_LIMIT_EXIST(sx_limit) ?     \
     (sx_limit) : MLNX_FDB_LEARNING_NO_LIMIT_VALUE)

/* Port Shared (Headroom) Buffer profile defaults */
#define SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_MIN_SIZE      (2 * 1440U)
#define SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_XON_INFINITE  (0xffff)
#define SAI_BUFFER_DEFAULT_PORT_SHARED_HEADROOM_BUFFER_XOFF_INFINITE (0xffff)

typedef enum _mlnx_port_breakout_capability_t {
    MLNX_PORT_BREAKOUT_CAPABILITY_NONE     = 0,
    MLNX_PORT_BREAKOUT_CAPABILITY_TWO      = 1,
    MLNX_PORT_BREAKOUT_CAPABILITY_FOUR     = 2,
    MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR = 3
} mlnx_port_breakout_capability_t;

/*
 *  Indexes for items in mlnx_port_config_t::port_policers[].
 *  Also represents storm_control_id value which will be used for calling sx_api_port_storm_control_set/get. This also means
 *  that a given sai_policer referenced in mlnx_port_config_t::port_policers[] will be created with storm_control_id == ii == index_of(port_policers[ii])
 */
typedef enum _mlnx_port_policer_type {
    MLNX_PORT_POLICER_TYPE_REGULAR_INDEX   = 0,
    MLNX_PORT_POLICER_TYPE_FLOOD_INDEX     = 1,
    MLNX_PORT_POLICER_TYPE_BROADCAST_INDEX = 2,
    MLNX_PORT_POLICER_TYPE_MULTICAST_INDEX = 3,
    MLNX_PORT_POLICER_TYPE_MAX             = 4
} mlnx_port_policer_type;
typedef struct _mlnx_sai_buffer_pool_attr {
    uint32_t                         sx_pool_id;
    sai_buffer_pool_type_t           pool_type;
    sai_buffer_pool_threshold_mode_t pool_mode;
    /*size in bytes*/
    uint32_t pool_size;
    /* is current pool is associated with shared headroom pool */
    bool is_shp_mapped;
} mlnx_sai_buffer_pool_attr_t;
typedef struct _mlnx_sai_shared_max_size_t {
    sai_buffer_profile_threshold_mode_t mode;
    union {
        sai_int8_t   alpha;
        sai_uint32_t static_th;
    } max;
} mlnx_sai_shared_max_size_t;
typedef struct _mlnx_sai_db_buffer_profile_entry_t {
    sai_object_id_t            sai_pool;
    sai_uint32_t               reserved_size;
    mlnx_sai_shared_max_size_t shared_max;
    uint32_t                   xon;
    uint32_t                   xoff;
    bool                       is_valid;
} mlnx_sai_db_buffer_profile_entry_t;
typedef struct _mlnx_sai_db_shp_to_ipool_map_entry_t {
    bool            is_shp_created;            /* global flag indicating Shared Headroom is globally enabled/disabled */
    sai_object_id_t sai_pool_id;              /* regular ingress Pool which is associated with shared headroom pool */
    sai_object_id_t shp_pool_id;              /* shared headroom pool */
} mlnx_sai_db_buffer_pool_shp_map_entry_t;

typedef struct _mlnx_policer_db_entry_t {
    sx_policer_id_t         sx_policer_id_trap;     /* For binding to trap group only. value == SX_POLICER_ID_INVALID, unless/until sx_policer is associated with this sai_policer.*/
    sx_policer_id_t         sx_policer_id_acl;      /* For binding to ACL only. see SX_POLICER_ID_INVALID note above, applies to this field as well*/
    sx_policer_id_t         sx_policer_id_acl_mirror;
    sx_policer_id_t         sx_policer_id_span_session;
    sx_policer_attributes_t sx_policer_attr;        /* Policer attribute values. The values will be applied to trap group, ACL and port storm policers.*/
} mlnx_policer_db_entry_t;

typedef struct {
    mlnx_shm_array_hdr_t    array_hdr;
    mlnx_policer_db_entry_t data;
} mlnx_policer_shm_array_entry_t;

typedef enum mlnx_sched_obj_type {
    MLNX_SCHED_OBJ_UNDEF,
    MLNX_SCHED_OBJ_PORT,
    MLNX_SCHED_OBJ_GROUP,
    MLNX_SCHED_OBJ_QUEUE,
} mlnx_sched_obj_type_t;
typedef struct mlnx_sched_obj {
    mlnx_sched_obj_type_t  type;
    sai_object_id_t        scheduler_id;
    sai_object_id_t        parent_id;
    uint8_t                index;
    bool                   is_used;
    int8_t                 next_index;
    uint8_t                level;
    uint8_t                max_child_count;
    sx_cos_ets_hierarchy_t ets_type;
} mlnx_sched_obj_t;
typedef struct _mlnx_sched_hierarchy_t {
    bool             is_default;
    uint8_t          groups_count[MAX_SCHED_LEVELS];
    mlnx_sched_obj_t groups[MAX_SCHED_LEVELS][MAX_SCHED_CHILD_GROUPS];
} mlnx_sched_hierarchy_t;

#define MAX_PG 32

typedef struct _mlnx_issu_lag_t {
    bool            lag_ingress_acl_oid_changed;
    sai_object_id_t lag_ingress_acl_oid;
    bool            lag_egress_acl_oid_changed;
    sai_object_id_t lag_egress_acl_oid;
    bool            lag_pvid_changed;
    uint16_t        lag_pvid;
    bool            lag_default_vlan_priority_changed;
    uint8_t         lag_default_vlan_priority;
    bool            lag_drop_untagged_changed;
    bool            lag_drop_untagged;
    bool            lag_drop_tagged_changed;
    bool            lag_drop_tagged;
} mlnx_issu_lag_t;

#define MAX_PORT_ATTR_ADV_SPEEDS_NUM 10
#define MAX_PORT_ATTR_ADV_INTFS_NUM  10

typedef enum _mlnx_port_autoneg_type_t {
    AUTO_NEG_DISABLE,
    AUTO_NEG_ENABLE,
    AUTO_NEG_DEFAULT
} mlnx_port_autoneg_type_t;

typedef struct _mlnx_port_config_t {
    uint16_t                        index;
    uint32_t                        module;
    uint32_t                        width;
    mlnx_port_breakout_capability_t breakout_modes;
    sx_port_speed_t                 speed_bitmap;
    sx_port_log_id_t                logical;
    sai_object_id_t                 saiport;
    bool                            is_split;
    uint8_t                         split_count;
    sx_port_mapping_t               port_map;
    uint8_t                         default_tc;
    bool                            is_present;
    uint32_t                        qos_maps[MLNX_QOS_MAP_TYPES_MAX];
    bool                            admin_state;
    bool                            is_span_analyzer_port;
    bool                            issu_remove_default_vid;
    bool                            has_hostif;
    uint32_t                        hostif_db_idx;
    uint32_t                        speed;
    sai_port_interface_type_t       intf;
    uint32_t                        adv_speeds[MAX_PORT_ATTR_ADV_SPEEDS_NUM];
    uint32_t                        adv_speeds_num;
    sai_port_interface_type_t       adv_intfs[MAX_PORT_ATTR_ADV_INTFS_NUM];
    uint32_t                        adv_intfs_num;
    mlnx_port_autoneg_type_t        auto_neg;
    acl_index_t                     ingress_acl_index;
    acl_index_t                     egress_acl_index;

    /*  SAI Port can have up to MLNX_PORT_POLICER_TYPE_MAX SDK port storm
     *  policers in use internally.  For each storm item we keep type of
     *  traffic it'll handle and SAI policer id which contains the policer
     *  attributes (cbs, pir, etc.) if SAI_NULL_OBJECT_ID == policer_id then
     *  given storm item is not in use currently.
     */
    sai_object_id_t  port_policers[MLNX_PORT_POLICER_TYPE_MAX];
    sx_port_log_id_t lag_id;
    /* sdk_port_added is ISSU initialization only */
    bool             sdk_port_added;
    sx_port_log_id_t before_issu_lag_id;
    uint32_t         internal_ingress_samplepacket_obj_idx;
    uint32_t         internal_egress_samplepacket_obj_idx;
    sai_object_id_t  scheduler_id;
    /* index of the 1st queue in the queue_db array */
    uint32_t               start_queues_index;
    mlnx_sched_hierarchy_t sched_hierarchy;
    uint16_t               rifs;
    sx_vid_t               pvid_create_rif;
    bool                   lossless_pg[MAX_PG];
    uint16_t               acl_refs;
    /* For ISSU, need to keep all LAG attributes in SAI port DB
     * Ingress ACL, Egress ACL, PVID, default VLAN priority, drop untagged/tagged
     * will be stored in SAI port DB only when port type is LAG and logical is zero */
    mlnx_issu_lag_t issu_lag_attr;
    uint32_t        isolation_group_port_refcount;
    uint32_t        isolation_group_bridge_port_refcount;
    sai_object_id_t isolation_group;
    uint32_t        hostif_table_refcount;
} mlnx_port_config_t;
typedef enum {
    MLNX_FID_FLOOD_TYPE_ALL,
    MLNX_FID_FLOOD_TYPE_NONE,
    MLNX_FID_FLOOD_TYPE_L2MC_GROUP,
    MLNX_FID_FLOOD_TYPE_COMBINED,
    MLNX_FID_FLOOD_TYPE_MAX
} mlnx_fid_flood_ctrl_type_t;
typedef enum {
    MLNX_FID_FLOOD_CTRL_ATTR_UC,
    MLNX_FID_FLOOD_CTRL_ATTR_MC,
    MLNX_FID_FLOOD_CTRL_ATTR_BC,
    MLNX_FID_FLOOD_CTRL_ATTR_MAX
} mlnx_fid_flood_ctrl_attr_t;
typedef struct mlnx_fid_flood_type_data {
    mlnx_fid_flood_ctrl_type_t type;
    uint32_t                   l2mc_db_idx;
} mlnx_fid_flood_type_data_t;
typedef struct _mlnx_fid_flood_data_t {
    mlnx_fid_flood_type_data_t types[MLNX_FID_FLOOD_CTRL_ATTR_MAX];
} mlnx_fid_flood_data_t;

/**
 * @brief Port Add/Delete Event
 */
typedef enum _sai_port_event_t {
    /** Create a new active port */
    MLNX_PORT_EVENT_ADD,

    /** Delete/Invalidate an existing port */
    MLNX_PORT_EVENT_DELETE,
} mlnx_port_event_t;

sai_status_t mlnx_fid_ports_get(_In_ sx_fid_t           sx_fid,
                                _Out_ sx_port_log_id_t *sx_ports,
                                _Inout_ uint32_t       *ports_count);
void mlnx_fid_flood_ctrl_init(_In_ mlnx_fid_flood_data_t *data);
sai_status_t mlnx_fid_flood_ctrl_set_forward_after_drop(_In_ sx_fid_t                          sx_fid,
                                                        _In_ mlnx_fid_flood_ctrl_attr_t        attr,
                                                        _In_ const mlnx_fid_flood_type_data_t *flood_data);
sai_status_t mlnx_fid_flood_ctrl_set_drop(_In_ sx_fid_t                          sx_fid,
                                          _In_ mlnx_fid_flood_ctrl_attr_t        attr,
                                          _In_ const mlnx_fid_flood_type_data_t *flood_data);
sai_status_t mlnx_fid_flood_ctrl_type_set(_In_ sx_fid_t                       sx_fid,
                                          _In_ mlnx_fid_flood_ctrl_attr_t     attr,
                                          _Inout_ mlnx_fid_flood_type_data_t *data,
                                          _In_ mlnx_fid_flood_ctrl_type_t     new_type);
sai_status_t mlnx_fid_flood_ctrl_l2mc_group_set(_In_ sx_fid_t                       sx_fid,
                                                _In_ mlnx_fid_flood_ctrl_attr_t     attr,
                                                _Inout_ mlnx_fid_flood_type_data_t *data,
                                                _In_ sai_object_id_t                group_oid);
sai_status_t mlnx_fid_flood_ctrl_port_event_handle(_In_ sx_fid_t                     sx_fid,
                                                   _In_ const mlnx_fid_flood_data_t *data,
                                                   _In_ const sx_port_log_id_t      *sx_ports,
                                                   _In_ uint32_t                     sx_port_count,
                                                   _In_ mlnx_port_event_t            event);
sai_status_t mlnx_default_vlan_flood_ctrl_init(void);
sai_status_t mlnx_fid_flood_ctrl_clear(_In_ sx_fid_t sx_fid);

typedef struct _mlnx_bridge_t {
    mlnx_shm_array_hdr_t  array_hdr;
    mlnx_fid_flood_data_t flood_data;
    sx_bridge_id_t        sx_bridge_id;
} mlnx_bridge_t;
typedef struct _mlnx_vlan_db_t {
    /* We keep here phy ports + LAGs */
    uint32_t              ports_map[MLNX_U32BITARRAY_SIZE(MAX_BRIDGE_1Q_PORTS)];
    sx_mstp_inst_id_t     stp_id;
    mlnx_fid_flood_data_t flood_data;
    bool                  is_created;
    uint32_t              hostif_table_refcount;
} mlnx_vlan_db_t;

/* MLNX Bridge API */
sai_status_t mlnx_bridge_init(void);
sx_bridge_id_t mlnx_bridge_default_1q(void);
sai_object_id_t mlnx_bridge_default_1q_oid(void);
mlnx_bridge_t* mlnx_bridge_1d_by_db_idx(_In_ uint32_t db_idx);
mlnx_fid_flood_ctrl_attr_t mlnx_bridge_flood_ctrl_group_attr_to_fid_attr(_In_ sai_bridge_attr_t attr);
sai_status_t mlnx_bridge_sx_ports_get(_In_ sx_bridge_id_t     sx_bridge,
                                      _Out_ sx_port_log_id_t *sx_ports,
                                      _Inout_ uint32_t       *ports_count);
sai_status_t mlnx_create_bridge_1d_object(sx_bridge_id_t sx_br_id, sai_object_id_t  *bridge_oid);
sai_status_t mlnx_bridge_oid_to_id(sai_object_id_t oid, sx_bridge_id_t *bridge_id);
sai_status_t mlnx_bridge_port_sai_to_log_port_not_locked(sai_object_id_t oid, sx_port_log_id_t *log_port);
sai_status_t mlnx_bridge_port_sai_to_log_port(sai_object_id_t oid, sx_port_log_id_t *log_port);
sai_status_t mlnx_bridge_port_to_vlan_port(sai_object_id_t oid, sx_port_log_id_t *log_port);
sai_status_t mlnx_log_port_to_sai_bridge_port(sx_port_log_id_t log_port, sai_object_id_t *oid);
sai_status_t mlnx_log_port_to_sai_bridge_port_soft(sx_port_log_id_t log_port, sai_object_id_t *oid);
sai_status_t mlnx_port_is_in_bridge_1q(const mlnx_port_config_t *port);
sai_status_t mlnx_bridge_port_by_log(sx_port_log_id_t log, mlnx_bridge_port_t **port);
sai_status_t mlnx_bridge_1q_port_by_log(sx_port_log_id_t log, mlnx_bridge_port_t **port);
sai_status_t mlnx_bridge_port_to_oid(mlnx_bridge_port_t *port, sai_object_id_t *oid);
sai_status_t mlnx_bridge_port_by_idx(uint32_t idx, mlnx_bridge_port_t **port);
sai_status_t mlnx_bridge_port_by_oid(sai_object_id_t oid, mlnx_bridge_port_t **port);
sai_status_t mlnx_bridge_port_by_tunnel_id(sx_tunnel_id_t sx_tunnel, mlnx_bridge_port_t **port);
sai_status_t mlnx_bridge_rif_add(sx_router_id_t vrf_id, mlnx_bridge_rif_t **rif);
sai_status_t mlnx_bridge_rif_del(mlnx_bridge_rif_t *rif);
sai_status_t mlnx_bridge_rif_by_idx(uint32_t idx, mlnx_bridge_rif_t **rif);
bool mlnx_is_vxlan_tunnel_bport_oid(sai_object_id_t oid);
bool mlnx_is_vxlan_tunnel_bridge_port(mlnx_bridge_port_t *port);

sai_status_t mlnx_rif_oid_create(_In_ mlnx_rif_type_t          rif_type,
                                 _In_ const mlnx_bridge_rif_t *bridge_rif,
                                 _In_ mlnx_shm_rm_array_idx_t  idx,
                                 _Out_ sai_object_id_t        *rif_oid);
sai_status_t mlnx_rif_sx_to_sai_oid(_In_ sx_router_interface_t sx_rif_id, _Out_ sai_object_id_t      *oid);
sai_status_t mlnx_rif_oid_counter_get(_In_ sai_object_id_t rif_oid, _Out_ sx_router_counter_id_t *sx_counter);
sai_status_t mlnx_rif_oid_to_bridge_rif(_In_ sai_object_id_t rif_oid, _Out_ uint32_t *bridge_rif_idx);
sai_status_t mlnx_rif_oid_to_sdk_rif_id(sai_object_id_t rif_oid, sx_router_interface_t *sdk_rif_id);
sai_status_t mlnx_rif_sx_init(_In_ sx_router_id_t                     sx_router,
                              _In_ const sx_router_interface_param_t *intf_params,
                              _In_ const sx_interface_attributes_t   *intf_attribs,
                              _Out_ sx_router_interface_t            *sx_rif_id,
                              _Out_ sx_router_counter_id_t           *sx_counter);
sai_status_t mlnx_rif_sx_deinit(_In_ mlnx_rif_sx_data_t *sx_data);
sai_status_t mlnx_rif_loopback_action_sai_to_sx(_In_ const sai_attribute_value_t *loopback_action,
                                                _In_ uint32_t                     attr_index,
                                                _Out_ sx_interface_attributes_t  *intf_attribs);
sai_status_t mlnx_rif_sx_attrs_get(_In_ sai_object_id_t                rif_oid,
                                   _In_ bool                           is_admin_state,
                                   _Out_ mlnx_rif_type_t              *rif_type,
                                   _Out_ bool                         *is_created,
                                   _Out_ mlnx_rif_sx_data_t          **sx_data,
                                   _Out_ sx_router_interface_state_t **rif_state,
                                   _Out_ sx_router_interface_param_t **intf_params,
                                   _Out_ sx_interface_attributes_t   **intf_attribs);
bool mlnx_rif_is_additional_mac_supported(void);
sai_status_t mlnx_rif_oid_to_mac_data(_In_ sai_object_id_t        rif_oid,
                                      _Out_ mlnx_rif_mac_data_t **rif_mac_data);
sai_status_t mlnx_debug_set_additional_mac_for_ptf(_In_ const char* value);
sai_status_t mlnx_debug_set_bfd_namespace_for_ptf(_In_ const char* value);
sai_status_t mlnx_bridge_sx_vport_create(_In_ sx_port_log_id_t           sx_port,
                                         _In_ sx_vlan_id_t               sx_vlan_id,
                                         _In_ sx_untagged_member_state_t sx_tagging_mode,
                                         _Out_ sx_port_log_id_t         *sx_vport);
sai_status_t mlnx_bridge_sx_vport_delete(_In_ sx_port_log_id_t sx_port,
                                         _In_ sx_vlan_id_t     sx_vlan_id,
                                         _In_ sx_port_log_id_t sx_vport);

sx_mstp_inst_id_t mlnx_stp_get_default_stp();
sai_status_t mlnx_vlan_list_stp_bind(_In_ const sx_vlan_id_t *vlan_ids,
                                     _In_ uint32_t            vlan_count,
                                     _In_ sx_mstp_inst_id_t   sx_stp_id);
sai_status_t mlnx_vlan_stp_bind(sai_vlan_id_t vlan_id, sx_mstp_inst_id_t sx_stp_id);
sai_status_t mlnx_vlan_stp_unbind(sai_vlan_id_t vlan_id);
void mlnx_vlan_stp_id_set(sai_vlan_id_t vlan_id, sx_mstp_inst_id_t sx_stp_id);
sx_mstp_inst_id_t mlnx_vlan_stp_id_get(sai_vlan_id_t vlan_id);

void mlnx_vlan_port_set(uint16_t vid, mlnx_bridge_port_t *port, bool is_set);
bool mlnx_vlan_port_is_set(uint16_t vid, const mlnx_bridge_port_t *port);
sai_status_t mlnx_vlan_sai_tagging_to_sx(_In_ sai_vlan_tagging_mode_t      mode,
                                         _Out_ sx_untagged_member_state_t *tagging,
                                         _Out_ sx_untagged_prio_state_t   *prio_tagging);
sai_status_t mlnx_vlan_log_port_tagging_get(_In_ sx_port_log_id_t             sx_port_id,
                                            _In_ sx_vlan_id_t                 sx_vlan_id,
                                            _Out_ sx_untagged_member_state_t *sx_tagging_mode);
sai_status_t mlnx_vlan_port_add(uint16_t vid, sai_vlan_tagging_mode_t mode, mlnx_bridge_port_t *port);
sai_status_t mlnx_vlan_port_del(uint16_t vid, mlnx_bridge_port_t *port);
sai_status_t sai_object_to_vlan(sai_object_id_t oid, uint16_t *vlan_id);
sai_status_t validate_vlan(_In_ const sai_vlan_id_t vlan_id);
sai_status_t mlnx_vlan_oid_create(_In_ sai_vlan_id_t vlan_id, _Out_ sai_object_id_t *vlan_oid);
mlnx_vlan_db_t* mlnx_vlan_db_get_vlan(_In_ sai_vlan_id_t vlan_id);
mlnx_vlan_db_t * mlnx_vlan_db_create_vlan(_In_ sai_vlan_id_t vlan_id);
bool mlnx_vlan_is_created(_In_ sai_vlan_id_t vlan_id);
sai_status_t mlnx_max_learned_addresses_value_validate(_In_ uint32_t limit, _In_ uint32_t attr_index);
sai_status_t mlnx_vlan_bridge_max_learned_addresses_set(_In_ sx_vid_t sx_vid, _In_ uint32_t limit);
sai_status_t mlnx_vlan_bridge_max_learned_addresses_get(_In_ sx_vid_t sx_vid, _In_ uint32_t *limit);
sai_status_t mlnx_buffer_port_profile_list_get(_In_ const sai_object_id_t     port_id,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ bool                      is_ingress);
sai_status_t mlnx_buffer_port_profile_list_set_unlocked(_In_ const sai_object_id_t        port_id,
                                                        _In_ const sai_attribute_value_t *value,
                                                        _In_ bool                         is_ingress);
sai_status_t mlnx_buffer_port_profile_list_set(_In_ const sai_object_id_t        port_id,
                                               _In_ const sai_attribute_value_t *value,
                                               _In_ bool                         is_ingress);
sai_status_t mlnx_get_sai_pool_data(_In_ sai_object_id_t sai_pool, _Out_ mlnx_sai_buffer_pool_attr_t* sai_pool_attr);

sai_status_t mlnx_port_tc_set(sx_port_log_id_t port_id, _In_ const uint8_t tc);

sai_status_t get_buffer_profile_db_index(_In_ sai_object_id_t oid, _Out_ uint32_t* db_index);
sai_status_t mlnx_buffer_apply(_In_ sai_object_id_t sai_buffer, _In_ sai_object_id_t to_obj_id);

sai_status_t mlnx_descriptor_buffer_init();
sai_status_t mlnx_apply_descriptor_buffer_to_port(sx_port_log_id_t port_log_id, bool remove_default_descriptor_buffer);
sai_status_t set_mc_sp_zero(_In_ uint32_t sp);

sai_status_t mlnx_wred_apply_to_queue(_In_ mlnx_port_config_t *port,
                                      _In_ uint32_t            queue_idx,
                                      _In_ sai_object_id_t     wred_id);
static inline mlnx_sched_obj_t * group_get(mlnx_port_config_t *port, uint8_t level, uint8_t index)
{
    return &port->sched_hierarchy.groups[level][index];
}
sai_status_t mlnx_scheduler_port_hierarchy_db_clear(_In_ mlnx_port_config_t *port);
sai_status_t mlnx_wred_port_queue_db_clear(_In_ mlnx_port_config_t *port);

sai_status_t mlnx_bfd_session_oid_create(_In_ mlnx_shm_rm_array_idx_t idx,
                                         _Out_ sai_object_id_t       *oid);

sai_status_t mlnx_port_bitmap_to_speeds(_In_ const sx_port_speed_t speed_bitmap,
                                        _Out_ uint32_t            *speeds,
                                        _Inout_ uint32_t          *speeds_count);

#define MAX_ENCAP_NEXTHOPS_NUMBER 40000
#define NUMBER_OF_LOCAL_VNETS     32
#define NUMBER_OF_VRF_DATA_SETS   ((NUMBER_OF_LOCAL_VNETS)+1)
#define MLNX_REGULAR_ECMP_INDEX   (NUMBER_OF_LOCAL_VNETS)

typedef struct _mlnx_fake_nh_db_data_t {
    sai_object_id_t associated_vrf;
    sx_ip_v4_addr_t sx_fake_ip_v4_addr;
    sx_ecmp_id_t    sx_fake_nexthop;
    int32_t         counter;
    int32_t         nhgm_counter;
} mlnx_fake_nh_db_data_t;

typedef struct _mlnx_encap_nexthop_db_data_t {
    sai_ip_address_t       dst_ip;
    sai_object_id_t        tunnel_id;
    sai_mac_t              tunnel_mac;
    uint32_t               tunnel_vni;
    sx_mac_addr_t          sx_fake_mac;
    int64_t                acl_counter;
    uint32_t               acl_index;
    mlnx_fake_nh_db_data_t fake_data[NUMBER_OF_LOCAL_VNETS];
    sx_flow_counter_id_t   flow_counter;
} mlnx_encap_nexthop_db_data_t;

typedef struct _mlnx_encap_nexthop_db_entry_t {
    mlnx_shm_array_hdr_t         array_hdr;
    mlnx_encap_nexthop_db_data_t data;
} mlnx_encap_nexthop_db_entry_t;

typedef enum _mlnx_nh_counter_type_t {
    NH_COUNTER_TYPE_NH,
    NH_COUNTER_TYPE_NHGM
} mlnx_nh_counter_type_t;

sai_status_t mlnx_encap_nexthop_oid_create(_In_ mlnx_shm_rm_array_idx_t idx,
                                           _Out_ sai_object_id_t       *oid);
sai_status_t mlnx_encap_nexthop_oid_to_data(_In_ sai_object_id_t                  oid,
                                            _Out_ mlnx_encap_nexthop_db_entry_t **encap_nexthop_db_entry,
                                            _Out_ mlnx_shm_rm_array_idx_t        *idx);
sai_status_t mlnx_encap_nexthop_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t          idx,
                                                     _Out_ mlnx_encap_nexthop_db_entry_t **encap_nexthop_db_entry);
sai_status_t mlnx_tunnel_get_bridge_and_rif(_In_ sai_object_id_t         tunnel_id,
                                            _In_ uint32_t                vni,
                                            _In_ sai_object_id_t         vrf,
                                            _Out_ sx_router_interface_t *br_rif,
                                            _Out_ sx_fid_t              *br_fid);
sai_status_t mlnx_tunnel_bridge_counter_update(_In_ sai_object_id_t tunnel_id,
                                               _In_ uint32_t        vni,
                                               _In_ sai_object_id_t vrf,
                                               _In_ int32_t         diff);
sai_status_t mlnx_encap_nexthop_get_ecmp(_In_ sai_object_id_t nh,
                                         _In_ sai_object_id_t vrf,
                                         _Out_ sx_ecmp_id_t  *sx_ecmp);
sai_status_t mlnx_encap_nexthop_counter_update(_In_ mlnx_shm_rm_array_idx_t nh_idx,
                                               _In_ sai_object_id_t         vrf,
                                               _In_ int32_t                 diff,
                                               _In_ mlnx_nh_counter_type_t  counter_type);
sai_status_t mlnx_encap_nexthop_change_dmac(_In_ sai_object_id_t nh,
                                            _In_ const sai_mac_t mac,
                                            _In_ bool            store);
sai_status_t mlnx_encap_nh_data_get(mlnx_shm_rm_array_idx_t nh_idx,
                                    sai_object_id_t         vrf,
                                    int32_t                 diff,
                                    sx_next_hop_t          *sx_next_hop);
sai_status_t mlnx_get_ecmp_attr(_In_ const sx_ecmp_id_t     ecmp_id,
                                _Out_ sx_ecmp_attributes_t *sx_ecmp_attr);
sai_status_t mlnx_nhg_get_ecmp(_In_ sai_object_id_t nhg,
                               _In_ sai_object_id_t vrf,
                               _In_ int32_t         diff,
                               _Out_ sx_ecmp_id_t  *sx_ecmp_id);
sai_status_t mlnx_counter_oid_to_data(_In_ sai_object_id_t           oid,
                                      _Out_ mlnx_counter_t         **counter_db_entry,
                                      _Out_ mlnx_shm_rm_array_idx_t *idx);
sai_status_t mlnx_counter_db_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx,
                                         _Out_ mlnx_counter_t       **counter);
sai_status_t mlnx_counter_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t *oid);
sai_status_t mlnx_get_sx_flow_counter_id_by_idx(_In_ mlnx_shm_rm_array_idx_t idx,
                                                _Out_ sx_flow_counter_id_t  *sx_flow_counter);
sai_status_t mlnx_route_next_hop_id_get_ext(_In_ sx_ecmp_id_t      ecmp,
                                            _Out_ sai_object_id_t *nh);

#define MLNX_NHG_DB_SIZE             (4000)
#define MLNX_NHG_MEMBER_DB_SIZE      (MLNX_NHG_DB_SIZE * 128)
#define MLNX_ECMP_TO_NHG_MAP_SIZE    (MLNX_NHG_DB_SIZE * NUMBER_OF_LOCAL_VNETS)
#define MLNX_ECMP_NHG_HASHTABLE_SIZE (251)

typedef enum _mlnx_nhg_type_t {
    MLNX_NHG_TYPE_NULL       = 0,
    MLNX_NHG_TYPE_ECMP       = 1,
    MLNX_NHG_TYPE_FINE_GRAIN = 2,
    MLNX_NHG_TYPE_ORDERED    = 3,
    MLNX_NHG_TYPE_MAX        = MLNX_NHG_TYPE_ORDERED
} mlnx_nhg_type_t;

typedef enum _mlnx_nhgm_type_t {
    MLNX_NHGM_TYPE_NULL           = 0,
    MLNX_NHGM_TYPE_NATIVE         = 1 << 0,
    MLNX_NHGM_TYPE_ENCAP          = 1 << 1,
    MLNX_NHGM_TYPE_FINE_GRAIN     = 1 << 2,
    MLNX_NHGM_TYPE_ORDERED_NATIVE = 1 << 3,
    MLNX_NHGM_TYPE_ORDERED_ENCAP  = 1 << 4,
    MLNX_NHGM_TYPE_MAX            = MLNX_NHGM_TYPE_ORDERED_ENCAP
} mlnx_nhgm_type_t;

typedef enum _mlnx_nhgm_state_t {
    MLNX_NHGM_STATE_INVALID     = 0,
    MLNX_NHGM_STATE_ALLOCATED   = 1,
    MLNX_NHGM_STATE_TO_REMOVE   = 2,
    MLNX_NHGM_STATE_INITIALIZED = 3,
} mlnx_nhgm_state_t;

typedef struct _mlnx_nhg_encap_vrf_data_t {
    sai_object_id_t associated_vrf;
    sx_ecmp_id_t    sx_ecmp_id;
    int32_t         refcount;
} mlnx_nhg_encap_vrf_data_t;

typedef struct _mlnx_nhg_encap_data_t {
    mlnx_nhg_encap_vrf_data_t vrf_data[NUMBER_OF_LOCAL_VNETS + 1];
} mlnx_nhg_encap_data_t;

typedef struct _mlnx_nhg_fine_grain_data_t {
    uint32_t     real_size;
    uint32_t     configured_size;
    sx_ecmp_id_t sx_ecmp_id;
} mlnx_nhg_fine_grain_data_t;

typedef struct _mlnx_nhg_db_data_t {
    mlnx_nhg_type_t         type;
    mlnx_shm_rm_array_idx_t members;
    uint32_t                members_count;
    mlnx_shm_rm_array_idx_t flow_counter;
    union {
        mlnx_nhg_encap_data_t      encap;
        mlnx_nhg_fine_grain_data_t fine_grain;
    } data;
} mlnx_nhg_db_data_t;

typedef struct _mlnx_nhg_db_entry_t {
    mlnx_shm_array_hdr_t array_hdr;
    mlnx_nhg_db_data_t   data;
} mlnx_nhg_db_entry_t;

typedef struct _mlnx_nhgm_native_data_t {
    sx_ecmp_id_t sx_ecmp_id;
} mlnx_nhgm_native_data_t;

typedef struct _mlnx_nhgm_encap_data_t {
    mlnx_shm_rm_array_idx_t nh_idx;
} mlnx_nhgm_encap_data_t;

typedef struct _mlnx_nhgm_fg_data_t {
    uint32_t        id;
    sai_object_id_t nh;
} mlnx_nhgm_fg_data_t;

typedef struct _mlnx_nhgm_ordered_data_t {
    uint32_t prio;
    union {
        mlnx_nhgm_native_data_t native;
        mlnx_nhgm_encap_data_t  encap;
    } entry;
} mlnx_nhgm_ordered_data_t;

typedef struct _mlnx_nhgm_db_data_t {
    mlnx_nhgm_type_t        type;
    mlnx_nhgm_state_t       state;
    uint32_t                weight;
    mlnx_shm_rm_array_idx_t flow_counter;
    union {
        mlnx_nhgm_native_data_t  native;
        mlnx_nhgm_encap_data_t   encap;
        mlnx_nhgm_fg_data_t      fg;
        mlnx_nhgm_ordered_data_t ordered;
    } entry;
    mlnx_shm_rm_array_idx_t nhg_idx;
    mlnx_shm_rm_array_idx_t next_member_idx;
    mlnx_shm_rm_array_idx_t prev_member_idx;
} mlnx_nhgm_db_data_t;

typedef struct _mlnx_nhgm_db_entry_t {
    mlnx_shm_array_hdr_t array_hdr;
    mlnx_nhgm_db_data_t  data;
} mlnx_nhgm_db_entry_t;

typedef struct _mlnx_ecmp_to_nhg_db_entry_t {
    mlnx_shm_array_hdr_t    array_hdr;
    sx_ecmp_id_t            key;
    mlnx_shm_rm_array_idx_t nhg_idx;
    mlnx_shm_rm_array_idx_t next_idx;
} mlnx_ecmp_to_nhg_db_entry_t;

sai_status_t mlnx_nhg_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx,
                                           _Out_ mlnx_nhg_db_entry_t  **nhg_db_entry);
sai_status_t mlnx_ecmp_to_nhg_map_entry_get(_In_ sx_ecmp_id_t              key,
                                            _Out_ mlnx_shm_rm_array_idx_t *value);
sai_status_t mlnx_nhg_counter_update(_In_ mlnx_shm_rm_array_idx_t nhg_idx,
                                     _In_ sai_object_id_t         vrf,
                                     _In_ int32_t                 diff,
                                     _In_ bool                    bulk_oprtation);
sai_status_t mlnx_nhg_oid_create(_In_ mlnx_shm_rm_array_idx_t idx,
                                 _Out_ sai_object_id_t       *oid);
sai_status_t mlnx_nhgm_oid_create(_In_ mlnx_shm_rm_array_idx_t idx,
                                  _Out_ sai_object_id_t       *oid);
sai_status_t mlnx_nhg_oid_to_data(_In_ sai_object_id_t           oid,
                                  _Out_ mlnx_nhg_db_entry_t    **nhg_db_entry,
                                  _Out_ mlnx_shm_rm_array_idx_t *idx);
sai_status_t mlnx_nhg_get_regular_ecmp(_In_ sai_object_id_t nhg,
                                       _Out_ sx_ecmp_id_t  *sx_ecmp_id);

#define mlnx_vlan_id_foreach(vid) \
    for (vid = SXD_VID_MIN; vid <= SXD_VID_MAX; vid++)

#define mlnx_stp_vlans_foreach(stp_id, vid)            \
    for (vid = SXD_VID_MIN; vid <= SXD_VID_MAX; vid++) \
    if (mlnx_vlan_stp_id_get(vid) == stp_id)

#define mlnx_port_local_foreach(port, idx)    \
    for (idx = 0; idx < MAX_PORTS &&          \
         (port = &mlnx_ports_db[idx]); idx++) \
    if (port->logical)

#define mlnx_port_phy_foreach(port, idx)      \
    for (idx = 0; idx < MAX_PORTS &&          \
         (port = &mlnx_ports_db[idx]); idx++) \
    if (port->is_present && port->logical)

#define mlnx_port_foreach(port, idx)                  \
    for (idx = 0; idx < (MAX_PORTS * 2) &&            \
         (port = &mlnx_ports_db[idx]); idx++)         \
    if ((port->is_present || port->sdk_port_added) && \
        (port->logical || ((idx >= (MAX_PORTS)) && port->sdk_port_added)))

#define mlnx_port_not_in_lag_foreach(port, idx) \
    for (idx = 0; idx < (MAX_PORTS * 2) &&      \
         (port = &mlnx_ports_db[idx]); idx++)   \
    if ((port->is_present || port->sdk_port_added) && !port->lag_id && !port->before_issu_lag_id)

#define mlnx_phy_port_not_in_lag_foreach(port, idx) \
    for (idx = 0; idx < MAX_PORTS &&                \
         (port = &mlnx_ports_db[idx]); idx++)       \
    if ((port->is_present || port->sdk_port_added) && !port->lag_id && !port->before_issu_lag_id)

#define mlnx_lag_foreach(lag, idx)                 \
    for (idx = MAX_PORTS; idx < (MAX_PORTS * 2) && \
         (lag = &mlnx_ports_db[idx]); idx++)       \
    if (lag->is_present && lag->logical)

#define mlnx_vxlan_exist_foreach(tun, idx)             \
    for (idx = 0; idx < MAX_TUNNEL_DB_SIZE &&          \
         (tun = &g_sai_db_ptr->tunnel_db[idx]); idx++) \
    if (tun->is_used && tun->sai_tunnel_type == SAI_TUNNEL_TYPE_VXLAN)

#define mlnx_bridge_non1q_port_foreach(port, idx, checked)  \
    for (idx = MAX_BRIDGE_1Q_PORTS, checked = 0;            \
         (idx < (MAX_BRIDGE_PORTS)) &&                      \
         (checked < g_sai_db_ptr->non_1q_bports_created) && \
         (port = &g_sai_db_ptr->bridge_ports_db[idx]);      \
         idx++, checked++)                                  \
    if (port->is_present)

#define mlnx_bridge_1d_foreach(bridge, idx)                                  \
    for (ii = 0;                                                             \
         (ii < mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_BRIDGE)) && \
         (bridge = mlnx_bridge_1d_by_db_idx(ii));                            \
         ii++)                                                               \
    if (bridge->array_hdr.is_used)

#define mlnx_bridge_1q_port_foreach(port, idx)                \
    for (idx = 0; idx < (MAX_BRIDGE_1Q_PORTS) &&              \
         (port = &g_sai_db_ptr->bridge_ports_db[idx]); idx++) \
    if (port->is_present)

#define mlnx_vlan_ports_foreach(vid, port, idx)               \
    for (idx = 0;                                             \
         (idx < MAX_BRIDGE_1Q_PORTS) &&                       \
         (port = &g_sai_db_ptr->bridge_ports_db[idx]); idx++) \
    if (port->is_present && mlnx_vlan_port_is_set(vid, port))

#define mlnx_port_non_lag_not_in_lag_foreach(port, idx) \
    for (idx = 0; idx < (MAX_PORTS) &&                  \
         (port = &mlnx_ports_db[idx]); idx++)           \
    if ((port->is_present || port->sdk_port_added) && !port->lag_id && !port->before_issu_lag_id)

typedef struct _mlnx_hostif_channel_t {
    sx_user_channel_t trap_channel;
    bool              is_in_use;
} mlnx_hostif_channel_t;

typedef struct _mlnx_trap_t {
    sai_packet_action_t     action;
    sai_object_id_t         trap_group;
    mlnx_shm_rm_array_idx_t bound_dbg_counter;
    mlnx_hostif_channel_t   trap_channel;
    bool                    is_used;
    uint32_t                refcount;
} mlnx_trap_t;

typedef struct _mlnx_wred_profile_t {
    sx_cos_redecn_profile_t green_profile_id;
    sx_cos_redecn_profile_t yellow_profile_id;
    sx_cos_redecn_profile_t red_profile_id;
    bool                    wred_enabled;
    bool                    ecn_enabled;
    bool                    in_use;
} mlnx_wred_profile_t;

/* UDF db */
typedef struct _mlnx_udf_list_t {
    uint32_t count;
    uint32_t udf_indexes[]; /* MLNX_UDF_GROUP_SIZE_MAX */
} mlnx_udf_list_t;

typedef struct _mlnx_udf_group_t {
    bool                 is_created;
    bool                 is_sx_custom_bytes_created;
    uint32_t             refs;
    sai_udf_group_type_t type;
    uint32_t             length;
    sai_object_id_t      sai_object;
    sx_acl_key_t         sx_custom_bytes_keys[]; /* MLNX_UDF_GROUP_LENGTH_MAX */
} mlnx_udf_group_t;

typedef struct _mlnx_udf_t {
    bool            is_created;
    uint32_t        match_index;
    uint32_t        group_index;
    sai_udf_base_t  base;
    sai_uint16_t    offset;
    sai_object_id_t sai_object;
} mlnx_udf_t;

typedef enum _mlnx_udf_match_type_t {
    MLNX_UDF_MATCH_TYPE_EMPTY,
    MLNX_UDF_MATCH_TYPE_ARP,
    MLNX_UDF_MATCH_TYPE_IPv4,
    MLNX_UDF_MATCH_TYPE_IPv6,
} mlnx_udf_match_type_t;

typedef struct _mlnx_match_t {
    bool                  is_created;
    uint32_t              refs;
    mlnx_udf_match_type_t type;
    uint8_t               priority;
    sai_object_id_t       sai_object;
} mlnx_match_t;

typedef struct _mlnx_udf_db_t {
    mlnx_udf_group_t *groups;      /* MLNX_UDF_GROUP_COUNT_MAX */
    mlnx_udf_list_t  *groups_udfs; /* MLNX_UDF_GROUP_COUNT_MAX */
    mlnx_udf_t       *udfs;        /* MLNX_UDF_COUNT_MAX */
    mlnx_match_t     *matches;     /* MLNX_UDF_MATCH_COUNT_MAX */
} mlnx_udf_db_t;

#define MAX_QOS_MAPS           MAX_PORTS
#define MAX_QOS_MAPS_DB        MAX_PORTS_DB
#define SAI_INVALID_PROFILE_ID 0xFFFFFFFF
#define MAX_SCHED              ((g_resource_limits.cos_port_ets_elements_num) * MAX_PORTS)
#define MAX_QUEUES             (g_resource_limits.cos_port_ets_traffic_class_max + 1)
#define MAX_SUB_GROUPS         (g_resource_limits.cos_port_ets_sub_group_max + 1)
#define MAX_ETS_TC             (g_resource_limits.cos_port_ets_traffic_class_max)
#define MAX_USED_TC            8
#define MAX_PORT_PRIO          (g_resource_limits.cos_port_prio_max)
#define MAX_PCP_PRIO           7

#define ACL_USER_META_RANGE_MIN 0
#define ACL_USER_META_RANGE_MAX 0x0FFF

#define ACL_INVALID_DB_INDEX (0x7FFFF)
#define ACL_INDEX_INVALID    ((acl_index_t) {.acl_db_index = ACL_INVALID_DB_INDEX})

#define ACL_MIN_TABLE_PRIO      0
#define ACL_MAX_TABLE_PRIO      UINT32_MAX
#define ACL_ENTRY_DB_SIZE       16000
#define ACL_MAX_SX_RULES_NUMBER 256000

#define ACL_GROUP_MEMBER_PRIO_MIN 0
#define ACL_GROUP_MEMBER_PRIO_MAX UINT16_MAX
#define ACL_SX_TABLES_NUMBER      (g_resource_limits.acl_regions_max)
#define ACL_TABLE_DB_SIZE         ACL_SX_TABLES_NUMBER

#define ACL_SEQ_GROUP_SIZE   ACL_SX_TABLES_NUMBER
#define ACL_PAR_GROUP_SIZE   (g_resource_limits.acl_groups_size_max)
#define ACL_GROUP_SIZE       MAX(ACL_SEQ_GROUP_SIZE, ACL_PAR_GROUP_SIZE)
#define ACL_GROUP_NUMBER     (g_resource_limits.acl_groups_num_max)
#define ACL_RIF_COUNT        (g_resource_limits.router_rifs_max)
#define ACL_VLAN_GROUP_COUNT (g_resource_limits.acl_vlan_groups_max)
#define ACL_VLAN_COUNT       4096

#define ACL_MAX_SX_COUNTER_BYTE_NUM   16000
#define ACL_MAX_SX_COUNTER_PACKET_NUM 16000

#define ACL_MAX_SX_ING_GROUP_NUMBER ACL_GROUP_NUMBER
#define ACL_MAX_SX_EGR_GROUP_NUMBER ACL_GROUP_NUMBER

#define ACL_PBS_MAP_IDX_TRIVIAL_RANGE_START ((mlnx_acl_pbs_map_idx_t)0)
#define ACL_PBS_MAP_FLOOD_PBS_INDEX         ((mlnx_acl_pbs_map_idx_t)(MAX_PORTS * 2))
#define ACL_PBS_MAP_HASH_INDEX_START        ((mlnx_acl_pbs_map_idx_t)(ACL_PBS_MAP_FLOOD_PBS_INDEX + 1))

#define ACL_PBS_MAP_PREDEF_REG_SIZE (ACL_PBS_MAP_HASH_INDEX_START - ACL_PBS_MAP_IDX_TRIVIAL_RANGE_START) /* Ports LAGs and Flood PBS */
#define ACL_MAX_PBS_NUMBER          (g_resource_limits.acl_pbs_entries_max)
#define ACL_PBS_MAP_RESERVE_PERCENT 1.2

#define ACL_PBS_MAP_INVALID_INDEX ((mlnx_acl_pbs_map_idx_t)-1)
#define ACL_PBS_MAP_INDEX_IS_VALID(index)      \
    (((index) != ACL_PBS_MAP_INVALID_INDEX) && \
     ((index) < g_sai_acl_db_pbs_map_size))
#define ACL_PBS_MAP_INDEX_IS_TRIVIAL(index) ((index) < ACL_PBS_MAP_FLOOD_PBS_INDEX)

#define SAI_HASH_MAX_OBJ_COUNT        32
#define SAI_ACL_RANGE_TYPE_COUNT      (SAI_ACL_RANGE_TYPE_PACKET_LENGTH + 1)
#define SAI_ACL_BIND_POINT_TYPE_COUNT (SAI_ACL_BIND_POINT_TYPE_SWITCH + 1)
#define SAI_ACL_MAX_BIND_POINT_BOUND  (MAX(MAX_PORTS + ACL_VLAN_GROUP_COUNT, ACL_RIF_COUNT))

#define ACL_IP_IDENT_FIELD_BYTE_COUNT 2
#define ACL_UDF_GROUP_COUNT_MAX       (SAI_ACL_USER_DEFINED_FIELD_ATTR_ID_RANGE + 1)

#define ACL_AETH_SYNDROME_FIELD_BYTE_COUNT 1

uint32_t mlnx_acl_entry_max_prio_get(void);
uint32_t mlnx_acl_entry_min_prio_get(void);

typedef struct _acl_bind_point_type_list_t {
    sai_acl_bind_point_type_t types[SAI_ACL_BIND_POINT_TYPE_COUNT];
    uint32_t                  count;
} acl_bind_point_type_list_t;

typedef struct _acl_table_wrapping_group_t {
    bool        created;
    sx_acl_id_t sx_group_id;
} acl_table_wrapping_group_t;


typedef struct _acl_udf_group_t {
    bool     is_set;
    uint32_t udf_group_db_index;
} acl_udf_group_t;

typedef acl_udf_group_t acl_udf_group_list_t[ACL_UDF_GROUP_COUNT_MAX];

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
    MLNX_ACL_FIELD_TYPE_TCP_UDP            = (1 << 9) | MLNX_ACL_FIELD_TYPE_IP,
    MLNX_ACL_FIELD_TYPE_TCP                = (1 << 10) | MLNX_ACL_FIELD_TYPE_TCP_UDP,
    MLNX_ACL_FIELD_TYPE_ICMP               = (1 << 11),
    MLNX_ACL_FIELD_TYPE_ICMPV4             = MLNX_ACL_FIELD_TYPE_ICMP | MLNX_ACL_FIELD_TYPE_IPV4,
    MLNX_ACL_FIELD_TYPE_ICMPV6             = MLNX_ACL_FIELD_TYPE_ICMP | MLNX_ACL_FIELD_TYPE_IPV6,
    MLNX_ACL_FIELD_TYPE_INNER_IP           = (1 << 14),
    MLNX_ACL_FIELD_TYPE_INNER_IPV4         = (1 << 15) | MLNX_ACL_FIELD_TYPE_INNER_IP,
    MLNX_ACL_FIELD_TYPE_INNER_IPV6         = (1 << 16) | MLNX_ACL_FIELD_TYPE_INNER_IP,
    MLNX_ACL_FIELD_TYPE_INNER_L4           = (1 << 17) | MLNX_ACL_FIELD_TYPE_INNER_IP,
} mlnx_acl_field_type_t;

typedef struct _acl_table_db_t {
    bool     is_used;
    bool     is_lock_inited;
    uint32_t queued;
    /* Valid only when group_references > 0 */
    sai_acl_table_group_type_t group_type;
    uint32_t                   group_references;
    sx_acl_id_t                table_id;
    sai_acl_stage_t            stage;
    sx_acl_region_id_t         region_id;
    sx_acl_size_t              region_size;
    sx_acl_key_type_t          key_type;
    bool                       is_dynamic_sized;
    uint32_t                   created_entry_count;
    psort_handle_t             psort_handle;
    cl_plock_t                 lock;
    sai_acl_range_type_t       range_types[SAI_ACL_RANGE_TYPE_COUNT];
    uint32_t                   range_type_count;
    acl_bind_point_type_list_t bind_point_types;
    mlnx_acl_field_type_t      table_fields_types;
    acl_table_wrapping_group_t wrapping_group;
    sx_acl_rule_offset_t       def_rules_offset;
    sx_acl_key_t               def_rule_key;
    bool                       is_ip_ident_used;
    bool                       is_aeth_syndrome_used;
    acl_udf_group_list_t       udf_group_list;
    uint32_t                   head_entry_index;
    uint32_t                   counter_ref;
} acl_table_db_t;

typedef uint16_t mlnx_acl_pbs_map_idx_t;
PACKED(struct _mlnx_acl_pbs_info_t {
    mlnx_acl_pbs_type_t type: 2;
    uint32_t idx: 17;              /* Should fit MAX_BRIDGE_PORTS (0x1F540) */
}, );
typedef struct _mlnx_acl_pbs_info_t mlnx_acl_pbs_info_t;
#define MLNX_ACL_PBS_INFO_INVALID {.type = MLNX_ACL_PBS_TYPE_INVALID}
#define MLNX_ACL_PBS_INFO_IS_VALID(info) ((info).type != MLNX_ACL_PBS_TYPE_INVALID)
#define MLNX_ACL_PBS_INFO_IS_FLOOD(info)       \
    (((info).type == MLNX_ACL_PBS_TYPE_MAP) && \
     ((info).idx == ACL_PBS_MAP_FLOOD_PBS_INDEX))
typedef struct _acl_pbs_map_key_t {
    uint32_t data[MLNX_U32BITARRAY_SIZE(MAX_PORTS_DB * 2)];
} acl_pbs_map_key_t;

typedef struct _acl_pbs_map_db_t {
    acl_pbs_map_key_t    key;
    mlnx_acl_pbs_entry_t entry;
} acl_pbs_map_entry_t;

typedef enum {
    SET_ROUTER_NOT_USED         = 0,
    SET_ROUTER_USED_BY_REDIRECT = 1,
    SET_ROUTER_USED_BY_SET_VRF  = 2,
} set_router_usage_t;

PACKED(struct _mlnx_acl_aeth_syndrome_info_t {
    uint32_t bth_opcode_enable: 1;
    uint32_t bth_opcode_value: 8;
    uint32_t bth_opcode_mask: 8;
    uint32_t aeth_syndrome_enable: 1;
    uint32_t aeth_syndrome_value: 8;
    uint32_t aeth_syndrome_mask: 8;
}, );

typedef struct _mlnx_acl_aeth_syndrome_info_t mlnx_acl_aeth_syndrome_info_t;

PACKED(struct _acl_entry_db_t {
    bool counter_byte_flag: 1;
    bool counter_packet_flag: 1;
    uint32_t sx_set_router_usage: 2;
    uint32_t next_entry_index: 19;
    uint32_t prev_entry_index: 19;
    uint32_t rule_cnt: 4;
    bool is_used;
    sx_span_session_id_t sx_span_session;
    uint32_t sx_prio;
    mlnx_acl_pbs_info_t pbs_info;
    sx_acl_rule_offset_t offset;
    sx_flow_counter_id_t sx_counter_id;
    sai_object_id_t hash_oid;
    mlnx_acl_aeth_syndrome_info_t aeth_syndrome_info;
}, );
typedef struct _acl_entry_db_t acl_entry_db_t;

typedef struct _acl_ip_ident_keys_t {
    uint32_t     refs;
    sx_acl_key_t sx_keys[ACL_IP_IDENT_FIELD_BYTE_COUNT];
} acl_ip_ident_keys_t;

typedef struct _acl_def_rule_mc_container_t {
    bool                 is_created;
    sx_mc_container_id_t mc_container;
} acl_def_rule_mc_container_t;

typedef enum {
    KEY_RC = 0,
    KEY_RD = 1,
    KEY_COUNT,
} aeth_syndrome_key_type_t;
typedef struct _acl_aeth_syndrome_keys_t {
    uint32_t     refs;
    sx_acl_key_t sx_keys[KEY_COUNT];
} acl_aeth_syndrome_keys_t;

typedef struct _acl_setting_tbl_t {
    bool       lazy_initialized;
    cl_plock_t lock;
#ifndef _WIN32
    pthread_cond_t  psort_thread_init_cond;
    pthread_cond_t  rpc_thread_init_cond;
    pthread_mutex_t cond_mutex;
#endif
    bool                        psort_thread_start_flag;
    bool                        psort_thread_stop_flag;
    bool                        rpc_thread_start_flag;
    bool                        rpc_thread_stop_flag;
    bool                        psort_thread_suspended;
    bool                        psort_thread_suspended_ack;
    uint32_t                    port_lists_count;
    acl_ip_ident_keys_t         ip_ident_keys;
    acl_def_rule_mc_container_t def_mc_container;
    uint32_t                    entry_db_first_free_index;
    uint32_t                    entry_db_indexes_allocated;
    acl_aeth_syndrome_keys_t    aeth_syndrome_keys;
} acl_setting_tbl_t;

typedef struct _acl_bind_point_target_data_t {
    bool                      is_set;
    sx_acl_direction_t        sx_direction;
    sai_acl_bind_point_type_t sai_bind_point_type;
    union {
        sx_port_log_id_t    sx_port;
        sx_rif_id_t         rif;
        sx_acl_vlan_group_t vlan_group;
    };
} acl_bind_point_target_data_t;

typedef struct _acl_bind_point_data_t {
    bool                         is_object_set;
    bool                         is_sx_group_created;
    acl_index_t                  acl_index;
    sx_acl_id_t                  sx_group;
    acl_bind_point_target_data_t target_data;
} acl_bind_point_data_t;

typedef struct _acl_bind_point_t {
    acl_bind_point_data_t ingress_data;
    acl_bind_point_data_t egress_data;
} acl_bind_point_t;

typedef struct _acl_bind_point_vlan_t {
    bool     is_bound;
    uint32_t vlan_group_index;
} acl_bind_point_vlan_t;

typedef struct _acl_vlan_group_t {
    acl_bind_point_data_t bind_data;
    uint32_t              vlan_count;
    sx_acl_vlan_group_t   sx_vlan_group;
} acl_vlan_group_t;

typedef struct _acl_bind_points_db_t {
    acl_bind_point_t      ports_lags[MAX_PORTS_DB * 2];
    acl_bind_point_vlan_t vlans[ACL_VLAN_COUNT];
    acl_bind_point_t      rifs[]; /* ACL_RIF_COUNT */
} acl_bind_points_db_t;

typedef struct _acl_bind_point_index_t {
    sai_acl_bind_point_type_t type;
    uint32_t                  index;
} acl_bind_point_index_t;

typedef struct _acl_group_bound_to_t {
    uint32_t               count;
    acl_bind_point_index_t indexes[]; /* SAI_ACL_MAX_BIND_POINT_BOUND */
} acl_group_bound_to_t;

typedef struct _acl_group_member_t {
    uint32_t table_index;
    uint32_t table_prio;
} acl_group_member_t;

typedef struct _acl_group_db_t {
    bool                       is_used;
    sai_acl_table_group_type_t search_type;
    sai_acl_stage_t            stage;
    acl_bind_point_type_list_t bind_point_types;
    uint32_t                   members_count;
    acl_group_member_t         members[];
} acl_group_db_t;

typedef struct {
    sx_acl_id_t             group_id;
    sx_acl_group_priority_t priority;
} perport_ipcnt_group_data_t;

typedef struct {
    perport_ipcnt_group_data_t ingress_group;
    perport_ipcnt_group_data_t egress_group;
} perport_ipcnt_group_t;

enum {
    /* below is ingress direction */
    PERPORT_IPCNT_IN_FIRST_INDEX = 0,
    /* SAI_PORT_STAT_IP_IN_UCAST_PKTS */
    PERPORT_IPCNT_IN_IP_UCAST = PERPORT_IPCNT_IN_FIRST_INDEX,
    /* SAI_PORT_STAT_IP_IN_NON_UCAST_PKTS */
    PERPORT_IPCNT_IN_IP_NON_UCAST = 1,
    /* SAI_PORT_STAT_IPV6_IN_UCAST_PKTS */
    PERPORT_IPCNT_IN_IP6_UCAST = 2,
    /* SAI_PORT_STAT_IPV6_IN_NON_UCAST_PKTS */
    PERPORT_IPCNT_IN_IP6_NON_UCAST = 3,
    /* above is ingress direction */
    PERPORT_IPCNT_IN_LAST_INDEX = PERPORT_IPCNT_IN_IP6_NON_UCAST,
    /* below is egress direction */
    PERPORT_IPCNT_OUT_FIRST_INDEX = 4,
    /* SAI_PORT_STAT_IP_OUT_UCAST_PKTS */
    PERPORT_IPCNT_OUT_IP_UCAST = PERPORT_IPCNT_OUT_FIRST_INDEX,
    /* SAI_PORT_STAT_IP_OUT_NON_UCAST_PKTS */
    PERPORT_IPCNT_OUT_IP_NON_UCAST = 5,
    /* SAI_PORT_STAT_IPV6_OUT_UCAST_PKTS */
    PERPORT_IPCNT_OUT_IP6_UCAST = 6,
    /* SAI_PORT_STAT_IPV6_OUT_NON_UCAST_PKTS */
    PERPORT_IPCNT_OUT_IP6_NON_UCAST = 7,
    /* above is egress direction */
    PERPORT_IPCNT_OUT_LAST_INDEX = PERPORT_IPCNT_OUT_IP6_NON_UCAST,

    PERPORT_IPCNT_NUMBER_IN_PORT = 8,
};

#define sai_2_ppipcnt_port_index(sai_port_index) ((sai_port_index) + 1)
#define ppipcnt_2_sai_port_index(ppipcnt_pindex) ((ppipcnt_pindex) - 1)

/* offset_2_port is to record the corresponding port_index,
 * and the port_index start from 1, use sai_2_ppipcnt_port_index
 * to set and ppipcnt_2_sai_port_index to get, 0 means invalid */
typedef struct {
    sx_acl_key_type_t    key_handle;
    sx_acl_region_id_t   region_id;
    sx_acl_id_t          acl_id;
    sx_acl_size_t        current_size;
    sx_acl_rule_offset_t free_space;
    uint16_t             offset_2_port[MAX_PORTS_DB];
} perport_ipcnt_table_data_t;

#define PERPORT_IPCNT_LAG_TABLE_SIZE 16
typedef struct {
    uint32_t                   size_delta;
    perport_ipcnt_table_data_t ingress_table;
    perport_ipcnt_table_data_t ingress_lag_table;
    perport_ipcnt_table_data_t egress_table;
} perport_ipcnt_table_t;

enum {
    PERPORT_IPCNT_KEY_L3_TYPE = 0,
    PERPORT_IPCNT_KEY_DMAC_UC = 1,
    PERPORT_IPCNT_KEY_PORT    = 2,
    PERPORT_IPCNT_KEY_MAX,
};

typedef struct {
    sx_acl_rule_offset_t entry_id[PERPORT_IPCNT_NUMBER_IN_PORT];
    /* counter_pool_idx start from 1 */
    uint16_t             counter_pool_idx;
    uint8_t              perport_ipcnt_flag;
    uint8_t              reserved;
    sx_mc_container_id_t port_list_id;
} perport_ipcnt_entry_t;

#define PERPORT_IPCNT_COUNTER_RESIZE 32
/* port_index indicate which port is using this pool, it start from 1
 * use sai_2_ppipcnt_port_index to set and
 * ppipcnt_2_sai_port_index to get, 0 means invalid */
typedef struct {
    uint8_t              is_used;
    uint8_t              reserved;
    uint16_t             port_index;
    sx_flow_counter_id_t ip_counters[PERPORT_IPCNT_NUMBER_IN_PORT];
} perport_ipcnt_pool_data_t;

typedef struct {
    uint16_t                  current_size;
    uint16_t                  reserved;
    perport_ipcnt_pool_data_t pool_data[MAX_PORTS_DB];
} perport_ipcnt_pool_t;

typedef struct _mlnx_acl_db_t {
    uint8_t              *db_base_ptr;
    acl_table_db_t       *acl_table_db;
    acl_entry_db_t       *acl_entry_db;
    acl_setting_tbl_t    *acl_settings_tbl;
    acl_pbs_map_entry_t  *acl_pbs_map_db;
    acl_bind_points_db_t *acl_bind_points;
    /* do not access directly as contains dynamic part, use sai_acl_db_group_ptr */
    acl_group_db_t        *acl_groups_db;
    acl_vlan_group_t      *acl_vlan_groups_db;
    acl_group_bound_to_t  *acl_group_bound_to_db;
    mlnx_udf_db_t          udf_db;
    perport_ipcnt_group_t *perport_ipcnt_group;
    perport_ipcnt_table_t *perport_ipcnt_table;
    perport_ipcnt_entry_t *perport_ipcnt_entry;
    perport_ipcnt_pool_t  *perport_ipcnt_pool;
} mlnx_acl_db_t;

sai_status_t mlnx_acl_port_lag_event_handle_locked(_In_ const mlnx_port_config_t *port, _In_ acl_event_type_t event);
sai_status_t mlnx_acl_port_lag_event_handle_unlocked(_In_ const mlnx_port_config_t *port, _In_ acl_event_type_t event);

extern mlnx_acl_db_t *g_sai_acl_db_ptr;
extern uint32_t       g_sai_acl_db_pbs_map_size;

typedef struct _mlnx_policer_to_trap_group_bind_params {
    sai_attribute_value_t attr_prio_value;
} mlnx_policer_to_trap_group_bind_params;

#define MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT             (14)
#define MLNX_SAI_FG_HASH_FIELD_REG_ID_MAX_COUNT       (8)
#define MLNX_SAI_FG_HASH_FIELD_SHM_RM_ARRAY_MAX_COUNT (8)

extern const char* sai_metadata_sai_native_hash_field_t_enum_values_short_names[];
#define MLNX_SAI_NATIVE_HASH_FIELD_STR(field) (sai_metadata_sai_native_hash_field_t_enum_values_short_names[field])

typedef struct _mlnx_sai_fg_hash_field_t {
    sai_object_id_t         fg_field_id;
    sai_native_hash_field_t field;
    sai_ip_addr_t           ip_mask;
    uint32_t                sequence_id;
    sx_register_key_t       reg_id[MLNX_SAI_FG_HASH_FIELD_REG_ID_MAX_COUNT];
    mlnx_shm_rm_array_idx_t shm_rm_array_idx[MLNX_SAI_FG_HASH_FIELD_SHM_RM_ARRAY_MAX_COUNT];
} mlnx_sai_fg_hash_field_t;

typedef struct _mlnx_hash_obj_t {
    sai_object_id_t          hash_id;
    uint64_t                 field_mask;
    udf_group_mask_t         udf_group_mask;
    mlnx_sai_fg_hash_field_t fg_fields[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT];
    uint8_t                  fg_hash_ref_count;
} mlnx_hash_obj_t;
typedef enum _mlnx_switch_hash_object_id {
    SAI_HASH_ECMP_ID = 0,
    SAI_HASH_ECMP_IP4_ID,
    SAI_HASH_ECMP_IPINIP_ID,
    SAI_HASH_ECMP_IP6_ID,
    SAI_HASH_ECMP_ID_MAX = SAI_HASH_ECMP_IP6_ID,
    SAI_HASH_LAG_ID,
    SAI_HASH_LAG_IP4_ID,
    SAI_HASH_LAG_IPINIP_ID,
    SAI_HASH_LAG_IP6_ID,
    SAI_HASH_FG_1_ID,
    SAI_HASH_FG_2_ID,
    SAI_HASH_MAX_OBJ_ID
} mlnx_switch_usage_hash_object_id_t;

sai_status_t mlnx_hash_config_apply_to_port(_In_ sx_port_log_id_t sx_port);

sai_status_t mlnx_udf_group_db_index_to_sx_acl_keys(_In_ uint32_t       udf_group_db_index,
                                                    _Out_ sx_acl_key_t *sx_acl_keys,
                                                    _Inout_ uint32_t   *flex_acl_key_ids_num,
                                                    _Inout_ uint32_t   *sx_acl_key_count);
sai_status_t mlnx_udf_group_length_get(_In_ uint32_t udf_group_db_index, _Out_ uint32_t *size);
sai_status_t mlnx_udf_group_oid_validate_and_fetch(_In_ sai_object_id_t udf_group_id,
                                                   _In_ uint32_t        attr_index,
                                                   _Out_ uint32_t      *udf_group_db_index);
sai_status_t mlnx_udf_group_objlist_validate_and_fetch_mask(_In_ const sai_object_list_t *udf_groups,
                                                            _In_ uint32_t                 attr_index,
                                                            _Out_ udf_group_mask_t       *udf_group_mask);
sai_status_t mlnx_acl_udf_group_list_references_add(_In_ const acl_udf_group_list_t udf_group_list);
sai_status_t mlnx_acl_udf_group_list_references_del(_In_ const acl_udf_group_list_t udf_group_list);
sai_status_t mlnx_udf_group_mask_references_add(_In_ udf_group_mask_t udf_group_mask);
sai_status_t mlnx_udf_group_mask_references_del(_In_ udf_group_mask_t udf_group_mask);
sai_status_t mlnx_udf_group_mask_to_objlist(_In_ udf_group_mask_t udf_group_mask, _Out_ sai_object_list_t *objlist);
sai_status_t mlnx_udf_group_mask_to_ecmp_hash_fields(_In_ udf_group_mask_t              udf_group_mask,
                                                     _Out_ sx_router_ecmp_hash_field_t *ecmp_hash_fields,
                                                     _Out_ uint32_t                    *ecmp_hash_field_count);
sai_status_t mlnx_udf_group_mask_is_hash_applicable(_In_ udf_group_mask_t                   udf_group_mask,
                                                    _In_ mlnx_switch_usage_hash_object_id_t hash_oper_type,
                                                    _In_ bool                              *is_applicable);
sai_status_t mlnx_udf_group_sx_gp_registers_create_destroy_spc2(_In_ sx_access_cmd_t         cmd,
                                                                _In_ const sx_gp_register_e *reg_ids,
                                                                _In_ uint32_t                reg_ids_count);
sai_status_t mlnx_udf_group_sx_reg_ext_point_set_spc2(_In_ sx_access_cmd_t              cmd,
                                                      _In_ sx_gp_register_e             reg_id,
                                                      _In_ const sx_extraction_point_t *ext_point_list,
                                                      _In_ uint32_t                     ext_point_cnt);
sai_status_t mlnx_custom_bytes_set(_In_ sx_access_cmd_t                             cmd,
                                   _In_ const sx_acl_custom_bytes_set_attributes_t *attrs,
                                   _Inout_ sx_acl_key_t                            *keys,
                                   _In_ uint32_t                                    length);
sai_status_t mlnx_sai_udf_issu_flow_validate_udf_group_hw_configured(uint32_t udf_group_db_index);
sai_status_t mlnx_sai_udf_check_udf_db_is_set_to_hw(void);
/*
 * GP register usage control functionality
 */
typedef enum _mlnx_gp_reg_usage_t {
    GP_REG_USED_NONE,
    GP_REG_USED_HASH_1,
    GP_REG_USED_HASH_2,
    GP_REG_USED_UDF,
    GP_REG_USED_IP_IDENT,
    GP_REG_USED_AETH_SYNDROME_RC,
    GP_REG_USED_AETH_SYNDROME_RD
} mlnx_gp_reg_usage_t;

typedef struct _mlnx_gp_reg_db_t {
    mlnx_shm_array_hdr_t mlnx_array;
    mlnx_gp_reg_usage_t  gp_usage;
} mlnx_gp_reg_db_t;

/* ISSU gp register */
#ifdef _WIN32
PACKED(struct _mlnx_issu_gp_reg_ip_ident_info {
    int dummy;
}, );
#else
PACKED(struct _mlnx_issu_gp_reg_ip_ident_info {
}, );
#endif

typedef struct _mlnx_issu_gp_reg_ip_ident_info mlnx_issu_gp_reg_ip_ident_info;

PACKED(struct _mlnx_issu_gp_reg_udf_info {
    sai_udf_group_type_t udf_group_type;
    uint32_t udf_group_length;
    /* mlnx_udf_match_type_t */
    uint32_t udf_match_type_bitmask;
    sai_uint16_t udf_offsets_arr[4];
}, );

typedef struct _mlnx_issu_gp_reg_udf_info mlnx_issu_gp_reg_udf_info;

PACKED(struct _mlnx_issu_gp_reg_pbh_info {
    /* register ids stored in order as they were allocated for fine grained hash fields purposes */
    sx_gp_register_e reg_ids[SX_GP_REGISTER_LAST_E];
    /* idx is sx_gp_register, value is idx to corresponding native field in list */
    uint8_t gp_reg_fg_fields_map[SX_GP_REGISTER_LAST_E];
    sai_native_hash_field_t native_fields_list[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT];
    sai_ip_addr_t masks[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT];
    uint32_t sequence_ids[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT];
}, );

typedef struct _mlnx_issu_gp_reg_pbh_info mlnx_issu_gp_reg_pbh_info;

/* ISSU gp register for aeth_syndrome */
#ifdef _WIN32
PACKED(struct _mlnx_issu_gp_reg_aeth_syndrome_info {
    int dummy;
}, );
#else
PACKED(struct _mlnx_issu_gp_reg_aeth_syndrome_info {
}, );
#endif

typedef struct _mlnx_issu_gp_reg_aeth_syndrome_info mlnx_issu_gp_reg_aeth_syndrome_info;

PACKED(struct _mlnx_sai_issu_gp_reg_info_elem {
    mlnx_gp_reg_usage_t type;
    uint32_t gp_reg_bitmask;
    union {
        mlnx_issu_gp_reg_ip_ident_info ip_ident;           /* used for ip identification gp register */
        mlnx_issu_gp_reg_udf_info udf;                     /* used for udf gp register */
        mlnx_issu_gp_reg_pbh_info pbh;                     /* used for pbh gp registers */
        mlnx_issu_gp_reg_aeth_syndrome_info aeth_syndrome; /* used for aeth_syndrome gp registers */
    };
}, );
typedef struct _mlnx_sai_issu_gp_reg_info_elem mlnx_sai_issu_gp_reg_info_elem;

sai_status_t mlnx_gp_reg_db_alloc(_Out_ mlnx_gp_reg_db_t **gp_reg_data, _Out_ mlnx_shm_rm_array_idx_t  *idx);
sai_status_t mlnx_gp_reg_db_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ mlnx_gp_reg_db_t **gp_reg);
sai_status_t mlnx_gp_reg_db_alloc_by_gp_reg_id(_Out_ mlnx_gp_reg_db_t **gp_reg_data, sx_gp_register_e reg_id);
sai_status_t mlnx_gp_reg_db_alloc_first_free(_Out_ mlnx_gp_reg_db_t       **gp_reg_data,
                                             _Out_ mlnx_shm_rm_array_idx_t *idx,
                                             _In_ mlnx_gp_reg_usage_t       reg_usage);
sai_status_t mlnx_gp_reg_db_free(_In_ mlnx_shm_rm_array_idx_t idx);

typedef enum {
    INTERNAL_ACL_OP_ADD_PORT,
    INTERNAL_ACL_OP_DEL_PORT,
    INTERNAL_ACL_OP_ADD_LAG,
    INTERNAL_ACL_OP_DEL_LAG,
    INTERNAL_ACL_OP_ADD_PORT_TO_LAG,
    INTERNAL_ACL_OP_DEL_PORT_FROM_LAG,
} internal_acl_op_types;

#define round_up_perport_ipcnt_counter_num(bulk_num, flow_counter_num)          \
    do {                                                                        \
        bulk_num = (flow_counter_num <= 16) ? 16 : (                            \
            (flow_counter_num <= 32) ? 32 : (                                   \
                (flow_counter_num <= 64) ? 64 : (                               \
                    (flow_counter_num <= 128) ? 128 : (                         \
                        (flow_counter_num <= 256) ? 256 : (                     \
                            (flow_counter_num <= 512) ? 512 : (                 \
                                (flow_counter_num <= 1024) ? 1024 : 2048)))))); \
    } while(0)

bool mlnx_perport_ipcnt_is_enable_nolock(void);
bool mlnx_perport_ipcnt_is_enable(void);
void perport_ipcnt_get_counter_pool_data(_In_ uint32_t                     pool_data_index,
                                         _Out_ perport_ipcnt_pool_data_t **pool_data);
void perport_ipcnt_get_counter_base_id(_In_ uint32_t               pool_data_index,
                                       _Out_ sx_flow_counter_id_t *counter_id);
sai_status_t mlnx_perport_ipcnt_get_counter_base_id_by_port(_In_ sai_object_id_t        port_id,
                                                            _Out_ sx_flow_counter_id_t *counter_id);
sai_status_t mlnx_perport_ipcnt_init(_In_ uint32_t port_number);
sai_status_t mlnx_perport_ipcnt_ops(_In_ sx_port_log_id_t port_id, _In_ uint16_t port_index, _In_ uint32_t op_type);

sai_status_t mlnx_udf_db_udf_group_size_get(uint32_t *db_size);
sai_status_t mlnx_sai_udf_get_issu_udf_info(_In_ uint32_t                    group_db_index,
                                            _Out_ mlnx_issu_gp_reg_udf_info *udf_info);
sai_status_t mlnx_sai_udf_get_gp_reg_issu_info_from_udf_db(_In_ uint32_t                         group_db_index,
                                                           _Out_ mlnx_sai_issu_gp_reg_info_elem *elem,
                                                           _Inout_ uint32_t                     *count);
sai_status_t mlnx_sai_issu_storage_get_pbh_stored_gp_reg_usage(_In_ uint32_t                        fields_count,
                                                               _In_ const mlnx_sai_fg_hash_field_t *fields_list,
                                                               _In_ bool                            optimized,
                                                               _Out_ mlnx_gp_reg_usage_t           *gp_reg_usage_prev);
sai_status_t mlnx_sai_issu_storage_pbh_gp_reg_idx_lookup(_In_ sai_native_hash_field_t field,
                                                         _In_ mlnx_gp_reg_usage_t     type,
                                                         _Out_ sx_gp_register_e      *reg_id_out);
sai_status_t mlnx_sai_issu_storage_ip_ident_gp_reg_idx_lookup(_Out_ sx_gp_register_e *reg_id);
sai_status_t mlnx_sai_issu_storage_udf_gp_reg_idx_lookup(_Out_ sx_gp_register_e *reg_id,
                                                         _In_ uint32_t           group_db_index);
sai_status_t mlnx_sai_issu_storage_aeth_syndrome_gp_reg_idx_lookup(_In_ mlnx_gp_reg_usage_t type,
                                                                   _Out_ sx_gp_register_e  *reg_id);
/*
 *  Corresponding union member should be picked by mlnx_sai_bind_policer based on the type of sai_object
 */
typedef union _mlnx_policer_bind_params {
    mlnx_port_policer_type port_policer_type;                 /*used for port binding*/
} mlnx_policer_bind_params;

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t find_port_in_db(_In_ sai_object_id_t port, _Out_ uint32_t *index);

sai_status_t db_get_sai_policer_data(_In_ sai_object_id_t            sai_policer_id,
                                     _Out_ mlnx_policer_db_entry_t** policer_data);
void db_reset_policer_entry(_In_ mlnx_policer_db_entry_t* policers_entry_p);
sai_status_t db_find_sai_policer_entry_ind(_In_ sx_policer_id_t           sx_policer,
                                           _Out_ mlnx_shm_rm_array_idx_t* idx_p);

/*
 *  Binds sai_policer to a given sai_object.
 */
sai_status_t mlnx_policer_oid_create(_In_ mlnx_shm_rm_array_idx_t idx,
                                     _Out_ sai_object_id_t      * policer_oid);
sai_status_t mlnx_sai_policer_bind_set_impl(_In_ sai_object_id_t        sai_object_id,
                                            _In_ sai_object_id_t        sai_policer,
                                            _In_ mlnx_port_policer_type policer_function);
sai_status_t mlnx_sai_bind_policer(_In_ sai_object_id_t           sai_object,
                                   _In_ sai_object_id_t           sai_policer,
                                   _In_ mlnx_policer_bind_params* bind_params);
sai_status_t mlnx_sai_unbind_policer(_In_ sai_object_id_t sai_object, _In_ mlnx_policer_bind_params* bind_params);
sai_status_t mlnx_sai_get_or_create_regular_sx_policer_for_bind(_In_ sai_object_id_t   sai_policer,
                                                                _In_ bool              is_host_if_policer,
                                                                _In_ bool              is_span_policer,
                                                                _Out_ sx_policer_id_t* sx_policer_id);
sai_status_t mlnx_sai_get_or_create_acl_mirror_sx_policer_for_bind(_In_ sai_object_id_t   sai_policer,
                                                                   _Out_ sx_policer_id_t* sx_policer_id);
sai_status_t mlnx_sai_update_span_session_policer(_In_ sx_span_session_id_t span_session_id,
                                                  _In_ sai_object_id_t      prev_policer,
                                                  _In_ sai_object_id_t      new_policer);

/* SAI DB R/w is required */
sai_status_t mlnx_sai_unbind_policer_from_port(_In_ sai_object_id_t           sai_port,
                                               _In_ mlnx_policer_bind_params* bind_params);
sai_status_t mlnx_sai_bind_policer_to_port(_In_ sai_object_id_t           sai_port,
                                           _In_ sai_object_id_t           sai_policer,
                                           _In_ mlnx_policer_bind_params* bind_params);

void log_sx_policer_attributes(_In_ sx_policer_id_t sx_policer, _In_ sx_policer_attributes_t* sx_attribs);

sai_status_t mlnx_sai_buffer_log_set(_In_ sx_verbosity_level_t level);

sai_status_t mlnx_port_samplepacket_params_clear(_In_ mlnx_port_config_t *port_config, _In_ bool is_soft);
sai_status_t mlnx_port_samplepacket_params_clone(_In_ mlnx_port_config_t *to, _In_ const mlnx_port_config_t *from);
sai_status_t mlnx_port_mirror_params_check(_In_ const mlnx_port_config_t *port1, _In_ const mlnx_port_config_t *port2);
sai_status_t mlnx_port_mirror_params_clear(_In_ mlnx_port_config_t *port_config);
sai_status_t mlnx_port_mirror_sessions_clone(_In_ mlnx_port_config_t *to, _In_ const mlnx_port_config_t *from);
sai_status_t mlnx_port_storm_control_policer_params_clear(_In_ mlnx_port_config_t *port_config, _In_ bool is_soft);
sai_status_t mlnx_port_storm_control_policer_params_clone(_In_ mlnx_port_config_t       *to,
                                                          _In_ const mlnx_port_config_t *from);
sai_status_t mlnx_port_egress_block_clone(_In_ mlnx_port_config_t *to, _In_ const mlnx_port_config_t *from);
sai_status_t mlnx_port_egress_block_clear(_In_ sx_port_log_id_t sx_port_id);
sai_status_t mlnx_port_egress_block_is_in_use(_In_ sx_port_log_id_t sx_port_id, _Out_ bool            *is_in_use);
sai_status_t mlnx_sx_port_list_compare(_In_ const sx_port_log_id_t *ports1,
                                       _In_ uint32_t                ports1_count,
                                       _In_ const sx_port_log_id_t *ports2,
                                       _In_ uint32_t                ports2_count,
                                       _Out_ bool                  *equal);

#define MLNX_INVALID_SAMPLEPACKET_SESSION 0
#define MLNX_SAMPLEPACKET_SESSION_MIN     1
#define MLNX_SAMPLEPACKET_SESSION_MAX     256

typedef struct _mlnx_samplepacket_t {
    bool                    in_use;
    uint32_t                sai_sample_rate;
    sai_samplepacket_type_t sai_type;
    sai_samplepacket_mode_t sai_mode;
} mlnx_samplepacket_t;

#define MLNX_MAX_TUNNEL_IPINIP        (g_resource_limits.tunnel_ipinip_num_max)
#define MLNX_MAX_TUNNEL_NVE           (g_resource_limits.tunnel_nve_num_max)
#define MAX_TUNNEL_DB_SIZE            (MLNX_MAX_TUNNEL_IPINIP + MLNX_MAX_TUNNEL_NVE)
#define MLNX_TUNNELTABLE_SIZE         256
#define MLNX_TUNNEL_MAP_LIST_MAX      50
#define MLNX_TUNNEL_MAP_MIN           0
#define MLNX_TUNNEL_MAP_MAX           12
#define MLNX_TUNNEL_MAP_ENTRY_INVALID 0
#define MLNX_TUNNEL_MAP_ENTRY_MIN     1
/* SONiC requires 8000 tunnel map entries */
#define MLNX_TUNNEL_MAP_ENTRY_MAX     8001
#define MLNX_BMTOR_BRIDGE_MAX         512
#define MLNX_TUNNEL_TO_TUNNEL_MAP_MAX 1000
#define MAX_IPINIP_TUNNEL             256
#define MAX_VXLAN_TUNNEL              1
#define MAX_TUNNEL                    257
#define MAX_UPLINK_PORTS              40    /* Max number of supported uplink ports in dscp remapping */
#define MAX_DSCP_REMAPPING_ACL_RULE   8     /* Max ACL rule number for encap and decap in dscp remapping */
#define UPLINK_LOSSLESS_PG_COUNT      4     /* The lossless pg count for uplink port in dscp remapping */

typedef struct _mlnx_tunneltable_t {
    bool                        in_use;
    sx_tunnel_decap_entry_key_t sdk_tunnel_decap_key_ipv4;
    uint32_t                    tunnel_db_idx;
    bool                        tunnel_lazy_created;
} mlnx_tunneltable_t;

typedef struct _mlnx_vxlan_udp_sport_acl_t {
    bool               is_acl_created;
    sx_acl_key_type_t  key;
    sx_acl_id_t        acl_group;
    sx_acl_id_t        acl;
    sx_acl_region_id_t region;
} mlnx_vxlan_udp_sport_acl_t;

typedef struct _mlnx_vxlan_udp_sport_initial_config_t {
    bool                              is_configured;
    sai_tunnel_vxlan_udp_sport_mode_t src_port_mode;
    int16_t                           src_port_base;
    int8_t                            src_port_mask;
} mlnx_vxlan_udp_sport_initial_config_t;

/*
 *  SAI tunnel hash commands
 */
typedef enum _mlnx_tunnel_hash_cmd_t {
    SAI_TUNNEL_HASH_CMD_SET_ZERO,
    SAI_TUNNEL_HASH_CMD_CALCULATE,
    SAI_TUNNEL_HASH_CMD_FIXED_VALUE,
    SAI_TUNNEL_HASH_CMD_MODIFIED_HASH
} mlnx_tunnel_hash_cmd_t;

/* VXLAN: Idx from 0 to MLNX_MAX_TUNNEL_NVE-1
 * IP in IP: Idx from MLNX_MAX_TUNNEL_NVE to MAX_TUNNEL_DB_SIZE-1 */
typedef struct _mlnx_tunnel_entry_t {
    bool                                  is_used;
    sai_tunnel_type_t                     sai_tunnel_type;
    sx_tunnel_id_t                        sx_tunnel_id_ipv4;
    sx_tunnel_id_t                        sx_tunnel_id_ipv6;
    bool                                  ipv4_created;
    bool                                  ipv6_created;
    bool                                  is_main_tunnel;
    sx_router_interface_t                 sx_overlay_rif_ipv6;
    sai_object_id_t                       sai_underlay_rif;
    bool                                  is_tunnel_p2p;
    uint16_t                              ipip_tunnel_p2p_refcnt;
    sai_ip_address_t                      sai_underlay_sip;
    sai_ip_address_t                      sai_underlay_dip;
    sai_object_id_t                       sai_tunnel_map_encap_id_array[MLNX_TUNNEL_MAP_MAX];
    uint32_t                              sai_tunnel_map_encap_cnt;
    sai_object_id_t                       sai_tunnel_map_decap_id_array[MLNX_TUNNEL_MAP_MAX];
    uint32_t                              sai_tunnel_map_decap_cnt;
    sx_tunnel_attribute_t                 sx_tunnel_attr;
    sx_tunnel_ttl_data_t                  sdk_encap_ttl_data_attrib;
    sx_tunnel_ttl_data_t                  sdk_decap_ttl_data_attrib;
    sx_tunnel_cos_data_t                  sdk_encap_cos_data;
    sx_tunnel_cos_data_t                  sdk_decap_cos_data;
    uint32_t                              term_table_cnt;
    mlnx_vxlan_udp_sport_initial_config_t init_vxlan_sport_config;
    sai_tunnel_vxlan_udp_sport_mode_t     src_port_mode;
    int32_t                               src_port_base;
    int8_t                                src_port_mask;
    mlnx_vxlan_udp_sport_acl_t            vxlan_acl;
    sai_object_id_t                       encap_qos_tc_and_color_to_dscp_map;
    sai_object_id_t                       encap_qos_tc_to_queue_map;
    sai_object_id_t                       decap_qos_dscp_to_tc_map;
    sai_object_id_t                       decap_qos_tc_to_priority_group_map;
} mlnx_tunnel_entry_t;

#define MLNX_MAX_TUNNEL_TYPES_NUM  SAI_TUNNEL_TYPE_MPLS + 1
#define TUNNEL_IPIP_P2P_OVERLAY_IF sx_tunnel_attr.attributes.ipinip_p2p.overlay_rif
#define TUNNEL_IPIP_P2P_UIF        sx_tunnel_attr.attributes.ipinip_p2p.underlay_rif

typedef struct _mlnx_switch_tunnel_t {
    sai_object_id_t                   switch_tunnel_id;
    sai_tunnel_vxlan_udp_sport_mode_t src_port_mode;
    uint16_t                          src_port_base;
    uint8_t                           src_port_mask;
} mlnx_switch_tunnel_t;

typedef struct _tunnel_map_t {
    bool                  in_use;
    sai_tunnel_map_type_t tunnel_map_type;
    uint32_t              tunnel_cnt;
    uint32_t              tunnel_idx[MAX_TUNNEL];
    uint32_t              tunnel_map_entry_cnt;
    uint32_t              tunnel_map_entry_head_idx;
    uint32_t              tunnel_map_entry_tail_idx;
} mlnx_tunnel_map_t;

typedef struct _tunnel_map_entry_pair_info_t {
    bool     pair_exist;
    bool     pair_already_bound_to_tunnel;
    uint32_t pair_tunnel_map_entry_idx;
    uint32_t bmtor_bridge_db_idx;
} tunnel_map_entry_pair_info_t;

typedef struct _tunnel_map_entry_t {
    bool                  in_use;
    sai_tunnel_map_type_t tunnel_map_type;
    sai_object_id_t       tunnel_map_id;
    uint8_t               oecn_key;
    uint8_t               oecn_value;
    uint8_t               uecn_key;
    uint8_t               uecn_value;
    uint16_t              vlan_id_key;
    uint16_t              vlan_id_value;
    uint32_t              vni_id_key;
    uint32_t              vni_id_value;
    sai_object_id_t       bridge_id_key;
    sai_object_id_t       bridge_id_value;
    sai_object_id_t       vr_id_key;
    sai_object_id_t       vr_id_value;
    uint32_t              prev_tunnel_map_entry_idx;
    uint32_t              next_tunnel_map_entry_idx;
    /* only used for bridge to vni and vni to bridge type */
    tunnel_map_entry_pair_info_t pair_per_vxlan_array[MAX_VXLAN_TUNNEL];
} mlnx_tunnel_map_entry_t;

typedef struct _mlnx_bmtor_bridge_t {
    bool            in_use;
    bool            is_default;
    sai_object_id_t connected_vrf_oid;
    sai_object_id_t bridge_oid;
    sai_object_id_t rif_oid;
    sai_object_id_t bridge_bport_oid;
    sai_object_id_t tunnel_bport_oid;
    sai_object_id_t tunnel_id;
    sx_tunnel_id_t  sx_vxlan_tunnel_id;
    uint32_t        vni;
    uint32_t        counter;
} mlnx_bmtor_bridge_t;

typedef struct _mlnx_tc_remapping_t {
    mlnx_qos_map_params_t from;
    mlnx_qos_map_params_t to;
    uint8_t               count;
} mlnx_tc_remapping_t;

typedef enum _mlnx_dscp_remapping_tunnel_type_t {
    DSCP_REMAPPING_TUNNEL_TYPE_ENCAP,
    DSCP_REMAPPING_TUNNEL_TYPE_DECAP,
    DSCP_REMAPPING_TUNNEL_TYPE_MAX
} mlnx_dscp_remapping_tunnel_type_t;

typedef struct _tunnel_qos_data_t {
    sai_object_id_t encap_tc_to_dscp_mapping;
    sai_object_id_t encap_tc_to_queue_mapping;
    sai_object_id_t encap_rif_oid;
    sai_object_id_t decap_dscp_to_tc_mapping;
    sai_object_id_t decap_tc_to_pg_mapping;
    sai_object_id_t decap_rif_oid;
} tunnel_qos_data_t;

typedef struct _port_qos_db_t {
    sai_object_id_t  effective_tc_to_pg_mapping;
    sai_object_id_t  effective_tc_to_queue_mapping;
    sx_port_log_id_t uplink_port_list[MAX_UPLINK_PORTS];
    sai_object_id_t  uplink_tc_to_pg_mapping[MAX_UPLINK_PORTS];
    sai_object_id_t  uplink_tc_to_queue_mapping[MAX_UPLINK_PORTS];
    bool             uplink_port_list_in_use[MAX_UPLINK_PORTS];
    bool             uplink_port_rewrite_done[MAX_UPLINK_PORTS];
} port_qos_db_t;

typedef struct _remapping_acl_data_t {
    sai_object_id_t      acl_binding_rif;
    sx_acl_id_t          group_id;
    sx_acl_key_type_t    key_handle;
    sx_acl_region_id_t   region_id;
    sx_acl_id_t          acl_id;
    sx_acl_rule_offset_t acl_rule_id[MLNX_QOS_MAP_CODES_MAX];
    uint8_t              acl_rule_count;
    mlnx_tc_remapping_t  tc_map;
} remapping_acl_data_t;

typedef struct _mlnx_dscp_remapping_t {
    bool                 dscp_remapping_enabled;
    tunnel_qos_data_t    tunnel_qos_data;
    port_qos_db_t        port_qos_db;
    remapping_acl_data_t remapping_acl_data[DSCP_REMAPPING_TUNNEL_TYPE_MAX];
} mlnx_dscp_remapping_t;

typedef struct sai_tunnel_db {
    void                    *db_base_ptr;
    mlnx_tunneltable_t      *tunneltable_db;
    mlnx_tunnel_entry_t     *tunnel_entry_db;
    mlnx_tunnel_map_t       *tunnel_map_db;
    mlnx_tunnel_map_entry_t *tunnel_map_entry_db;
    mlnx_bmtor_bridge_t     *bmtor_bridge_db;
    mlnx_dscp_remapping_t   *dscp_remapping_db;
} sai_tunnel_db_t;

extern sai_tunnel_db_t *g_sai_tunnel_db_ptr;
extern uint32_t         g_sai_tunnel_db_size;
extern bool             g_dscp_remapping_enabled;

bool mlnx_tunnel_dscp_remapping_enabled(void);
sai_status_t mlnx_debug_set_dscp_remapping_for_ptf(_In_ const char* value);
sai_status_t mlnx_tunnel_update_dscp_remapping_acl_rules(void);
sai_status_t mlnx_acl_dscp_remapping_acl_data_init(void);
sai_status_t mlnx_acl_dscp_remapping_acl_data_clear(void);
sai_status_t mlnx_acl_update_dscp_remapping_rules(_In_ mlnx_tc_remapping_t              *tc_remapping,
                                                  _In_ mlnx_dscp_remapping_tunnel_type_t tunnel_type);
sai_status_t mlnx_acl_bind_dscp_remapping(_In_ mlnx_dscp_remapping_tunnel_type_t tunnel_type);
sai_status_t mlnx_acl_unbind_dscp_remapping(_In_ mlnx_dscp_remapping_tunnel_type_t tunnel_type);
sai_status_t mlnx_port_on_dscp_remapping_uplink_update(_In_ sx_port_log_id_t port_id);
sai_status_t mlnx_port_dscp_remapping_uplink_list_init(void);
void mlnx_port_dscp_remapping_uplink_list_clear(void);
sai_status_t mlnx_port_do_dscp_rewriting_for_all_uplink_ports(void);
sai_status_t mlnx_port_undo_dscp_rewriting_for_all_uplink_ports(void);
bool mlnx_port_is_tc_to_dscp_rewrite_done(_In_ sx_port_log_id_t port_id);
sai_status_t mlnx_port_get_qos_map_id_by_log_port(_In_ sx_port_log_id_t   port_id,
                                                  _In_ sai_qos_map_type_t qos_map_type,
                                                  _Out_ sai_object_id_t  *oid);

typedef struct _fdb_action_t {
    sai_fdb_entry_t     fdb_entry;
    sai_packet_action_t action;
} fdb_action_t;

typedef struct _fdb_actions_db_t {
    fdb_action_t actions[FDB_SAVED_ACTIONS_NUM];
    uint32_t     count;
} fdb_actions_db_t;

#define SPAN_SESSION_MAX 8

typedef struct _trap_mirror_db_t {
    sai_object_id_t mirror_oid[SPAN_SESSION_MAX];
    uint32_t        count;
} trap_mirror_db_t;

/* g_resource_liits.shared_buff_mc_max_num_prio 15*/
#define MAX_LOSSLESS_SP 15

/*
 *  SAI host if type
 */
typedef enum _sai_host_object_type_t {
    SAI_HOSTIF_OBJECT_TYPE_VLAN,
    SAI_HOSTIF_OBJECT_TYPE_PORT,
    SAI_HOSTIF_OBJECT_TYPE_LAG,
    SAI_HOSTIF_OBJECT_TYPE_FD,
    SAI_HOSTIF_OBJECT_TYPE_GENETLINK
} sai_host_object_type_t;

typedef struct sai_netdev {
    bool                   is_used;
    sai_host_object_type_t sub_type;
    char                   ifname[SAI_HOSTIF_NAME_SIZE + 1];
    sx_port_log_id_t       port_id;
    uint16_t               vid;
    sx_fd_t                fd;
    char                   mcgrpname[SAI_HOSTIF_GENETLINK_MCGRP_NAME_SIZE];
    sx_psample_params_t    psample_group;
    uint32_t               refcount;
} sai_netdev_t;

#define MLNX_L2MC_GROUP_DB_SIZE (1000)

typedef struct _mlnx_l2mc_group_t {
    bool                 is_used;
    sx_mc_container_id_t mc_container_tunnels;
    sx_mc_container_id_t mc_container_ports;
    mlnx_acl_pbs_entry_t pbs_entry;
    uint32_t             flood_ctrl_ref;
} mlnx_l2mc_group_t;

#define MLNX_L2MC_GROUP_MEMBER_DB_SIZE (64000)

typedef struct _mlnx_l2mc_group_member_t {
    bool             is_used;
    uint32_t         l2mc_group_db_idx;
    uint32_t         bport_db_idx;
    sai_ip_address_t endpoint_ip;
} mlnx_l2mc_group_member_t;

typedef struct _mlnx_mirror_vlan_t {
    bool     vlan_header_valid;
    uint16_t vlan_id;
    uint8_t  vlan_pri;
    uint8_t  vlan_cfi;
} mlnx_mirror_vlan_t;

typedef struct _mlnx_mirror_policer_acl_t {
    bool               is_acl_created;
    uint32_t           refs;
    sx_acl_key_type_t  key;
    sx_acl_id_t        acl_group;
    sx_acl_id_t        acl;
    sx_acl_region_id_t region;
} mlnx_mirror_policer_acl_t;

typedef struct _mlnx_mirror_policer_t {
    sai_object_id_t           policer_oid;
    mlnx_mirror_policer_acl_t extra_acl[SX_ACL_DIRECTION_LAST];
} mlnx_mirror_policer_t;

sai_status_t mlnx_mirror_policer_is_used(_In_ sai_object_id_t policer, _Out_ bool *is_used);
sai_status_t mlnx_mirror_policer_sx_attrs_validate(_In_ const sx_policer_attributes_t *sx_attrs);

typedef enum {
    BOOT_TYPE_REGULAR,
    BOOT_TYPE_WARM,
    BOOT_TYPE_FAST
} mlnx_sai_boot_type_t;

sai_status_t mlnx_sai_issu_storage_pre_shutdown_prepare_impl(void);
sai_status_t mlnx_sai_issu_init_impl(sai_switch_profile_id_t profile_id,
                                     mlnx_sai_boot_type_t    boot_type);
sai_status_t mlnx_sai_issu_storage_check_gp_reg_is_set_to_hw();

#define l2mc_group_db(idx)                   (g_sai_db_ptr->l2mc_groups[(idx)])
#define MLNX_L2MC_GROUP_DB_IDX_IS_VALID(idx) ((idx) < MLNX_L2MC_GROUP_DB_SIZE)
#define MLNX_L2MC_GROUP_DB_IDX_INVALID ((uint32_t)(-1))

#define l2mc_group_member_db(idx)                   (g_sai_db_ptr->l2mc_group_members[(idx)])
#define MLNX_L2MC_GROUP_MEMBER_DB_IDX_IS_VALID(idx) ((idx) < MLNX_L2MC_GROUP_MEMBER_DB_SIZE)
#define MLNX_L2MC_GROUP_MEMBER_DB_IDX_INVALID ((uint32_t)(-1))

sai_status_t mlnx_l2mc_group_oid_create(_In_ const mlnx_l2mc_group_t *l2mc_group, _Out_ sai_object_id_t *oid);
sai_status_t mlnx_l2mc_group_oid_to_sai(_In_ sai_object_id_t oid, _Out_ mlnx_l2mc_group_t **l2mc_group);
sai_status_t mlnx_l2mc_group_oid_to_db_idx(_In_ sai_object_id_t oid, _Out_ uint32_t *db_idx);
sai_status_t mlnx_l2mc_group_sx_ports_get(_In_ const mlnx_l2mc_group_t *l2mc_group,
                                          _Out_ sx_port_log_id_t       *sx_ports,
                                          _Inout_ uint32_t             *ports_count);
sai_status_t mlnx_l2mc_group_to_pbs_info(_In_ const mlnx_l2mc_group_t *l2mc_group,
                                         _Out_ mlnx_acl_pbs_info_t    *pbs_info);
sai_status_t mlnx_l2mc_group_pbs_info_to_group(_In_ mlnx_acl_pbs_info_t  pbs_info,
                                               _Out_ mlnx_l2mc_group_t **l2mc_group);
sai_status_t mlnx_l2mc_group_pbs_use(_In_ mlnx_l2mc_group_t *l2mc_group);
void mlnx_l2mc_group_flood_ctrl_ref_inc(_In_ uint32_t group_db_idx);
void mlnx_l2mc_group_flood_ctrl_ref_dec(_In_ uint32_t group_db_idx);

typedef enum mlnx_platform_type {
    MLNX_PLATFORM_TYPE_INVALID = 0,
    MLNX_PLATFORM_TYPE_1710    = 1710,
    MLNX_PLATFORM_TYPE_2010    = 2010,
    MLNX_PLATFORM_TYPE_2100    = 2100,
    MLNX_PLATFORM_TYPE_2201    = 2201,
    MLNX_PLATFORM_TYPE_2410    = 2410,
    MLNX_PLATFORM_TYPE_2420    = 2420,
    MLNX_PLATFORM_TYPE_2700    = 2700,
    MLNX_PLATFORM_TYPE_2740    = 2740,
    MLNX_PLATFORM_TYPE_3420    = 3420,
    MLNX_PLATFORM_TYPE_3700    = 3700,
    MLNX_PLATFORM_TYPE_3800    = 3800,
    MLNX_PLATFORM_TYPE_4410    = 4410,
    MLNX_PLATFORM_TYPE_4600    = 4600,
    MLNX_PLATFORM_TYPE_4600C   = 4601,
    MLNX_PLATFORM_TYPE_4700    = 4700,
    MLNX_PLATFORM_TYPE_4800    = 4800,
    MLNX_PLATFORM_TYPE_5600    = 5600
} mlnx_platform_type_t;

mlnx_platform_type_t mlnx_platform_type_get(void);
char * mlnx_platform_type_to_str(_In_ mlnx_platform_type_t platform);

#define MLNX_SWITCH_STAT_ID_RANGE_CHECK(stat)                                                                      \
    (((SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_BASE <= stat) && (stat < SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_END)) || \
     ((SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_BASE <= stat) && (stat < SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_END)))

sai_status_t mlnx_translate_flow_counter_to_sai_counter(sx_flow_counter_id_t flow_counter,
                                                        sai_object_id_t     *counter_id);
sai_status_t mlnx_translate_trap_id_to_sai_counter(sai_object_id_t trap_id, sai_object_id_t *counter_id);

#define MLNX_DEBUG_COUNTER_MAX_REASONS                  \
    MAX((uint32_t)SAI_IN_DROP_REASON_ACL_EGRESS_SWITCH, \
        (uint32_t)SAI_OUT_DROP_REASON_L3_EGRESS_LINK_DOWN)

typedef struct _mlnx_debug_counter_t {
    mlnx_shm_array_hdr_t     array_hdr;
    sx_trap_group_t          sx_trap_group;
    mlnx_shm_rm_array_idx_t  policer_db_idx;
    sai_debug_counter_type_t type;
    bool                     drop_reasons[MLNX_DEBUG_COUNTER_MAX_REASONS];
} mlnx_debug_counter_t;

/* SX_TRAP_ID_HOST_MISS_IPV4, SX_TRAP_ID_HOST_MISS_IPV6, SX_TRAP_ID_ETH_L3_MTUERROR, SX_TRAP_ID_ETH_L3_TTLERROR */
#define MLNX_DEBUG_COUNTER_TRAP_DB_SIZE 4

typedef struct _mlnx_debug_counter_trap_t {
    mlnx_shm_rm_array_idx_t bound_counter_idx;
    sx_trap_id_t            trap_id;
    sai_packet_action_t     action;
} mlnx_debug_counter_trap_t;

sai_status_t mlnx_debug_counter_db_init(void);
sai_status_t mlnx_debug_counter_db_trap_action_update(_In_ sx_trap_id_t        sx_trap,
                                                      _In_ sai_packet_action_t action);

sai_status_t mlnx_get_trap_db_index_by_sx_trap(_In_ sx_trap_id_t sx_trap,
                                               _Out_ uint32_t   *index);
sai_status_t mlnx_trap_reset_group_impl(_In_ uint32_t        trap_db_index,
                                        _In_ sai_object_id_t trap_group);

#define MLNX_BFD_STAT_ID_RANGE_CHECK(stat)                                                      \
    ((SAI_BFD_SESSION_STAT_IN_PACKETS == stat) || (stat == SAI_BFD_SESSION_STAT_OUT_PACKETS) || \
     (stat == SAI_BFD_SESSION_STAT_DROP_PACKETS))

#define BFD_MIN_SUPPORTED_INTERVAL 50000

typedef struct _mlnx_bfd_session_db_data_t {
    bool                multihop;
    uint8_t             traffic_class;
    uint8_t             ip_header_version;
    uint8_t             tos;
    uint8_t             ttl;
    uint8_t             multiplier;
    uint8_t             remote_multiplier;
    uint8_t             is_polling;
    uint8_t             is_final;
    sx_bfd_session_id_t tx_session;
    sx_bfd_session_id_t rx_session;
    sai_object_id_t     vr_id;
    uint32_t            bfd_session_state;
    uint32_t            local_discriminator;
    uint32_t            remote_discriminator;
    uint32_t            udp_src_port;
    uint32_t            remote_min_tx;
    uint32_t            remote_min_rx;
    uint32_t            remote_echo;
    uint32_t            min_tx;
    uint32_t            min_rx;
    sai_ip_address_t    src_ip;
    sai_ip_address_t    dst_ip;
} mlnx_bfd_session_db_data_t;

typedef struct _mlnx_bfd_session_db_entry_t {
    mlnx_shm_array_hdr_t       array_hdr;
    mlnx_bfd_session_db_data_t data;
} mlnx_bfd_session_db_entry_t;

PACKED(struct _mlnx_bfd_packet_t {
    uint8_t vers_diag;        /* Version and diagnostic. */
    uint8_t flags;        /* 2bit State field followed by flags. */
    uint8_t mult;         /* Fault detection multiplier. */
    uint8_t length;        /* Length of this BFD message. */
    uint32_t my_disc;        /* My discriminator. */
    uint32_t your_disc;        /* Your discriminator. */
    uint32_t min_tx;        /* Desired minimum tx interval. */
    uint32_t min_rx;        /* Required minimum rx interval. */
    uint32_t min_rx_echo;        /* Required minimum echo rx interval. */
}, );
typedef struct _mlnx_bfd_packet_t mlnx_bfd_packet_t;
#define BFD_PKT_FLAG_POLL  0x20
#define BFD_PKT_FLAG_FINAL 0x10

sai_status_t mlnx_set_offload_bfd_rx_session(_Inout_ mlnx_bfd_session_db_data_t *bfd_db_data,
                                             _In_ mlnx_shm_rm_array_idx_t        bfd_session_db_index,
                                             _In_ sx_access_cmd_t                cmd);
sai_status_t mlnx_set_offload_bfd_tx_session(_Inout_ mlnx_bfd_session_db_data_t *bfd_db_data,
                                             _In_ sx_access_cmd_t                cmd);

typedef struct _mlnx_control_pg_buff_profile_entry {
    sx_cos_port_buffer_attr_t sx_pg_buff_reserved_attr;
    bool                      is_valid;
} mlnx_control_pg_buff;

typedef struct _mlnx_buffer_attrs_t {
    sx_cos_port_buffer_attr_t        sx_reserved_attr;
    sx_cos_port_shared_buffer_attr_t sx_shared_attr;
    bool                             is_valid;
} mlnx_buffer_attrs_t;

#ifndef PATH_MAX
#define PATH_MAX 256
#endif /* PATH_MAX */

typedef struct _mlnx_dump_configuration_t {
    char     path[SX_API_DUMP_PATH_LEN_LIMIT];
    char     mft_cfg_path[SX_API_DUMP_PATH_LEN_LIMIT];
    uint32_t max_events_to_store;
} mlnx_dump_configuration_t;

#define MAX_SUBSCRIBED_PORTS_ISOLATION_GROUP ((MAX_PORTS_DB) / 2)
#define MAX_SUBSCRIBED_ACL_ISOLATION_GROUP   2
#define MAX_ISOLATION_GROUPS                 MAX_PORTS_DB
#define MAX_ISOLATION_GROUP_MEMBERS          MAX_PORTS_DB
typedef struct _mlnx_isolation_group {
    bool                       is_used;
    sai_isolation_group_type_t type;
    sx_port_log_id_t           subscribed_ports[MAX_SUBSCRIBED_PORTS_ISOLATION_GROUP];
    uint32_t                   subscribed_ports_count;
    sai_object_id_t            subscribed_acl[MAX_SUBSCRIBED_ACL_ISOLATION_GROUP];
    uint32_t                   subscribed_acl_count;
    sx_port_log_id_t           members[MAX_ISOLATION_GROUP_MEMBERS];
    uint32_t                   members_count;
} mlnx_isolation_group_t;

/* needs sai_db write lock */
sai_status_t mlnx_set_port_isolation_group_impl(sai_object_id_t port_oid, sai_object_id_t isolation_group);
/* needs sai_db read lock */
sai_status_t mlnx_get_port_isolation_group_impl(sai_object_id_t port_oid, sai_object_id_t *isolation_group);
/* needs sai_db and acl_table write lock */
sai_status_t mlnx_set_acl_entry_isolation_group_impl(sai_object_id_t acl_entry, sai_object_id_t new_isolation_group);
/* needs sai_db write lock */
sai_status_t mlnx_get_acl_entry_isolation_group_impl(sai_object_id_t acl_entry, sai_object_id_t *isolation_group);

/* needs sai_db write lock */
sai_status_t mlnx_port_isolation_is_in_use(const mlnx_port_config_t *port, bool *is_in_use);
/* needs sai_db write lock */
sai_status_t mlnx_port_move_isolation_group_to_lag(mlnx_port_config_t *port, mlnx_port_config_t *lag);
/* needs sai_db write lock */
sai_status_t mlnx_port_move_isolation_group_from_lag(mlnx_port_config_t *lag, mlnx_port_config_t *port);
sai_status_t mlnx_get_switch_log_ports_not_in_lag(const sx_port_log_id_t *exclude_ports,
                                                  const uint32_t          exclude_ports_count,
                                                  sx_port_log_id_t       *ports,
                                                  uint32_t               *ports_count);
sai_status_t mlnx_create_isolation_group_oid(uint32_t isolation_group_idx, sai_isolation_group_type_t type,
                                             sai_object_id_t *object_id);

sai_status_t mlnx_create_isolation_group_member_oid(sai_object_id_t *object_id,
                                                    sai_object_id_t  isolation_group,
                                                    sx_port_log_id_t log_port);
/* needs sai_db read lock */
sai_status_t mlnx_acl_entry_update_port_filter(sai_object_id_t  acl_entry_id,
                                               sx_access_cmd_t  cmd,
                                               sx_port_log_id_t log_port);
sai_status_t mlnx_isolation_group_update_mc_containers(sx_access_cmd_t cmd, sx_port_log_id_t log_port);

typedef enum _mlnx_port_isolation_api {
    PORT_ISOLATION_API_NONE              = 0,
    PORT_ISOLATION_API_EGRESS_BLOCK_PORT = 1,
    PORT_ISOLATION_API_ISOLATION_GROUP   = 2,
    PORT_ISOLATION_API_MAX               = PORT_ISOLATION_API_ISOLATION_GROUP,
} mlnx_port_isolation_api_t;

sai_status_t mlnx_validate_port_isolation_api(mlnx_port_isolation_api_t port_isolation_api);
sai_status_t mlnx_reset_port_isolation_api(void);
bool mlnx_rif_is_ar_enabled(_In_ sai_object_id_t rif_id);
sai_status_t mlnx_port_ar_link_util_percentage_to_kbps(_In_ sx_port_log_id_t port_id,
                                                       _In_ uint32_t         percentage_number,
                                                       _Out_ uint32_t       *link_util);
sai_status_t mlnx_port_get_ar_link_util_kbps(_In_ sx_port_log_id_t port_id, _Out_ uint32_t  *link_util);
bool mlnx_find_ar_port_by_id(_In_ sx_port_log_id_t port_id,
                             _Out_ uint32_t       *index,
                             _Out_ uint32_t       *link_util_percentage);

typedef struct _ar_port_data_t {
    uint32_t         lane_count;
    uint32_t         lane_list[MAX_LANES_SPC3_4];
    sx_port_log_id_t port_id;
    uint32_t         link_util_percentage;
} ar_port_data_t;

typedef struct _mlnx_ar_db_data_t {
    sx_ar_profile_key_t               profile_key;
    sx_ar_profile_attr_t              profile_attr;
    sx_ar_classifier_action_t         default_classifier_action;
    sx_ar_classifier_id_e             classifier_id;
    sx_ar_classifier_attr_t           classifier_attr;
    sx_ar_classifier_action_t         classifier_action;
    sx_ar_congestion_threshold_attr_t congestion_threshold;
    sx_ar_shaper_attr_t               shaper_attr;
    uint32_t                          ar_port_count;
    uint32_t                          ar_ecmp_size;
    ar_port_data_t                    ar_port_list[MAX_PORTS_DB];
} mlnx_ar_db_data_t;

typedef struct _sai_optional_u32_t {
    uint32_t val;
    bool     enabled;
} sai_optional_u32_t;

typedef struct _sai_optional_bool_t {
    bool val;
    bool enabled;
} sai_optional_bool_t;

typedef struct _ar_xml_port_data_t {
    sai_optional_u32_t lane_list[MAX_LANES_SPC3_4];
    sai_optional_u32_t link_util_percentage;
} ar_xml_port_data_t;

typedef struct _ar_config_data_t {
    sai_optional_u32_t  mode;
    sai_optional_u32_t  congestion_thresh_lo;
    sai_optional_u32_t  congestion_thresh_med;
    sai_optional_u32_t  congestion_thresh_hi;
    sai_optional_u32_t  bind_time;
    sai_optional_u32_t  free_threshold;
    sai_optional_u32_t  busy_threshold;
    sai_optional_bool_t only_elephant_en;
    sai_optional_bool_t from_shaper_is_enable;
    sai_optional_u32_t  shaper_rate_from;
    sai_optional_bool_t to_shaper_is_enable;
    sai_optional_u32_t  shaper_rate_to;
    sai_optional_u32_t  ar_ecmp_size;
    ar_xml_port_data_t  port_list[MAX_PORTS_DB];
} ar_config_data_t;

typedef struct sai_db {
    cl_plock_t         p_lock;
    sx_mac_addr_t      base_mac_addr;
    char               dev_mac[18];
    uint32_t           ports_number;
    uint32_t           ports_configured;
    uint32_t           max_ipinip_ipv6_loopback_rifs;
    bool               perport_ipcnt_enable;
    mlnx_port_config_t ports_db[MAX_PORTS_DB * 2];
    mlnx_bridge_port_t bridge_ports_db[MAX_BRIDGE_PORTS];
    uint32_t           non_1q_bports_created; /* to optimize mlnx_bridge_non1q_port_foreach */
    mlnx_bridge_rif_t  bridge_rifs_db[MAX_BRIDGE_RIFS];
    mlnx_vlan_db_t     vlans_db[SXD_VID_MAX];
    sai_netdev_t       hostif_db[MAX_HOSTIFS];
    sai_object_id_t    default_trap_group;
    sai_object_id_t    default_vrid;
    sx_user_channel_t  callback_channel;
    bool               trap_group_valid[MAX_TRAP_GROUPS];
    /* index is according to index in mlnx_traps_info */
    mlnx_trap_t           traps_db[SXD_TRAP_ID_ACL_MAX];
    mlnx_hostif_channel_t wildcard_channel;
    mlnx_qos_map_t        qos_maps_db[MAX_QOS_MAPS_DB];
    uint32_t              switch_qos_maps[MLNX_QOS_MAP_TYPES_MAX];
    uint8_t               switch_default_tc;
    /* control priority group default values configured by sdk */
    mlnx_control_pg_buff              port_pg9_defaults[MAX_PG9_VAL_NUMBER];
    mlnx_buffer_attrs_t               port_queue_defaults;
    mlnx_buffer_attrs_t               port_pg0_defaults;
    mlnx_hash_obj_t                   hash_list[SAI_HASH_MAX_OBJ_COUNT];
    sai_object_id_t                   oper_hash_list[SAI_HASH_MAX_OBJ_ID];
    sx_router_ecmp_port_hash_params_t port_ecmp_hash_params;
    sx_lag_port_hash_params_t         lag_hash_params;
    mlnx_samplepacket_t               mlnx_samplepacket_session[MLNX_SAMPLEPACKET_SESSION_MAX];
    bool                              tunnel_module_initialized;
    bool                              port_parsing_depth_set_for_tunnel;
    sx_bridge_id_t                    sx_bridge_id;
    sai_object_id_t                   default_1q_bridge_oid;
    sai_object_id_t                   dummy_1d_bridge_oid;
    sx_port_log_id_t                  sx_nve_log_port;
    mlnx_shm_rm_array_idx_t           ecmp_to_nhg_map[MLNX_ECMP_NHG_HASHTABLE_SIZE];
    bool                              is_stp_initialized;
    sx_mstp_inst_id_t                 def_stp_id;
    mlnx_mstp_inst_t                  mlnx_mstp_inst_db[SX_MSTP_INST_ID_MAX - SX_MSTP_INST_ID_MIN + 1];
    sai_packet_action_t               flood_actions[MLNX_FID_FLOOD_CTRL_ATTR_MAX];
    fdb_actions_db_t                  fdb_actions;
    bool                              transaction_mode_enable;
    bool                              issu_enabled;
    bool                              restart_warm;
    bool                              issu_start_called;
    bool                              issu_end_called;
    uint32_t                          acl_divider;
    mlnx_sai_boot_type_t              boot_type;
    sx_port_packet_storing_mode_t     packet_storing_mode;
    trap_mirror_db_t                  trap_mirror_discard_wred_db;
    trap_mirror_db_t                  trap_mirror_discard_router_db;
    bool                              is_switch_priority_lossless[MAX_LOSSLESS_SP];
    sx_chip_types_t                   sx_chip_type;
    bool                              crc_check_enable;
    bool                              crc_recalc_enable;
    mlnx_platform_type_t              platform_type;
    bool                              fx_initialized;
    bool                              fx_pipe_created;
    bool                              flex_parser_initialized;
    uint32_t                          fdb_table_size;
    uint32_t                          route_table_size;
    bool                              is_ipv4_route_size;
    uint32_t                          ipv4_route_table_size;
    uint32_t                          ipv4_route_table_size_min;
    uint32_t                          ipv4_route_table_size_max;
    bool                              is_ipv6_route_size;
    uint32_t                          ipv6_route_table_size;
    uint32_t                          ipv6_route_table_size_min;
    uint32_t                          ipv6_route_table_size_max;
    uint32_t                          neighbor_table_size;
    bool                              is_ipv4_neigh_size;
    uint32_t                          ipv4_neighbor_table_size;
    uint32_t                          ipv4_neighbor_table_size_min;
    uint32_t                          ipv4_neighbor_table_size_max;
    bool                              is_ipv6_neigh_size;
    uint32_t                          ipv6_neighbor_table_size;
    uint32_t                          ipv6_neighbor_table_size_min;
    uint32_t                          ipv6_neighbor_table_size_max;
    bool                              aggregate_bridge_drops;
    mlnx_dump_configuration_t         dump_configuration;
    mlnx_mirror_vlan_t                erspan_vlan_header[SPAN_SESSION_MAX];
    mlnx_mirror_policer_t             mirror_policer[SPAN_SESSION_MAX];
    int32_t                           mirror_congestion_mode[SPAN_SESSION_MAX];
    uint32_t                          mirror_sample_rate[SPAN_SESSION_MAX];
    mlnx_l2mc_group_t                 l2mc_groups[MLNX_L2MC_GROUP_DB_SIZE];
    mlnx_l2mc_group_member_t          l2mc_group_members[MLNX_L2MC_GROUP_MEMBER_DB_SIZE];
    mlnx_debug_counter_trap_t         debug_counter_traps[MLNX_DEBUG_COUNTER_TRAP_DB_SIZE];
    bool                              is_bfd_module_initialized;
    sai_mac_t                         vxlan_mac;
    bool                              pbhash_transition;
    uint32_t                          pbhash_gre;
    sx_acl_id_t                       vxlan_acl_id;
    mlnx_shm_pool_t                   shm_pool;
    mlnx_isolation_group_t            isolation_groups[MAX_ISOLATION_GROUPS];
    mlnx_port_isolation_api_t         port_isolation_api;
    mlnx_switch_tunnel_t              switch_tunnel[MLNX_MAX_TUNNEL_TYPES_NUM];
    uint16_t                          accumed_flow_cnt_in_k;
#ifndef _WIN32
    sem_t dfw_sem;
    sem_t bulk_counter_transaction_sem;
#endif
    sai_bulk_counter_info_t  bulk_counter_info;
    mlnx_sai_fg_hash_field_t fg_hash_fields[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT];
    bool                     is_issu_gp_reg_restore;
    uint32_t                 rif_mac_range_ref_counter;
    sx_mac_addr_t            rif_mac_range_addr;
    bool                     reduced_rif_counter_enable;
    mlnx_ar_db_data_t        ar_db;
    /* must be last element, followed by dynamic arrays */
    mlnx_shm_rm_array_info_t array_info[MLNX_SHM_RM_ARRAY_TYPE_SIZE];
} sai_db_t;

extern sai_db_t *g_sai_db_ptr;

#define mlnx_ports_db (g_sai_db_ptr->ports_db)

mlnx_port_config_t * mlnx_port_by_idx(uint16_t id);
mlnx_port_config_t * mlnx_port_by_local_id(uint16_t local_port);

typedef struct mlnx_qos_queue_config {
    sai_object_id_t  wred_id;
    sai_object_id_t  buffer_id;
    mlnx_sched_obj_t sched_obj;
} mlnx_qos_queue_config_t;

#define port_queues_foreach(port, queue, idx)                                      \
    for (idx = 0;                                                                  \
         port->start_queues_index + idx < port->start_queues_index + MAX_QUEUES && \
         (queue = &g_sai_qos_db_ptr->queue_db[port->start_queues_index + idx]); idx++)

typedef struct mlnx_sched_profile_t {
    bool                        is_used;
    sx_cos_ets_element_config_t ets;
    uint64_t                    min_rate;
    uint64_t                    max_rate;
} mlnx_sched_profile_t;

typedef struct sai_qos_db {
    void                    *db_base_ptr;
    mlnx_wred_profile_t     *wred_db;
    mlnx_sched_profile_t    *sched_db;
    mlnx_qos_queue_config_t *queue_db;
} sai_qos_db_t;

extern sai_qos_db_t *g_sai_qos_db_ptr;
extern uint32_t      g_sai_qos_db_size;

typedef struct _mlnx_sai_buffer_resource_limits_t {
    uint32_t num_ingress_pools;
    uint32_t num_egress_pools;
    uint32_t num_total_pools;
    uint32_t num_port_queue_buff;
    uint32_t num_port_pg_buff;
    uint32_t unit_size;
    uint32_t max_buffers_per_port;
    uint32_t num_shared_headroom_pools;
    uint32_t num_port_shared_headroom_buff;
} mlnx_sai_buffer_resource_limits_t;
const mlnx_sai_buffer_resource_limits_t* mlnx_sai_get_buffer_resource_limits();

void init_buffer_resource_limits();

typedef struct _mlnx_sai_buffer_pool_ids_t {
    uint32_t default_ingress_pool_id;
    uint32_t management_ingress_pool_id;
    uint32_t base_ingress_user_sx_pool_id;
    uint32_t default_egress_pool_id;
    uint32_t management_egress_pool_id;
    uint32_t base_egress_user_sx_pool_id;
    uint32_t default_multicast_pool_id;
    uint32_t user_pool_step;
    uint32_t default_descriptor_ingress_pool_id;
    uint32_t default_descriptor_egress_pool_id;
    uint32_t ingress_descriptor_pool_id;
    uint32_t egress_descriptor_pool_id;
} mlnx_sai_buffer_pool_ids_t;

sai_status_t mlnx_init_buffer_pool_ids();

#define BUFFER_DB_PER_PORT_PROFILE_INDEX_ARRAY_SIZE             \
    (mlnx_sai_get_buffer_resource_limits()->num_ingress_pools + \
     mlnx_sai_get_buffer_resource_limits()->num_egress_pools +  \
     mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff    \
    )

typedef struct _sai_buffer_db_t {
    /*
     *  Base pointer to the memory map containing all SAI buffer db data
     */
    uint8_t* db_base_ptr;
    /*
     *  pointer to array of all buffer profiles inside buffer_db_base_ptr
     *  The size of the array == 1 + MAX_BUFFER_PROFILE.
     *  1 is for sentinel entry at index[0].
     */
    mlnx_sai_db_buffer_profile_entry_t* buffer_profiles;

    /*
     *  Contains indexes of referenced buffer profiles by a port.
     *  Structure:
     *   (uint32_t arr_i[]  of size mlnx_sai_get_buffer_resource_limits()->num_ingress_pools) * MAX_PORTS followed by
     *   (uint32_t arr_e[]  of size mlnx_sai_get_buffer_resource_limits()->num_egress_pools)  * MAX_PORTS followed by
     *   (uint32_t arr_pg[] of size mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff)  * MAX_PORTS
     *
     *   ii == index_of(g_sai_db_ptr->ports_db[ii])
     *
     *   arr_i for g_sai_db_ptr->ports_db[ii] ==
     *       port_buffer_data + (ii * mlnx_sai_get_buffer_resource_limits()->num_ingress_pools)
     *
     *   arr_e for g_sai_db_ptr->ports_db[ii] ==
     *       port_buffer_data +
     *       (mlnx_sai_get_buffer_resource_limits()->num_ingress_pools * MAX_PORTS) +
     *       (ii  * mlnx_sai_get_buffer_resource_limits()->num_egress_pools)
     *
     *   arr_pg for g_sai_db_ptr->ports_db[ii] ==
     *       port_buffer_data +
     *       (mlnx_sai_get_buffer_resource_limits()->num_ingress_pools * MAX_PORTS) +
     *       (mlnx_sai_get_buffer_resource_limits()->num_egress_pools  * MAX_PORTS) +
     *       (ii * mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff)
     */
    uint32_t* port_buffer_data;

    /*
     *  pool_allocation[1 + user ingress pools + user egress pools]
     *  When SAI starts up it will load current buffer configuration into SAI buffer infrastructure,
     *  so user would be able to use it. However on the first user request to create a pool all
     *  existing buffer configuration will be deleted.
     *  This item will be set initially to 0, and after first create pool request will be set to true.
     *  When all pools are removed the flag is 0 again and default configuration is applied
     */
    bool *pool_allocation;

    /* keeps association between shared headroom pool and ingress pool */
    mlnx_sai_db_buffer_pool_shp_map_entry_t *shp_ipool_map;
    mlnx_sai_buffer_pool_ids_t               buffer_pool_ids;
} sai_buffer_db_t;

typedef enum _port_buffer_index_array_type_t {
    PORT_BUFF_TYPE_INGRESS,
    PORT_BUFF_TYPE_EGRESS,
    PORT_BUFF_TYPE_PG,
    PORT_BUFF_TYPE_QUEUE
} port_buffer_index_array_type_t;

sai_status_t mlnx_sai_get_port_buffer_index_array(uint32_t                       db_port_ind,
                                                  port_buffer_index_array_type_t buff_type,
                                                  uint32_t                    ** index_arr);

uint32_t mlnx_sai_get_buffer_profile_number();
sai_status_t mlnx_sai_buffer_update_port_buffers_internal(_In_ const mlnx_port_config_t *port);
sai_status_t mlnx_sai_buffer_update_pg0_buffer_sdk_if_required(_In_ const mlnx_port_config_t *port);
sai_status_t mlnx_sai_buffer_update_db_control_pg9_buff_profile_if_required(_In_ const mlnx_port_config_t *port);
sai_status_t mlnx_sai_buffer_update_pg9_buffer_sdk(_In_ const mlnx_port_config_t *port);

extern sai_buffer_db_t *g_sai_buffer_db_ptr;
extern uint32_t         g_sai_buffer_db_size;


#define sai_db_read_lock()  cl_plock_acquire(&g_sai_db_ptr->p_lock)
#define sai_db_write_lock() cl_plock_excl_acquire(&g_sai_db_ptr->p_lock)
#define sai_db_unlock()     cl_plock_release(&g_sai_db_ptr->p_lock)
#define sai_db_sync()       msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC)

#define sai_qos_db_read_lock()  sai_db_read_lock()
#define sai_qos_db_write_lock() sai_db_write_lock()
#define sai_qos_db_unlock()     sai_db_unlock()

#define sai_qos_sched_db (g_sai_qos_db_ptr->sched_db)
#define sai_qos_db_sync() msync(g_sai_qos_db_ptr->db_base_ptr, g_sai_qos_db_size, MS_SYNC)

/* DB read lock is needed */
sai_status_t mlnx_sched_hierarchy_reset(mlnx_port_config_t *port);

sai_status_t mlnx_sched_group_port_init(mlnx_port_config_t *port, bool is_warmboot_init_stage);

sai_status_t mlnx_queue_cfg_lookup(sx_port_log_id_t log_port_id, uint32_t queue_idx, mlnx_qos_queue_config_t **cfg);

/* DB read lock is needed */
sai_status_t mlnx_port_by_log_id_soft(sx_port_log_id_t log_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_port_by_log_id(sx_port_log_id_t log_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_lag_by_log_id(sx_port_log_id_t log_id, mlnx_port_config_t **lag);
/* DB read lock is needed */
sai_status_t mlnx_port_by_obj_id(sai_object_id_t obj_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_port_fetch_lag_if_lag_member(_Inout_ mlnx_port_config_t **port_config);
/* DB read lock is needed */
sai_status_t mlnx_port_idx_by_log_id(sx_port_log_id_t log_port_id, uint32_t *index);
/* DB read lock is needed */
sai_status_t mlnx_port_idx_by_obj_id(sai_object_id_t obj_id, uint32_t *index);
/* DB read lock is needed */
sx_port_log_id_t mlnx_port_get_lag_id(const mlnx_port_config_t *port);
/* DB read lock is needed */
uint32_t mlnx_port_idx_get(const mlnx_port_config_t *port);

/* DB read lock is needed */
sai_status_t mlnx_port_add(mlnx_port_config_t *port, bool is_lag);
sai_status_t mlnx_port_del(mlnx_port_config_t *port);
sai_status_t mlnx_update_issu_port_db();
sai_status_t mlnx_port_config_init_mandatory(mlnx_port_config_t *port);
sai_status_t mlnx_port_config_init(mlnx_port_config_t *port);
sai_status_t mlnx_port_config_uninit(mlnx_port_config_t *port);
sai_status_t mlnx_port_auto_split(mlnx_port_config_t *port);
sai_status_t mlnx_port_speed_bitmap_apply(_In_ mlnx_port_config_t *port);
sai_status_t mlnx_port_crc_params_apply(const mlnx_port_config_t *port, bool init);
sai_status_t mlnx_port_fec_set_impl(sx_port_log_id_t port_log_id, int32_t value);

sai_status_t mlnx_port_in_use_check(const mlnx_port_config_t *port);
bool mlnx_port_is_net(const mlnx_port_config_t *port);
bool mlnx_port_is_virt(const mlnx_port_config_t *port);
bool mlnx_port_is_lag(const mlnx_port_config_t *port);
bool mlnx_port_is_lag_member(const mlnx_port_config_t *port);
bool mlnx_port_is_sai_lag_member(const mlnx_port_config_t *port);
bool mlnx_port_is_sdk_lag_member_not_sai(const mlnx_port_config_t *port);
bool mlnx_log_port_is_cpu(sx_port_log_id_t log_id);
bool mlnx_log_port_is_vport(sx_port_log_id_t log_id);
const char * mlnx_port_type_str(const mlnx_port_config_t *port);
sai_status_t mlnx_port_lag_pvid_attr_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
sai_status_t mlnx_port_lag_pvid_attr_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
sai_status_t mlnx_port_lag_default_vlan_prio_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
sai_status_t mlnx_port_lag_default_vlan_prio_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
sai_status_t mlnx_port_lag_drop_tags_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
sai_status_t mlnx_port_lag_drop_tags_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
sai_status_t mlnx_wred_mirror_port_event(_In_ sx_port_log_id_t port_log_id, _In_ bool is_add);
sai_status_t mlnx_port_wred_mirror_set_impl(_In_ sx_port_log_id_t     sx_port,
                                            _In_ sx_span_session_id_t sx_session,
                                            _In_ bool                 is_add);
sai_status_t mlnx_internal_acls_bind(_In_ internal_acl_op_types op_type,
                                     _In_ sai_object_id_t       sai_port_id);

sai_status_t sai_policer_attr_set(_In_ const sai_object_key_t* key,
                                  _In_ sai_attribute_t         sai_attr,
                                  _In_ char                  * attr_name);

/* DB read lock is needed */
sai_status_t mlnx_switch_get_mac(sx_mac_addr_t *mac);

sai_status_t mlnx_port_qos_params_clear(_In_ mlnx_port_config_t *port);

/* DB read lock is needed */
sai_status_t __mlnx_scheduler_to_queue_apply(sai_object_id_t   scheduler_id,
                                             sx_port_log_id_t  port_log_id,
                                             mlnx_sched_obj_t *obj);

typedef enum mlnx_iter_ret {
    ITER_NEXT,
    ITER_STOP,
} mlnx_iter_ret_t;

typedef mlnx_iter_ret_t (* mlnx_sched_obj_iter_t)(mlnx_port_config_t *cfg, mlnx_sched_obj_t       *obj,
                                                  void                   *ctx);

typedef struct mlnx_iter_ctx {
    void                 *arg;
    sai_status_t          sai_status;
    mlnx_sched_obj_iter_t iter;
    void                 *iter_ctx;
} mlnx_sched_iter_ctx_t;

sai_status_t mlnx_sched_hierarchy_foreach(mlnx_port_config_t    *port,
                                          mlnx_sched_obj_iter_t  it,
                                          mlnx_sched_iter_ctx_t *ctx);

#define KV_DEVICE_MAC_ADDRESS                        "DEVICE_MAC_ADDRESS"
#define SAI_KEY_IPV4_ROUTE_TABLE_SIZE                "SAI_IPV4_ROUTE_TABLE_SIZE"
#define SAI_KEY_IPV4_ROUTE_TABLE_SIZE_MIN            "SAI_IPV4_ROUTE_TABLE_SIZE_MIN"
#define SAI_KEY_IPV4_ROUTE_TABLE_SIZE_MAX            "SAI_IPV4_ROUTE_TABLE_SIZE_MAX"
#define SAI_KEY_IPV6_ROUTE_TABLE_SIZE                "SAI_IPV6_ROUTE_TABLE_SIZE"
#define SAI_KEY_IPV6_ROUTE_TABLE_SIZE_MIN            "SAI_IPV6_ROUTE_TABLE_SIZE_MIN"
#define SAI_KEY_IPV6_ROUTE_TABLE_SIZE_MAX            "SAI_IPV6_ROUTE_TABLE_SIZE_MAX"
#define SAI_KEY_IPV4_NEIGHBOR_TABLE_SIZE             "SAI_IPV4_NEIGHBOR_TABLE_SIZE"
#define SAI_KEY_IPV4_NEIGHBOR_TABLE_SIZE_MIN         "SAI_IPV4_NEIGHBOR_TABLE_SIZE_MIN"
#define SAI_KEY_IPV4_NEIGHBOR_TABLE_SIZE_MAX         "SAI_IPV4_NEIGHBOR_TABLE_SIZE_MAX"
#define SAI_KEY_IPV6_NEIGHBOR_TABLE_SIZE             "SAI_IPV6_NEIGHBOR_TABLE_SIZE"
#define SAI_KEY_IPV6_NEIGHBOR_TABLE_SIZE_MIN         "SAI_IPV6_NEIGHBOR_TABLE_SIZE_MIN"
#define SAI_KEY_IPV6_NEIGHBOR_TABLE_SIZE_MAX         "SAI_IPV6_NEIGHBOR_TABLE_SIZE_MAX"
#define SAI_KEY_AGGREGATE_BRIDGE_DROPS               "SAI_AGGREGATE_BRIDGE_DROPS"
#define SAI_KEY_DUMP_STORE_PATH                      "SAI_DUMP_STORE_PATH"
#define SAI_KEY_DUMP_STORE_AMOUNT                    "SAI_DUMP_STORE_AMOUNT"
#define SAI_KEY_DUMP_MFT_CFG_PATH                    "SAI_DUMP_MFT_CFG_PATH"
#define SAI_KEY_ACCUMULATED_FLOW_COUNTER_UNITS_IN_KB "SAI_ACCUMULATED_FLOW_COUNTER_MAX"
#define SAI_KEY_DSCP_REMAPPING_ENABLED               "SAI_DSCP_REMAPPING_ENABLED"
#define SAI_KEY_ADDITIONAL_MAC_ENABLED               "SAI_ADDITIONAL_MAC_ENABLED"
#define SAI_KEY_REDUCED_RIF_COUNTER_ENABLED          "SAI_REDUCED_RIF_COUNTER_ENABLED"
#define SAI_KEY_ADAPTIVE_ROUTING_CONFIG_FILE         "SAI_ADAPTIVE_ROUTING_CONFIG_FILE"
#define SAI_KEY_BFD_NAMESPACE                        "SAI_KEY_BFD_NAMESPACE"

#define MLNX_MIRROR_VLAN_TPID           0x8100
#define MLNX_GRE_PROTOCOL_TYPE          0x8949
#define MIRROR_VLAN_PRI_MAX             7
#define MIRROR_VLAN_CFI_MAX             1
#define IPV4_HEADER_VERSION             4
#define IPV6_HEADER_VERSION             6
#define MLNX_VLAN_ID_WHEN_TP_DISABLED   0
#define MLNX_MIRROR_TP_DISABLE          0
#define MLNX_MIRROR_TP_ENABLE           1
#define DSCP_OFFSET                     2
#define DSCP_MASK_AFTER_SHIFT           0x3F /* 0011 1111 */
#define DSCP_MASK                       0xFC /* 1111 1100 */
#define MLNX_VLAN_ETHERTYPE_ID          0
#define MLNX_MIRROR_DEFAULT_SWITCH_PRIO 0
#define MIRROR_CONGESTION_MODE_UNINITIALIZED(congestion_mode) ((congestion_mode) == -1)

typedef enum _mirror_ip_address_type_t {
    MIRROR_SRC_IP_ADDRESS,
    MIRROR_DST_IP_ADDRESS
} mirror_ip_address_type_t;

typedef enum _mirror_mac_address_type_t {
    MIRROR_SRC_MAC_ADDRESS,
    MIRROR_DST_MAC_ADDRESS
} mirror_mac_address_type_t;

typedef enum _mirror_port_direction_type_t {
    MIRROR_INGRESS_PORT,
    MIRROR_EGRESS_PORT
} mirror_port_direction_type_t;

/* Tunneling related */
typedef sx_status_t (*sx_api_tunnel_set_fn)(_In_ const sx_api_handle_t handle, _In_ const sx_access_cmd_t cmd,
                                            _In_ const sx_tunnel_attribute_t * tunnel_attr_p,
                                            _Inout_ sx_tunnel_id_t              * tunnel_id_p);
typedef sx_status_t (*sx_api_tunnel_get_fn)(_In_ const sx_api_handle_t handle, _In_ const sx_tunnel_id_t tunnel_id,
                                            _Out_ sx_tunnel_attribute_t * tunnel_attr_p);
typedef sx_status_t (*sx_api_tunnel_decap_rules_set_fn)(_In_ const sx_api_handle_t                handle,
                                                        _In_ const sx_access_cmd_t                cmd,
                                                        _In_ const sx_tunnel_decap_entry_key_t  * decap_key_p,
                                                        _In_ const sx_tunnel_decap_entry_data_t * decap_data_p);
typedef sx_status_t (*sx_api_tunnel_decap_rules_get_fn)(_In_ const sx_api_handle_t               handle,
                                                        _In_ const sx_tunnel_decap_entry_key_t * decap_key_p,
                                                        _Out_ sx_tunnel_decap_entry_data_t     * decap_data_p);

typedef sx_status_t (*sx_api_router_interface_set_fn)(_In_ const sx_api_handle_t handle,
                                                      _In_ const sx_access_cmd_t cmd, _In_ const sx_router_id_t vrid,
                                                      _In_ const sx_router_interface_param_t *ifc_p,
                                                      _In_ const sx_interface_attributes_t *ifc_attr_p,
                                                      _Inout_ sx_router_interface_t *rif_p);
typedef sx_status_t (*sx_api_router_interface_get_fn)(_In_ const sx_api_handle_t         handle,
                                                      _In_ const sx_router_interface_t   rif,
                                                      _Out_ sx_router_id_t              *vrid_p,
                                                      _Out_ sx_router_interface_param_t *ifc_p,
                                                      _Out_ sx_interface_attributes_t   *ifc_attr_p);

typedef struct _sdk_tunnel_api_t {
    sx_api_tunnel_set_fn             sx_api_tunnel_set_f;
    sx_api_tunnel_get_fn             sx_api_tunnel_get_f;
    sx_api_tunnel_decap_rules_set_fn sx_api_tunnel_decap_rules_set_f;
    sx_api_tunnel_decap_rules_get_fn sx_api_tunnel_decap_rules_get_f;
    sx_api_router_interface_set_fn   sx_api_router_interface_set_f;
    sx_api_router_interface_get_fn   sx_api_router_interface_get_f;
} sdk_tunnel_api_t;

typedef enum _samplepacket_port_direction_type_t {
    SAMPLEPACKET_INGRESS_PORT,
    SAMPLEPACKET_EGRESS_PORT,
} samplepacket_port_direction_type;

typedef enum _tunnel_direction_type_t {
    TUNNEL_ENCAP,
    TUNNEL_DECAP,
} tunnel_direction_type;

typedef enum _tunnel_rif_type_t {
    MLNX_TUNNEL_OVERLAY,
    MLNX_TUNNEL_UNDERLAY,
} tunnel_rif_type;

typedef enum _tunnel_map_entry_key_value_type_t {
    MLNX_OECN_KEY,
    MLNX_OECN_VALUE,
    MLNX_UECN_KEY,
    MLNX_UECN_VALUE,
    MLNX_VLAN_ID_KEY,
    MLNX_VLAN_ID_VALUE,
    MLNX_VNI_ID_KEY,
    MLNX_VNI_ID_VALUE,
    MLNX_BRIDGE_ID_KEY,
    MLNX_BRIDGE_ID_VALUE,
    MLNX_VR_ID_KEY,
    MLNX_VR_ID_VALUE,
} tunnel_map_entry_key_value_type;

sai_status_t mlnx_translate_sdk_tunnel_id_to_sai_tunnel_id(_In_ const sx_tunnel_id_t sdk_tunnel_id,
                                                           _Out_ sai_object_id_t    *sai_tunnel_id);
sai_status_t mlnx_parsing_depth_increase(void);

/* caller needs to guard this function with lock */
sai_status_t mlnx_get_sai_tunnel_db_idx(_In_ sai_object_id_t sai_tunnel_id, _Out_ uint32_t *tunnel_db_idx);
sai_status_t mlnx_acl_psort_thread_suspend(void);
sai_status_t mlnx_acl_psort_thread_resume(void);

sai_status_t mlnx_port_cb_table_init(void);
sai_status_t mlnx_acl_cb_table_init(void);
sai_status_t mlnx_udf_cb_table_init(void);
sai_status_t mlnx_sai_issu_storage_cb_table_init(void);

sai_status_t mlnx_sai_tunnel_to_sx_tunnel_id(_In_ sai_object_id_t  sai_tunnel_id,
                                             _Out_ sx_tunnel_id_t *sx_tunnel_id);

sai_status_t mlnx_vrid_to_br_rif_get(_In_ sx_router_id_t          sx_vrid,
                                     _In_ sx_tunnel_id_t          sx_vxlan_tunnel,
                                     _Out_ sx_router_interface_t *br_rif,
                                     _Out_ sx_fid_t              *br_fid);

sai_status_t mlnx_get_flow_counter_id(_In_ sai_object_id_t        counter,
                                      _Out_ sx_flow_counter_id_t *sx_counter_id);
sai_status_t mlnx_update_hostif_trap_counter_unlocked(_In_ sai_object_id_t trap_id,
                                                      _In_ sai_object_id_t counter_id);

sai_status_t mlnx_update_hostif_trap_counter(_In_ sai_object_id_t trap_id,
                                             _In_ sai_object_id_t counter_id);

sai_status_t mlnx_translate_action_to_no_trap(sai_packet_action_t  action,
                                              sai_packet_action_t *no_trap_action,
                                              bool                *is_action_present);
sai_status_t mlnx_translate_action_to_trap(bool                 is_current_action_present,
                                           sai_packet_action_t  action,
                                           sai_packet_action_t *trap_action);

sai_status_t mlnx_translate_action_to_no_forward(sai_packet_action_t action, sai_packet_action_t *no_forward_action);
sai_status_t mlnx_translate_action_to_forward(sai_packet_action_t action, sai_packet_action_t *forward_action);

#define is_isolation_group_in_use() (g_sai_db_ptr->port_isolation_api == PORT_ISOLATION_API_ISOLATION_GROUP)
#define is_egress_block_in_use()    (g_sai_db_ptr->port_isolation_api == PORT_ISOLATION_API_EGRESS_BLOCK_PORT)

#define LINE_LENGTH 120

void SAI_dump_acl(_In_ FILE *file);
void SAI_dump_bfd(_In_ FILE *file);
void SAI_dump_bridge(_In_ FILE *file);
void SAI_dump_buffer(_In_ FILE *file);
void SAI_dump_debug_counter(_In_ FILE *file);
void SAI_dump_hash(_In_ FILE *file);
void SAI_dump_hostintf(_In_ FILE *file);
void SAI_dump_isolation_group(_In_ FILE *file);
void SAI_dump_mirror(_In_ FILE *file);
void SAI_dump_policer(_In_ FILE *file);
void SAI_dump_port(_In_ FILE *file);
void SAI_dump_ar(_In_ FILE *file);
void SAI_dump_qosmaps(_In_ FILE *file);
void SAI_dump_queue(_In_ FILE *file);
void SAI_dump_samplepacket(_In_ FILE *file);
void SAI_dump_scheduler(_In_ FILE *file);
void SAI_dump_stp(_In_ FILE *file);
void SAI_dump_tunnel(_In_ FILE *file);
void SAI_dump_udf(_In_ FILE *file);
void SAI_dump_vlan(_In_ FILE *file);
void SAI_dump_wred(_In_ FILE *file);
void SAI_dump_gp_reg(_In_ FILE *file);
void SAI_dump_nhg_nhgm(_In_ FILE *file);
void SAI_dump_nh(_In_ FILE *file);

sai_status_t sai_dbg_generate_dump_ext(_In_ const char *dump_file_name,
                                       _In_ int32_t     flags);

size_t oid_n_to_str(_In_ sai_object_id_t oid,
                    _In_ size_t          len,
                    _Out_ char          *str);
void oid_to_str(_In_ sai_object_id_t oid,
                _Out_ char          *str);
size_t key_n_to_str(_In_ const sai_object_key_t *key,
                    _In_ sai_object_type_t       object_type,
                    _In_ size_t                  len,
                    _Out_ char                  *str);
void key_to_str(_In_ const sai_object_key_t *key,
                _In_ sai_object_type_t       object_type,
                _Out_ char                  *str);

#define MLNX_LOG_KEY(log_level, str, key, object_type)                   \
    do {                                                                 \
        char key_str[MAX_KEY_STR_LEN] = {0};                             \
        key_to_str((const sai_object_key_t *)key, object_type, key_str); \
        SX_LOG(log_level, "%s %s\n", str, key_str);                      \
    } while (false)
#define MLNX_LOG_KEY_CREATED(log_level, key, object_type) MLNX_LOG_KEY(log_level, "Created", key, object_type)
#define MLNX_LOG_KEY_REMOVE(log_level, key, object_type)  MLNX_LOG_KEY(log_level, "Remove", key, object_type)
#define MLNX_LOG_OID(str, oid)               \
    do {                                     \
        char oid_str[MAX_KEY_STR_LEN] = {0}; \
        oid_to_str(oid, oid_str);            \
        SX_LOG_NTC("%s %s\n", str, oid_str); \
    } while (false)
#define MLNX_LOG_OID_CREATED(oid) MLNX_LOG_OID("Created", oid)
#define MLNX_LOG_OID_REMOVE(oid)  MLNX_LOG_OID("Remove", oid)

#define MLNX_LOG_ATTRS_VERBOSITY(log_level, attr_count, attr_list, object_type)                     \
    do {                                                                                            \
        char list_str[MAX_LIST_VALUE_STR_LEN] = {0};                                                \
        sai_attr_list_to_str(attr_count, attr_list, object_type, MAX_LIST_VALUE_STR_LEN, list_str); \
        SX_LOG(log_level, "Create %s: %s\n", SAI_TYPE_STR(object_type), list_str);                  \
    } while (false)
#define MLNX_LOG_ATTRS(attr_count, attr_list, object_type) \
    MLNX_LOG_ATTRS_VERBOSITY(SX_LOG_NOTICE,                \
                             attr_count,                   \
                             attr_list,                    \
                             object_type)

bool u32_list_equal(_In_ const uint32_t *list1,
                    _In_ uint32_t        list1_count,
                    _In_ const uint32_t *list2,
                    _In_ uint32_t        list2_count);

#endif /* __MLNXSAI_H_ */
