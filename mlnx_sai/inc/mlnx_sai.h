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

#if !defined (__MLNXSAI_H_)
#define __MLNXSAI_H_

#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_acl.h>
#include <sx/sdk/sx_api_bridge.h>
#include <sx/sdk/sx_api_cos.h>
#include <sx/sdk/sx_api_cos_redecn.h>
#include <sx/sdk/sx_api_dbg.h>
#include <sx/sdk/sx_api_fdb.h>
#include <sx/sdk/sx_api_flex_acl.h>
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
#include <resource_manager/resource_manager.h>
#include <sx/sxd/sxd_access_register.h>
#include <sx/sxd/sxd_command_ifc.h>
#include <sx/sxd/sxd_dpt.h>
#include <sx/sxd/sxd_status.h>
#include <complib/cl_event.h>
#include <complib/cl_passivelock.h>
#ifndef _WIN32
#include <pthread.h>
#endif
#include <sx/utils/psort.h>
#include <sai.h>

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

#define mlnx_syslog(level, module, fmt, ...) \
    do { \
        int __mlnx_sai_verbosity_level__ = 0; \
        SEVERITY_LEVEL_TO_VERBOSITY_LEVEL(level, __mlnx_sai_verbosity_level__); \
                                                                            \
        syslog(VERBOSITY_LEVEL_TO_SYSLOG_LEVEL(__mlnx_sai_verbosity_level__), \
               MLNX_SYSLOG_FMT fmt, \
               module, mlnx_severity_to_syslog(level), \
               ## __VA_ARGS__); \
    } while (0)

#ifdef CONFIG_SYSLOG
#define MLNX_SAI_LOG(level, fmt, ...) \
    mlnx_syslog(level, QUOTEME(__MODULE__), MLNX_LOG_FMT fmt, \
                __FILE__, __LINE__, __FUNCTION__, \
                ## __VA_ARGS__)
#else
#define MLNX_SAI_LOG(level, fmt, ...) printf(fmt, ## __VA_ARGS__)
#endif

#define MLNX_SAI_LOG_DBG(fmt, ...) MLNX_SAI_LOG(SX_LOG_DEBUG, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_INF(fmt, ...) MLNX_SAI_LOG(SX_LOG_INFO, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_WRN(fmt, ...) MLNX_SAI_LOG(SX_LOG_WARNING, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_ERR(fmt, ...) MLNX_SAI_LOG(SX_LOG_ERROR, fmt, ## __VA_ARGS__)
#define MLNX_SAI_LOG_NTC(fmt, ...) MLNX_SAI_LOG(SX_LOG_NOTICE, fmt, ## __VA_ARGS__)

#define SAI_ERR(status) ((status) != SAI_STATUS_SUCCESS)
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

#define DEFAULT_ETH_SWID 0
#define DEFAULT_VRID     0
#define DEFAULT_RIF_MTU  1500

#define DEFAULT_MULTICAST_TTL_THRESHOLD 1
#define FIRST_PORT                      (0x10000 | (1 << 8))
#define PORT_MAC_BITMASK                (~0x3F)
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
#define PORT_SPEED_0                    0
#define PORT_SPEED_MAX_SP               PORT_SPEED_100
#define PORT_SPEED_MAX_SP2              PORT_SPEED_200
#define NUM_SPEEDS                      10
#define CPU_PORT                        0
#define ECMP_MAX_PATHS                  64
#define SX_DEVICE_ID                    1
#define DEFAULT_DEVICE_ID               255
#define DEFAULT_VLAN                    1
#define DEFAULT_TRAP_GROUP_PRIO         SX_TRAP_PRIORITY_LOW
#define DEFAULT_TRAP_GROUP_ID           0
#define RECV_ATTRIBS_NUM                3
#define FDB_NOTIF_ATTRIBS_NUM           3
#define FDB_OR_ROUTE_SAVED_ACTIONS_NUM  100

#define SAI_INVALID_STP_INSTANCE (SX_MSTP_INST_ID_MAX + 1)

#define MLNX_UDF_GROUP_SIZE_MAX   (3) /* max of extraction points in one custom bytes set */
#define MLNX_UDF_GROUP_LENGTH_MAX (g_resource_limits.acl_custom_bytes_set_size_max)
#define MLNX_UDF_GROUP_COUNT_MAX  (g_resource_limits.acl_custom_bytes_set_max)
#define MLNX_UDF_COUNT_MAX        (MLNX_UDF_GROUP_SIZE_MAX * MLNX_UDF_GROUP_COUNT_MAX)
#define MLNX_UDF_MATCH_COUNT_MAX  (MLNX_UDF_COUNT_MAX)
#define MLNX_UDF_OFFSET_MAX       (g_resource_limits.acl_custom_bytes_extraction_point_offset_max)

#define MLNX_UDF_DB_UDF_GROUP_SIZE \
    (sizeof(mlnx_udf_group_t) + \
     sizeof(sx_acl_key_t) * MLNX_UDF_GROUP_LENGTH_MAX)
#define MLNX_UDF_DB_UDF_GROUPS_SIZE      (MLNX_UDF_DB_UDF_GROUP_SIZE * MLNX_UDF_GROUP_COUNT_MAX)
#define MLNX_UDF_DB_UDF_GROUP_UDFS_SIZE  (sizeof(mlnx_udf_list_t) + sizeof(uint32_t) * MLNX_UDF_GROUP_SIZE_MAX)
#define MLNX_UDF_DB_UDF_GROUPS_UDFS_SIZE (MLNX_UDF_DB_UDF_GROUP_UDFS_SIZE * MLNX_UDF_GROUP_COUNT_MAX)
#define MLNX_UDF_DB_UDFS_SIZE            (sizeof(mlnx_udf_t) * MLNX_UDF_COUNT_MAX)
#define MLNX_UDF_DB_MATCHES_SIZE         (sizeof(mlnx_match_t) * MLNX_UDF_MATCH_COUNT_MAX)

#define MLNX_UDF_GROUP_MASK_EMPTY (0)

#define MLNX_UDF_ACL_ATTR_COUNT  (10)
#define MLNX_UDF_ACL_ATTR_MAX_ID (MLNX_UDF_ACL_ATTR_COUNT - 1)

#define mlnx_udf_db (g_sai_acl_db_ptr->udf_db)
#define udf_db_group_ptr(index) \
    ((mlnx_udf_group_t*)((uint8_t*)mlnx_udf_db.groups + \
                         (MLNX_UDF_DB_UDF_GROUP_SIZE * index)))
#define udf_db_group_udfs_ptr(index) \
    ((mlnx_udf_list_t*)((uint8_t*)mlnx_udf_db.groups_udfs + \
                        (MLNX_UDF_DB_UDF_GROUP_UDFS_SIZE * index)))
#define udf_db_udf(index)   (mlnx_udf_db.udfs[index])
#define udf_db_match(index) (mlnx_udf_db.matches[index])

typedef uint64_t udf_group_mask_t;


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
    MLNX_SHM_RM_ARRAY_TYPE_MAX = MLNX_SHM_RM_ARRAY_TYPE_BRIDGE,
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
#define MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED \
    ((mlnx_shm_rm_array_idx_t) {.type = MLNX_SHM_RM_ARRAY_TYPE_INVALID, .idx = \
                                    0})
#define MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx) \
    (((idx).type == MLNX_SHM_RM_ARRAY_TYPE_INVALID) && \
     ((idx).idx == 0))

sai_status_t mlnx_shm_rm_array_alloc(_In_ mlnx_shm_rm_array_type_t  type,
                                     _Out_ mlnx_shm_rm_array_idx_t *idx,
                                     _Out_ void                   **elem);
sai_status_t mlnx_shm_rm_array_free(_In_ mlnx_shm_rm_array_idx_t idx);
sai_status_t mlnx_shm_rm_array_find(_In_ mlnx_shm_rm_array_type_t  type,
                                    _In_ mlnx_shm_rm_array_cmp_fn  cmp_fn,
                                    _In_ mlnx_shm_rm_array_idx_t   start_idx,
                                    _In_ const void               *data,
                                    _Out_ mlnx_shm_rm_array_idx_t *idx,
                                    _Out_ void                   **elem);
sai_status_t mlnx_shm_rm_array_idx_to_ptr(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ void                   **elem);
uint32_t mlnx_shm_rm_array_size_get(_In_ mlnx_shm_rm_array_type_t type);

PACKED(struct _mlnx_object_id_t {
           sai_uint8_t object_type;
           PACKED(struct {
                      uint8_t sub_type: 3;
                      uint8_t swid: 5;
                  }, field);
           union {
               sai_uint8_t bytes[EXTENDED_DATA_SIZE];
               PACKED(struct {
                          uint8_t dev_id;
                          uint8_t phy_id;
                      }, port);
               PACKED(struct {
                          uint8_t lag_id;
                          uint8_t sub_id;
                      }, lag);
               PACKED(struct {
                          uint16_t id;
                      }, stp);
               PACKED(struct {
                          uint8_t group_id;
                          uint8_t nhop_id;
                      }, nhop_group_member_high);
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
                          uint16_t bport_db_idx; /* .1Q bridge ports are located at (0, MAX_PORTS *2) indexes */
                      }, l2mc_group_member);
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
               PACKED(struct {
                          uint16_t group_id;
                          uint16_t nhop_id;
                      }, nhop_group_member_low);
               PACKED(struct {
                          uint32_t db_idx;
                      }, l2mc_group);
           } id;
       }, );

typedef struct _mlnx_object_id_t mlnx_object_id_t;

extern const char* sai_metadata_sai_acl_entry_attr_t_enum_values_names[];
#define MLNX_SAI_ACL_ENTRY_ATTR_STR(attr) (sai_metadata_sai_acl_entry_attr_t_enum_values_names[attr])

#define SAI_TYPE_CHECK_RANGE(type) (type < SAI_OBJECT_TYPE_MAX)
extern const char* sai_metadata_sai_object_type_t_enum_values_short_names[];
#define SAI_TYPE_STR(type) \
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
typedef struct _mlnx_rif_db_t {
    mlnx_shm_array_hdr_t mlnx_array;
    mlnx_rif_sx_data_t   sx_data;
} mlnx_rif_db_t;

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
typedef struct _mlnx_attr_enum_info_t {
    int32_t *attrs;
    uint32_t count;
    bool     all;
} mlnx_attr_enum_info_t;
typedef struct _mlnx_obj_type_attrs_enum_infos_t {
    const mlnx_attr_enum_info_t *info;
    uint32_t                     count;
} mlnx_obj_type_attrs_enums_info_t;
typedef struct _mlnx_obj_type_attrs_info_t {
    const sai_vendor_attribute_entry_t    *vendor_data;
    const mlnx_obj_type_attrs_enums_info_t enums_info;
} mlnx_obj_type_attrs_info_t;
/* A set of macros that allows to define a number of values passed to the macro
 * Example PP_NARG(a, b, c) gives 3.
 */
#ifndef _WIN32
#define PP_NARG(...) \
    PP_NARG_(__VA_ARGS__, PP_RSEQ_N())
#define PP_NARG_(...) \
    PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( \
        _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, \
        _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, \
        _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, \
        _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, \
        _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, \
        _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, \
        _61, _62, _63,  N, ...) N
#define PP_RSEQ_N() \
    63, 62, 61, 60,                   \
    59, 58, 57, 56, 55, 54, 53, 52, 51, 50, \
    49, 48, 47, 46, 45, 44, 43, 42, 41, 40, \
    39, 38, 37, 36, 35, 34, 33, 32, 31, 30, \
    29, 28, 27, 26, 25, 24, 23, 22, 21, 20, \
    19, 18, 17, 16, 15, 14, 13, 12, 11, 10, \
    9, 8, 7, 6, 5, 4, 3, 2, 1, 0
#else
#define EXPAND(x) x
#define PP_NARG(...) \
    EXPAND(_xPP_NARGS_IMPL(__VA_ARGS__, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
#define _xPP_NARGS_IMPL(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, N, ...) N
#endif
#define ATTR_ARR_LEN(...) PP_NARG(__VA_ARGS__)

#define ATTR_ENUM_VALUES_LIST(...) \
    {.attrs = (int32_t[ATTR_ARR_LEN(__VA_ARGS__)]) {__VA_ARGS__}, \
     .count = ATTR_ARR_LEN(__VA_ARGS__),                         \
     .all   = false }
#define ATTR_ENUM_VALUES_ALL() \
    {.attrs = NULL,        \
     .count = 0,           \
     .all   = true }
#define ATTR_ENUM_INFO_IS_VALID(info) (((info)->all) || ((info)->count > 0))
#define OBJ_ATTRS_ENUMS_INFO(enum_info_arr) \
    {.info = enum_info_arr, .count = ARRAY_SIZE(enum_info_arr)}
#define OBJ_ATTRS_ENUMS_INFO_EMPTY() \
    {.info = NULL, .count = 0}

void mlnx_udf_acl_attrs_metadata_init();
bool mlnx_udf_acl_attribute_id_is_not_supported(_In_ sai_attr_id_t attr_id);
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
sai_status_t sai_nexthops_to_str(_In_ uint32_t               next_hop_count,
                                 _In_ const sai_object_id_t* nexthops,
                                 _In_ uint32_t               max_length,
                                 _Out_ char                 *str);
sai_status_t sai_qos_map_to_str(_In_ const sai_qos_map_list_t *qos_map,
                                _In_ sai_qos_map_type_t        type,
                                _In_ uint32_t                  max_length,
                                _Out_ char                    *value_str);
sai_status_t mlnx_translate_sai_trap_action_to_sdk(sai_int32_t       action,
                                                   sx_trap_action_t *trap_action,
                                                   uint32_t          param_index);
sai_status_t mlnx_translate_sai_router_action_to_sdk(sai_int32_t         action,
                                                     sx_router_action_t *router_action,
                                                     uint32_t            param_index);
sai_status_t mlnx_translate_sdk_router_action_to_sai(sx_router_action_t router_action, sai_int32_t *sai_action);
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

bool mlnx_route_entries_are_equal(_In_ const sai_route_entry_t *u1, _In_ const sai_route_entry_t *u2);

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

sai_status_t mlnx_register_trap(const sx_access_cmd_t                 cmd,
                                uint32_t                              index,
                                sai_hostif_table_entry_channel_type_t channel,
                                sx_fd_t                               fd,
                                sx_host_ifc_register_key_t           *reg);
sai_status_t mlnx_trap_set(uint32_t index, sai_packet_action_t sai_action, sai_object_id_t trap_group);
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

sai_status_t mlnx_fill_objlist(const sai_object_id_t *data, uint32_t count, sai_object_list_t *list);
sai_status_t mlnx_fill_u8list(const uint8_t *data, uint32_t count, sai_u8_list_t *list);
sai_status_t mlnx_fill_s8list(const int8_t *data, uint32_t count, sai_s8_list_t *list);
sai_status_t mlnx_fill_u16list(const uint16_t *data, uint32_t count, sai_u16_list_t *list);
sai_status_t mlnx_fill_s16list(const int16_t *data, uint32_t count, sai_s16_list_t *list);
sai_status_t mlnx_fill_u32list(const uint32_t *data, uint32_t count, sai_u32_list_t *list);
sai_status_t mlnx_fill_s32list(const int32_t *data, uint32_t count, sai_s32_list_t *list);
sai_status_t mlnx_fill_vlanlist(const sai_vlan_id_t *data, uint32_t count, sai_vlan_list_t *list);
sai_status_t mlnx_fill_aclresourcelist(const sai_acl_resource_t *data, uint32_t count, sai_acl_resource_list_t *list);
sai_status_t mlnx_attribute_value_list_size_check(_Inout_ uint32_t *out_size, _In_ uint32_t in_size);

sai_status_t mlnx_wred_apply_to_queue_oid(_In_ sai_object_id_t wred_id, _In_ sai_object_id_t queue_oid);
sai_status_t mlnx_wred_init();

sai_status_t mlnx_scheduler_to_queue_apply(sai_object_id_t scheduler_id, sai_object_id_t queue_id);

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

sai_status_t mlnx_fdb_route_action_save(_In_ sai_object_type_t   type,
                                        _In_ const void         *entry,
                                        _In_ sai_packet_action_t action);
void mlnx_fdb_route_action_clear(_In_ sai_object_type_t type, _In_ const void        *entry);
void mlnx_fdb_route_action_fetch(_In_ sai_object_type_t type,
                                 _In_ const void       *entry,
                                 _Out_ void            *entry_action);
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
sai_status_t mlnx_acl_stage_action_types_get(_In_ sai_acl_stage_t stage, _Out_ sai_s32_list_t *list);
sai_status_t mlnx_acl_db_free_entries_get(_In_ sai_object_type_t resource_type, _Out_ uint32_t         *free_entries);
#define acl_global_lock()   cl_plock_excl_acquire(&g_sai_acl_db_ptr->acl_settings_tbl->lock)
#define acl_global_unlock() cl_plock_release(&g_sai_acl_db_ptr->acl_settings_tbl->lock)

typedef struct _mlnx_mstp_inst_t {
    bool     is_used;
    uint32_t vlan_count;
} mlnx_mstp_inst_t;

sai_status_t mlnx_hash_initialize();

bool mlnx_stp_is_initialized();
sai_status_t mlnx_stp_preinitialize();
sai_status_t mlnx_stp_initialize();
sai_status_t mlnx_stp_port_state_set_impl(_In_ sx_port_log_id_t          port,
                                          _In_ sx_mstp_inst_port_state_t state,
                                          _In_ sx_mstp_inst_id_t         mstp_instance);

/* Helper for mlnx_mstp_inst_db */
mlnx_mstp_inst_t * get_stp_db_entry(sx_mstp_inst_id_t sx_stp_id);
#define END_TRAP_INFO_ID 0xFFFFFFFF
typedef enum _mlnx_trap_type_t {
    MLNX_TRAP_TYPE_REGULAR,
    MLNX_TRAP_TYPE_USER_DEFINED
} mlnx_trap_type_t;

sai_status_t mlnx_translate_sdk_trap_to_sai(_In_ sx_trap_id_t             sdk_trap_id,
                                            _Out_ sai_hostif_trap_type_t *trap_id,
                                            _Out_ const char            **trap_name,
                                            _Out_ mlnx_trap_type_t       *trap_type);

#define MAX_SDK_TRAPS_PER_SAI_TRAP 6
typedef struct _mlnx_trap_info_t {
    sai_hostif_trap_type_t trap_id;
    uint8_t                sdk_traps_num;
    sx_trap_id_t           sdk_trap_ids[MAX_SDK_TRAPS_PER_SAI_TRAP];
    sai_packet_action_t    action;
    const char            *trap_name;
    mlnx_trap_type_t       trap_type;
} mlnx_trap_info_t;
extern const mlnx_trap_info_t mlnx_traps_info[];

#define MAX_SCHED_LEVELS       2
#define MAX_SCHED_CHILD_GROUPS 8
#define MAX_ETS_ELEMENTS       (g_resource_limits.cos_port_ets_elements_num)

#define MAX_VLANS (SXD_VID_MAX + 1)

#define MAX_PORTS           (g_resource_limits.port_ext_num_max)
#define MAX_PORTS_DB        128
#define MAX_BRIDGES_1D      1000
#define MAX_VPORTS          (MAX_BRIDGES_1D * MAX_PORTS_DB)
#define MAX_BRIDGE_1Q_PORTS (MAX_PORTS_DB * 2) /* Ports and LAGs */
#define MAX_BRIDGE_RIFS     64
#define MAX_BRIDGE_PORTS    (MAX_VPORTS + MAX_BRIDGE_1Q_PORTS + MAX_BRIDGE_RIFS)
#define MAX_LANES           4
#define MAX_HOSTIFS         200
#define MAX_POLICERS        100
#define MAX_TRAP_GROUPS     32
#define MIN_SX_BRIDGE_ID    0x1000

#define DEFAULT_INGRESS_SX_POOL_ID   0
#define DEFAULT_EGRESS_SX_POOL_ID    11
#define MANAGEMENT_INGRESS_POOL_ID   1
#define BASE_INGRESS_USER_SX_POOL_ID 2
#define BASE_EGRESS_USER_SX_POOL_ID  13
#define MANAGEMENT_EGRESS_POOL_ID    12
#define DEFAULT_MULTICAST_POOL_ID    10

#define SENTINEL_BUFFER_DB_ENTRY_INDEX 0

#define MLNX_FDB_LEARNING_NO_LIMIT_VALUE (0)
#define MLNX_FDB_IS_LEARNING_LIMIT_EXISTS(limit) ((limit) != MLNX_FDB_LEARNING_NO_LIMIT_VALUE)

#define MLNX_FDB_LIMIT_SAI_TO_SX(limit) (MLNX_FDB_IS_LEARNING_LIMIT_EXISTS(limit) ? (limit) : SX_FDB_UC_NO_LIMIT)
#define MLNX_FDB_LIMIT_SX_TO_SAI(sx_limit) \
    (SX_FDB_IS_LIMIT_EXIST(sx_limit) ?             \
     (sx_limit) : MLNX_FDB_LEARNING_NO_LIMIT_VALUE)

typedef enum _mlnx_port_breakout_capability_t {
    MLNX_PORT_BREAKOUT_CAPABILITY_NONE     = 0,
    MLNX_PORT_BREAKOUT_CAPABILITY_TWO      = 1,
    MLNX_PORT_BREAKOUT_CAPABILITY_FOUR     = 2,
    MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR = 3
} mlnx_port_breakout_capability_t;

/*
 *  Indexes for items in mlnx_port_config_t::port_policers[].
 *  Also represents storm_control_id value which wwill be used for calling sx_api_port_storm_control_set/get. This also means
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
typedef struct _mlnx_policer_db_entry_t {
    sx_policer_id_t         sx_policer_id_trap;     /* For binding to trap group only. value == SX_POLICER_ID_INVALID, unless/untill sx_policer is associated with this sai_policer.*/
    sx_policer_id_t         sx_policer_id_acl;      /* For binding to ACL only. see SX_POLICER_ID_INVALID note above, applies to this field as well*/
    sx_policer_attributes_t sx_policer_attr;        /* Policer attribute values. The values will be applied to trap group, ACL and port storm policers.*/
    bool                    valid;    /*does given db entry have valid policer data*/
} mlnx_policer_db_entry_t;
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

typedef struct _mlnx_port_config_t {
    uint8_t                         index;
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

    /*  SAI Port can have up to MLNX_PORT_POLICER_TYPE_MAX SDK port storm
     *  policers in use internally.  For each storm item we keep type of
     *  traffic it'll handle and SAI policer id which contains the policer
     *  attributes (cbs, pir, etc.) if SAI_NULL_OBJECT_ID == policer_id then
     *  given storm item is not in use currently.
     */
    sai_object_id_t  port_policers[MLNX_PORT_POLICER_TYPE_MAX];
    sx_port_log_id_t lag_id;
    uint32_t         internal_ingress_samplepacket_obj_idx;
    uint32_t         internal_egress_samplepacket_obj_idx;
    sai_object_id_t  scheduler_id;
    /* index of the 1st queue in the queue_db array */
    uint32_t               start_queues_index;
    mlnx_sched_hierarchy_t sched_hierarchy;
    uint16_t               rifs;
    bool                   lossless_pg[MAX_PG];
    uint16_t               acl_refs;
} mlnx_port_config_t;
typedef enum {
    MLNX_FID_FLOOD_TYPE_ALL,
    MLNX_FID_FLOOD_TYPE_NONE,
    MLNX_FID_FLOOD_TYPE_L2MC_GROUP,
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
void mlnx_fid_flood_ctrl_l2mc_group_refs_inc(_In_ const mlnx_fid_flood_data_t *data);
void mlnx_fid_flood_ctrl_l2mc_group_refs_dec(_In_ const mlnx_fid_flood_data_t *data);
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
} mlnx_vlan_db_t;

/* MLNX Bridge API */
sai_status_t mlnx_bridge_init(void);
sx_bridge_id_t mlnx_bridge_default_1q(void);
sai_object_id_t mlnx_bridge_default_1q_oid(void);
mlnx_bridge_t* mlnx_bridge_1d_by_db_idx(_In_ uint32_t db_idx);
sai_status_t mlnx_bridge_sx_ports_get(_In_ sx_bridge_id_t     sx_bridge,
                                      _Out_ sx_port_log_id_t *sx_ports,
                                      _Inout_ uint32_t       *ports_count);
sai_status_t mlnx_create_bridge_1d_object(sx_bridge_id_t sx_br_id, sai_object_id_t  *bridge_oid);
sai_status_t mlnx_bridge_oid_to_id(sai_object_id_t oid, sx_bridge_id_t *bridge_id);
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
sai_status_t mlnx_rif_oid_create(_In_ mlnx_rif_type_t          rif_type,
                                 _In_ const mlnx_bridge_rif_t *bridge_rif,
                                 _In_ mlnx_shm_rm_array_idx_t  idx,
                                 _Out_ sai_object_id_t        *rif_oid);
sai_status_t mlnx_rif_sx_to_sai_oid(_In_ sx_router_interface_t sx_rif_id, _Out_ sai_object_id_t      *oid);
sai_status_t mlnx_rif_oid_to_bridge_rif(_In_ sai_object_id_t rif_oid, _Out_ uint32_t *bridge_rif_idx);
sai_status_t mlnx_rif_oid_to_sdk_rif_id(sai_object_id_t rif_oid, sx_router_interface_t *sdk_rif_id);
sai_status_t mlnx_rif_sx_init(_In_ sx_router_id_t                     sx_router,
                              _In_ const sx_router_interface_param_t *intf_params,
                              _In_ const sx_interface_attributes_t   *intf_attribs,
                              _Out_ sx_router_interface_t            *sx_rif_id,
                              _Out_ sx_router_counter_id_t           *sx_counter);
sai_status_t mlnx_rif_sx_deinit(_In_ mlnx_rif_sx_data_t *sx_data);
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
sai_status_t mlnx_buffer_port_profile_list_set(_In_ const sai_object_id_t        port_id,
                                               _In_ const sai_attribute_value_t *value,
                                               _In_ bool                         is_ingress);
sai_status_t mlnx_get_sai_pool_data(_In_ sai_object_id_t sai_pool, _Out_ mlnx_sai_buffer_pool_attr_t* sai_pool_attr);

sai_status_t mlnx_port_tc_set(mlnx_port_config_t *port, _In_ const uint8_t tc);

sai_status_t get_buffer_profile_db_index(_In_ sai_object_id_t oid, _Out_ uint32_t* db_index);
sai_status_t mlnx_buffer_apply(_In_ sai_object_id_t sai_buffer, _In_ sai_object_id_t to_obj_id);

sai_status_t set_mc_sp_zero(_In_ uint32_t sp);

sai_status_t mlnx_wred_apply_to_queue(_In_ mlnx_port_config_t *port,
                                      _In_ uint32_t            queue_idx,
                                      _In_ sai_object_id_t     wred_id);
sai_status_t mlnx_wred_port_queue_db_clear(_In_ mlnx_port_config_t *port);

#define mlnx_vlan_id_foreach(vid) \
    for (vid = SXD_VID_MIN; vid <= SXD_VID_MAX; vid++)

#define mlnx_stp_vlans_foreach(stp_id, vid) \
    for (vid = SXD_VID_MIN; vid <= SXD_VID_MAX; vid++) \
        if (mlnx_vlan_stp_id_get(vid) == stp_id)

#define mlnx_port_local_foreach(port, idx) \
    for (idx = 0; idx < MAX_PORTS && \
         (port = &mlnx_ports_db[idx]); idx++) \
        if (port->logical)

#define mlnx_port_phy_foreach(port, idx) \
    for (idx = 0; idx < MAX_PORTS && \
         (port = &mlnx_ports_db[idx]); idx++) \
        if (port->is_present && port->logical)

#define mlnx_port_foreach(port, idx) \
    for (idx = 0; idx < (MAX_PORTS * 2) && \
         (port = &mlnx_ports_db[idx]); idx++) \
        if (port->is_present && port->logical)

#define mlnx_port_not_in_lag_foreach(port, idx) \
    for (idx = 0; idx < (MAX_PORTS * 2) && \
         (port = &mlnx_ports_db[idx]); idx++) \
        if (port->is_present && !port->lag_id)

#define mlnx_lag_foreach(lag, idx) \
    for (idx = MAX_PORTS; idx < (MAX_PORTS * 2) && \
         (lag = &mlnx_ports_db[idx]); idx++) \
        if (lag->is_present && lag->logical)

#define mlnx_vxlan_exist_foreach(tun, idx) \
    for (idx = 0; idx < MAX_TUNNEL_DB_SIZE && \
         (tun = &g_sai_db_ptr->tunnel_db[idx]); idx++) \
        if (tun->is_used && tun->sai_tunnel_type == SAI_TUNNEL_TYPE_VXLAN)

#define mlnx_bridge_non1q_port_foreach(port, idx, checked)  \
    for (idx = MAX_BRIDGE_1Q_PORTS, checked = 0;            \
         (idx < (MAX_BRIDGE_PORTS)) &&                      \
         (checked < g_sai_db_ptr->non_1q_bports_created) && \
         (port = &g_sai_db_ptr->bridge_ports_db[idx]);      \
         idx++, checked++)                                 \
        if (port->is_present)

#define mlnx_bridge_1d_foreach(bridge, idx)        \
    for (ii = 0;                                   \
         (ii < mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_BRIDGE)) && \
         (bridge = mlnx_bridge_1d_by_db_idx(ii));   \
         ii++)                                     \
        if (bridge->array_hdr.is_used)

#define mlnx_bridge_1q_port_foreach(port, idx) \
    for (idx = 0; idx < (MAX_BRIDGE_1Q_PORTS) && \
         (port = &g_sai_db_ptr->bridge_ports_db[idx]); idx++) \
        if (port->is_present)

#define mlnx_vlan_ports_foreach(vid, port, idx) \
    for (idx = 0; \
         (idx < MAX_BRIDGE_1Q_PORTS) && \
         (port = &g_sai_db_ptr->bridge_ports_db[idx]); idx++) \
        if (port->is_present && mlnx_vlan_port_is_set(vid, port))

typedef struct _mlnx_trap_t {
    sai_packet_action_t action;
    sai_object_id_t     trap_group;
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
#define ACL_MAX_SX_RULES_NUMBER 16000

/* Priority.
 * 0 is not allowed on sp2 since it makes region work in legacy mode
 * 1 is reserved for default goto rule
 * SAI range is [0, UINT16_MAX - 2]
 * SDK range is [2, UINT16_MAX]
 */
#define ACL_SAI_ENTRY_PRIO_TO_SX(prio) (prio + 2)
#define ACL_SX_RULE_PRIO_TO_SAI(prio)  (prio - 2)
#define ACL_SX_RULE_DEF_PRIO   (FLEX_ACL_RULE_PRIORITY_MIN)
#define ACL_SX_RULE_MIN_PRIO   (ACL_SX_RULE_DEF_PRIO + 1)
#define ACL_SX_RULE_MAX_PRIO   (FLEX_ACL_RULE_PRIORITY_MAX)
#define ACL_SAI_ENTRY_MIN_PRIO ACL_SX_RULE_PRIO_TO_SAI(ACL_SX_RULE_MIN_PRIO)
#define ACL_SAI_ENTRY_MAX_PRIO ACL_SX_RULE_PRIO_TO_SAI(ACL_SX_RULE_MAX_PRIO)
#define ACL_SAI_ENTRY_PRIO_CHECK_RANGE(prio) ((prio <= ACL_SAI_ENTRY_MAX_PRIO))

#define ACL_PSORT_TABLE_MIN_PRIO  ACL_SX_RULE_DEF_PRIO
#define ACL_PSORT_TABLE_MAX_PRIO  ACL_SX_RULE_MAX_PRIO
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

#define ACL_MAX_SX_COUNTER_BYTE_NUM   ACL_MAX_SX_RULES_NUMBER
#define ACL_MAX_SX_COUNTER_PACKET_NUM ACL_MAX_SX_RULES_NUMBER

#define ACL_MAX_SX_ING_GROUP_NUMBER ACL_GROUP_NUMBER
#define ACL_MAX_SX_EGR_GROUP_NUMBER ACL_GROUP_NUMBER

#define ACL_PBS_MAP_IDX_TRIVIAL_RANGE_START ((mlnx_acl_pbs_map_idx_t)0)
#define ACL_PBS_MAP_FLOOD_PBS_INDEX         ((mlnx_acl_pbs_map_idx_t)(MAX_PORTS * 2))
#define ACL_PBS_MAP_HASH_INDEX_START        ((mlnx_acl_pbs_map_idx_t)(ACL_PBS_MAP_FLOOD_PBS_INDEX + 1))

#define ACL_PBS_MAP_PREDEF_REG_SIZE (ACL_PBS_MAP_HASH_INDEX_START - ACL_PBS_MAP_IDX_TRIVIAL_RANGE_START) /* Ports LAGs and Flood PBS */
#define ACL_MAX_PBS_NUMBER          (g_resource_limits.acl_pbs_entries_max)
#define ACL_PBS_MAP_RESERVE_PERCENT 1.2

#define ACL_PBS_MAP_INVALID_INDEX ((mlnx_acl_pbs_map_idx_t)-1)
#define ACL_PBS_MAP_INDEX_IS_VALID(index) \
                                            (((index) != ACL_PBS_MAP_INVALID_INDEX) && \
                                             ((index) < g_sai_acl_db_pbs_map_size))
#define ACL_PBS_MAP_INDEX_IS_TRIVIAL(index) ((index) < ACL_PBS_MAP_FLOOD_PBS_INDEX)

#define SAI_HASH_MAX_OBJ_COUNT        32
#define SAI_ACL_RANGE_TYPE_COUNT      (SAI_ACL_RANGE_TYPE_PACKET_LENGTH + 1)
#define SAI_ACL_BIND_POINT_TYPE_COUNT (SAI_ACL_BIND_POINT_TYPE_SWITCH + 1)
#define SAI_ACL_MAX_BIND_POINT_BOUND  (MAX(MAX_PORTS + ACL_VLAN_GROUP_COUNT, ACL_RIF_COUNT))

#define ACL_IP_IDENT_FIELD_BYTE_COUNT 2
#define ACL_UDF_GROUP_COUNT_MAX       (SAI_ACL_USER_DEFINED_FIELD_ATTR_ID_RANGE + 1)

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
    acl_table_wrapping_group_t wrapping_group;
    sx_acl_rule_offset_t       def_rules_offset;
    sx_acl_key_t               def_rule_key;
    bool                       is_ip_ident_used;
    acl_udf_group_list_t       udf_group_list;
    uint32_t                   head_entry_index;
    uint32_t                   counter_ref;
} acl_table_db_t;

typedef uint16_t mlnx_acl_pbs_map_idx_t;
PACKED(struct _mlnx_acl_pbs_info_t {
           mlnx_acl_pbs_type_t type: 2;
           uint32_t idx: 17;       /* Should fit MAX_BRIDGE_PORTS (0x1F540) */
       }, );
typedef struct _mlnx_acl_pbs_info_t mlnx_acl_pbs_info_t;
#define MLNX_ACL_PBS_INFO_INVALID ((mlnx_acl_pbs_info_t) {.type = MLNX_ACL_PBS_TYPE_INVALID})
#define MLNX_ACL_PBS_INFO_IS_VALID(info) (info.type != MLNX_ACL_PBS_TYPE_INVALID)
typedef struct _acl_pbs_map_key_t {
    uint32_t data[MLNX_U32BITARRAY_SIZE(MAX_PORTS_DB * 2)];
} acl_pbs_map_key_t;

typedef struct _acl_pbs_map_db_t {
    acl_pbs_map_key_t    key;
    mlnx_acl_pbs_entry_t entry;
} acl_pbs_map_entry_t;

PACKED(struct _acl_entry_db_t {
           bool counter_byte_flag: 1;
           bool counter_packet_flag: 1;
           uint32_t next_entry_index: 19;
           uint32_t prev_entry_index: 19;
           bool is_used;
           uint16_t sx_prio;
           mlnx_acl_pbs_info_t pbs_info;
           sx_acl_rule_offset_t offset;
           sx_flow_counter_id_t sx_counter_id;
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

typedef struct _mlnx_acl_db_t {
    uint8_t              *db_base_ptr;
    acl_table_db_t       *acl_table_db;
    acl_entry_db_t       *acl_entry_db;
    acl_setting_tbl_t    *acl_settings_tbl;
    acl_pbs_map_entry_t  *acl_pbs_map_db;
    acl_bind_points_db_t *acl_bind_points;
    acl_group_db_t       *acl_groups_db;
    acl_vlan_group_t     *acl_vlan_groups_db;
    acl_group_bound_to_t *acl_group_bound_to_db;
    mlnx_udf_db_t         udf_db;
} mlnx_acl_db_t;

sai_status_t mlnx_acl_port_lag_event_handle_locked(_In_ const mlnx_port_config_t *port, _In_ acl_event_type_t event);
sai_status_t mlnx_acl_port_lag_event_handle_unlocked(_In_ const mlnx_port_config_t *port, _In_ acl_event_type_t event);

extern mlnx_acl_db_t *g_sai_acl_db_ptr;
extern uint32_t       g_sai_acl_db_pbs_map_size;

typedef struct _mlnx_policer_to_trap_group_bind_params {
    sai_attribute_value_t attr_prio_value;
} mlnx_policer_to_trap_group_bind_params;
typedef struct _mlnx_hash_obj_t {
    sai_object_id_t  hash_id;
    uint64_t         field_mask;
    udf_group_mask_t udf_group_mask;
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
    SAI_HASH_MAX_OBJ_ID
} mlnx_switch_usage_hash_object_id_t;

sai_status_t mlnx_hash_ecmp_hash_params_apply(const sai_attr_id_t attr_id, const sai_attribute_value_t* value);

sai_status_t mlnx_hash_object_apply(const sai_object_id_t                    hash_id,
                                    const mlnx_switch_usage_hash_object_id_t hash_oper_id);

sai_status_t mlnx_hash_ecmp_cfg_apply_on_port(sx_port_log_id_t port_log_id);

sai_status_t mlnx_udf_group_db_index_to_sx_acl_keys(_In_ uint32_t       udf_group_db_index,
                                                    _Out_ sx_acl_key_t *sx_acl_keys,
                                                    _Out_ uint32_t     *sx_acl_key_count);
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
sai_status_t mlnx_custom_bytes_set(_In_ sx_access_cmd_t                             cmd,
                                   _In_ const sx_acl_custom_bytes_set_attributes_t *attrs,
                                   _Inout_ sx_acl_key_t                            *keys,
                                   _In_ uint32_t                                    length);
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
void db_reset_policer_entry(_In_ uint32_t db_policer_entry_index);
sai_status_t db_find_sai_policer_entry_ind(_In_ sx_policer_id_t sx_policer, _Out_ uint32_t* entry_index);


/*
 *  Binds sai_policer to a given sai_object.
 */
sai_status_t mlnx_sai_bind_policer(_In_ sai_object_id_t           sai_object,
                                   _In_ sai_object_id_t           sai_policer,
                                   _In_ mlnx_policer_bind_params* bind_params);
sai_status_t mlnx_sai_unbind_policer(_In_ sai_object_id_t sai_object, _In_ mlnx_policer_bind_params* bind_params);
sai_status_t mlnx_sai_get_or_create_regular_sx_policer_for_bind(_In_ sai_object_id_t   sai_policer,
                                                                _In_ bool              is_host_if_policer,
                                                                _Out_ sx_policer_id_t* sx_policer_id);

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

#define MAX_TUNNEL_DB_SIZE            100
#define MLNX_TUNNELTABLE_SIZE         256
#define MLNX_TUNNEL_MAP_LIST_MAX      50
#define MLNX_TUNNEL_MAP_MIN           0
#define MLNX_TUNNEL_MAP_MAX           8
#define MLNX_TUNNEL_MAP_ENTRY_INVALID 0
#define MLNX_TUNNEL_MAP_ENTRY_MIN     1
#define MLNX_TUNNEL_MAP_ENTRY_MAX     50
#define MLNX_TUNNEL_TO_TUNNEL_MAP_MAX 1000
#define MAX_VXLAN_TUNNEL              1

typedef struct _mlnx_tunneltable_t {
    bool                        in_use;
    sx_tunnel_decap_entry_key_t sdk_tunnel_decap_key_ipv4;
    uint32_t                    tunnel_db_idx;
    bool                        tunnel_lazy_created;
} mlnx_tunneltable_t;

typedef struct _tunnel_db_entry_t {
    bool                  is_used;
    sai_tunnel_type_t     sai_tunnel_type;
    sx_tunnel_id_t        sx_tunnel_id_ipv4;
    sx_tunnel_id_t        sx_tunnel_id_ipv6;
    bool                  ipv4_created;
    bool                  ipv6_created;
    sx_router_interface_t sx_overlay_rif_ipv6;
    sai_object_id_t       sai_underlay_rif;
    sai_object_id_t       sai_tunnel_map_encap_id_array[MLNX_TUNNEL_MAP_MAX];
    uint32_t              sai_tunnel_map_encap_cnt;
    sai_object_id_t       sai_tunnel_map_decap_id_array[MLNX_TUNNEL_MAP_MAX];
    uint32_t              sai_tunnel_map_decap_cnt;
    sx_tunnel_attribute_t sx_tunnel_attr;
    sx_tunnel_ttl_data_t  sdk_encap_ttl_data_attrib;
    sx_tunnel_ttl_data_t  sdk_decap_ttl_data_attrib;
    sx_tunnel_cos_data_t  sdk_encap_cos_data;
    sx_tunnel_cos_data_t  sdk_decap_cos_data;
    uint32_t              term_table_cnt;
} tunnel_db_entry_t;

typedef struct _tunnel_map_t {
    bool                  in_use;
    sai_tunnel_map_type_t tunnel_map_type;
    uint32_t              tunnel_cnt;
    uint32_t              vxlan_tunnel_cnt;
    uint32_t              vxlan_tunnel_idx[MAX_VXLAN_TUNNEL];
    uint32_t              tunnel_map_entry_cnt;
    uint32_t              tunnel_map_entry_head_idx;
    uint32_t              tunnel_map_entry_tail_idx;
} mlnx_tunnel_map_t;

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
    uint32_t              prev_tunnel_map_entry_idx;
    uint32_t              next_tunnel_map_entry_idx;
} mlnx_tunnel_map_entry_t;

typedef enum _nve_tunnel_type_t {
    NVE_8021Q_TUNNEL,
    NVE_8021D_TUNNEL,
    NVE_TUNNEL_UNKNOWN
} mlnx_nve_tunnel_type_t;

typedef struct _fdb_action_t {
    sai_object_type_t type;
    union {
        sai_fdb_entry_t   fdb_entry;
        sai_route_entry_t route_entry;
    };
    sai_packet_action_t action;
} fdb_or_route_action_t;

typedef struct _fdb_actions_db_t {
    fdb_or_route_action_t actions[FDB_OR_ROUTE_SAVED_ACTIONS_NUM];
    uint32_t              count;
} fdb_or_route_actions_db_t;

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
    SAI_HOSTIF_OBJECT_TYPE_FD
} sai_host_object_type_t;

typedef struct sai_netdev {
    bool                   is_used;
    sai_host_object_type_t sub_type;
    char                   ifname[SAI_HOSTIF_NAME_SIZE + 1];
    sx_port_log_id_t       port_id;
    uint16_t               vid;
    sx_fd_t                fd;
} sai_netdev_t;

#define MLNX_L2MC_GROUP_DB_SIZE (1000)

typedef struct _mlnx_l2mc_group_t {
    bool                 is_used;
    sx_mc_container_id_t mc_container;
    mlnx_acl_pbs_entry_t pbs_entry;
    uint32_t             flood_ctrl_ref;
} mlnx_l2mc_group_t;

typedef enum {
    BOOT_TYPE_REGULAR,
    BOOT_TYPE_WARM,
    BOOT_TYPE_FAST
} mlnx_sai_boot_type_t;

#define l2mc_group_db(idx)                   (g_sai_db_ptr->l2mc_groups[(idx)])
#define MLNX_L2MC_GROUP_DB_IDX_IS_VALID(idx) ((idx) < MLNX_L2MC_GROUP_DB_SIZE)
#define MLNX_L2MC_GROUP_DB_IDX_INVALID ((uint32_t)(-1))

sai_status_t mlnx_l2mc_group_oid_create(_In_ const mlnx_l2mc_group_t *l2mc_group, _Out_ sai_object_id_t         *oid);
sai_status_t mlnx_l2mc_group_oid_to_sai(_In_ sai_object_id_t oid, _Out_ mlnx_l2mc_group_t **l2mc_group);
sai_status_t mlnx_l2mc_group_oid_to_db_idx(_In_ sai_object_id_t oid, _Out_ uint32_t       *db_idx);
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

typedef struct sai_db {
    cl_plock_t         p_lock;
    sx_mac_addr_t      base_mac_addr;
    char               dev_mac[18];
    uint32_t           ports_number;
    uint32_t           ports_configured;
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
    mlnx_trap_t                       traps_db[SXD_TRAP_ID_ACL_MAX];
    mlnx_qos_map_t                    qos_maps_db[MAX_QOS_MAPS_DB];
    uint32_t                          switch_qos_maps[MLNX_QOS_MAP_TYPES_MAX];
    uint8_t                           switch_default_tc;
    mlnx_policer_db_entry_t           policers_db[MAX_POLICERS];
    mlnx_hash_obj_t                   hash_list[SAI_HASH_MAX_OBJ_COUNT];
    sai_object_id_t                   oper_hash_list[SAI_HASH_MAX_OBJ_ID];
    sx_router_ecmp_port_hash_params_t port_hash_params;
    mlnx_samplepacket_t               mlnx_samplepacket_session[MLNX_SAMPLEPACKET_SESSION_MAX];
    mlnx_tunneltable_t                mlnx_tunneltable[MLNX_TUNNELTABLE_SIZE];
    tunnel_db_entry_t                 tunnel_db[MAX_TUNNEL_DB_SIZE];
    mlnx_tunnel_map_t                 mlnx_tunnel_map[MLNX_TUNNEL_MAP_MAX];
    mlnx_tunnel_map_entry_t           mlnx_tunnel_map_entry[MLNX_TUNNEL_MAP_ENTRY_MAX];
    bool                              tunnel_module_initialized;
    bool                              port_parsing_depth_set_for_tunnel;
    sx_bridge_id_t                    sx_bridge_id;
    sai_object_id_t                   default_1q_bridge_oid;
    sx_port_log_id_t                  sx_nve_log_port;
    mlnx_nve_tunnel_type_t            nve_tunnel_type;
    bool                              is_stp_initialized;
    sx_mstp_inst_id_t                 def_stp_id;
    mlnx_mstp_inst_t                  mlnx_mstp_inst_db[SX_MSTP_INST_ID_MAX - SX_MSTP_INST_ID_MIN + 1];
    sai_packet_action_t               flood_actions[MLNX_FID_FLOOD_CTRL_ATTR_MAX];
    fdb_or_route_actions_db_t         fdb_or_route_actions;
    bool                              transaction_mode_enable;
    bool                              issu_enabled;
    bool                              restart_warm;
    bool                              warm_recover;
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
    mlnx_l2mc_group_t                 l2mc_groups[MLNX_L2MC_GROUP_DB_SIZE];
    mlnx_shm_rm_array_info_t          array_info[MLNX_SHM_RM_ARRAY_TYPE_SIZE];
} sai_db_t;

extern sai_db_t *g_sai_db_ptr;

#define mlnx_ports_db (g_sai_db_ptr->ports_db)

mlnx_port_config_t * mlnx_port_by_idx(uint8_t id);
mlnx_port_config_t * mlnx_port_by_local_id(uint8_t local_port);

typedef struct mlnx_qos_queue_config {
    sai_object_id_t  wred_id;
    sai_object_id_t  buffer_id;
    mlnx_sched_obj_t sched_obj;
} mlnx_qos_queue_config_t;

#define port_queues_foreach(port, queue, idx) \
    for (idx = 0; \
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
} mlnx_sai_buffer_resource_limits_t;
const mlnx_sai_buffer_resource_limits_t* mlnx_sai_get_buffer_resource_limits();

void init_buffer_resource_limits();

#define BUFFER_DB_PER_PORT_PROFILE_INDEX_ARRAY_SIZE                          \
    (mlnx_sai_get_buffer_resource_limits()->num_ingress_pools +    \
     mlnx_sai_get_buffer_resource_limits()->num_egress_pools +    \
     mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff       \
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
     *  existring buffer configuration will be deleted.
     *  This item will be set initially to 0, and after first create pool request will be set to true.
     *  Once set to true, it cannot be modified.
     */
    bool *pool_allocation;
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
uint32_t mlnx_port_idx_get(const mlnx_port_config_t *port);

/* DB read lock is needed */
sai_status_t mlnx_port_add(mlnx_port_config_t *port);
sai_status_t mlnx_port_del(mlnx_port_config_t *port);
sai_status_t mlnx_port_config_init(mlnx_port_config_t *port);
sai_status_t mlnx_port_config_uninit(mlnx_port_config_t *port);
sai_status_t mlnx_port_auto_split(mlnx_port_config_t *port);
sai_status_t mlnx_port_speed_bitmap_apply(_In_ const mlnx_port_config_t *port);
sai_status_t mlnx_port_crc_params_apply(const mlnx_port_config_t *port);

sai_status_t mlnx_port_in_use_check(const mlnx_port_config_t *port);
bool mlnx_port_is_net(const mlnx_port_config_t *port);
bool mlnx_port_is_virt(const mlnx_port_config_t *port);
bool mlnx_port_is_lag(const mlnx_port_config_t *port);
bool mlnx_port_is_lag_member(const mlnx_port_config_t *port);
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
sai_status_t mlnx_port_mirror_wred_discard_set(_In_ sx_port_log_id_t port_log_id, _In_ bool is_add);
sai_status_t mlnx_port_speed_get_impl(_In_ sx_port_log_id_t sx_port,
                                      _Out_ uint32_t       *oper_speed,
                                      _Out_ uint32_t       *admin_speed);

/* DB read lock is needed */
sai_status_t mlnx_switch_get_mac(sx_mac_addr_t *mac);

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

#define KV_DEVICE_MAC_ADDRESS "DEVICE_MAC_ADDRESS"
#define KV_INITIAL_FAN_SPEED  "INITIAL_FAN_SPEED"
#define MIN_FAN_PERCENT       30
#define MAX_FAN_PERCENT       100

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

#define LINE_LENGTH 120

void SAI_dump_acl(_In_ FILE *file);
void SAI_dump_bridge(_In_ FILE *file);
void SAI_dump_buffer(_In_ FILE *file);
void SAI_dump_hash(_In_ FILE *file);
void SAI_dump_hostintf(_In_ FILE *file);
void SAI_dump_policer(_In_ FILE *file);
void SAI_dump_port(_In_ FILE *file);
void SAI_dump_qosmaps(_In_ FILE *file);
void SAI_dump_queue(_In_ FILE *file);
void SAI_dump_samplepacket(_In_ FILE *file);
void SAI_dump_scheduler(_In_ FILE *file);
void SAI_dump_stp(_In_ FILE *file);
void SAI_dump_tunnel(_In_ FILE *file);
void SAI_dump_udf(_In_ FILE *file);
void SAI_dump_vlan(_In_ FILE *file);
void SAI_dump_wred(_In_ FILE *file);

#endif /* __MLNXSAI_H_ */
