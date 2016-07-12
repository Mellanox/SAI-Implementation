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

#if !defined (__MLNXSAI_H_)
#define __MLNXSAI_H_

#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_router.h>
#include <sx/sdk/sx_api_vlan.h>
#include <sx/sdk/sx_api_cos.h>
#include <sx/sdk/sx_api_lag.h>
#include <sx/sdk/sx_api_mstp.h>
#include <sx/sdk/sx_api_port.h>
#include <sx/sdk/sx_api_fdb.h>
#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_init.h>
#include <sx/sdk/sx_api_host_ifc.h>
#include <sx/sdk/sx_lib_host_ifc.h>
#include <sx/sdk/sx_api_policer.h>
#include <sx/sdk/sx_api_acl.h>
#include <sx/sdk/sx_api_flex_acl.h>
#include <sx/sdk/sx_lib_flex_acl.h>
#include <sx/sdk/sx_api_flow_counter.h>
#include <sx/sdk/sx_api_span.h>
#include <sx/sdk/sx_api_topo.h>
#include <sx/sdk/sx_api_dbg.h>
#include <sx/sdk/sx_api_cos_redecn.h>
#include <sx/sdk/sx_api_tunnel.h>
#include <resource_manager/resource_manager.h>
#include <sx/sxd/sxd_command_ifc.h>
#include <sx/sxd/sxd_dpt.h>
#include <sx/sxd/sxd_status.h>
#include <sx/sxd/sxd_access_register.h>
#include <complib/cl_passivelock.h>
#include <complib/cl_event.h>
#ifndef _WIN32
#include <pthread.h>
#endif
#include <sx/utils/psort.h>
#include <sai.h>

#define SAI_ERR(status) ((status) != SAI_STATUS_SUCCESS)
#define SX_ERR(status)  ((status) != SX_STATUS_SUCCESS)

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
#define IF_NAMESIZE 32
#define PROT_READ   1
#define PROT_WRITE  2
#define MAP_SHARED  1
#define MAP_FAILED  (void*)-1
#define MS_SYNC     4
#endif

extern sx_api_handle_t        gh_sdk;
extern service_method_table_t g_mlnx_services;
extern rm_resources_t         g_resource_limits;
extern sx_log_cb_t            sai_log_cb;

sai_status_t sdk_to_sai(sx_status_t status);

extern const sai_route_api_t            mlnx_route_api;
extern const sai_virtual_router_api_t   mlnx_router_api;
extern const sai_switch_api_t           mlnx_switch_api;
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

#define DEFAULT_ETH_SWID 0
#define DEFAULT_VRID     0
#define DEFAULT_RIF_MTU  1500

#define DEFAULT_MULTICAST_TTL_THRESHOLD 1
#define FIRST_PORT                      (0x10000 | (1 << 8))
#define PORT_MAC_BITMASK                (~0x3F)
#define PORT_SPEED_100                  100000
#define PORT_SPEED_50                   50000
#define PORT_SPEED_25                   25000
#define PORT_SPEED_56                   56000
#define PORT_SPEED_40                   40000
#define PORT_SPEED_20                   20000
#define PORT_SPEED_10                   10000
#define PORT_SPEED_1                    1000
#define NUM_SPEEDS                      8
#define CPU_PORT                        0
#define ECMP_MAX_PATHS                  64
#define SX_DEVICE_ID                    1
#define DEFAULT_DEVICE_ID               255
#define DEFAULT_VLAN                    1
#define DEFAULT_TRAP_GROUP_PRIO         SX_TRAP_PRIORITY_LOW
#define DEFAULT_TRAP_GROUP_ID           0
#define RECV_ATTRIBS_NUM                3
#define FDB_NOTIF_ATTRIBS_NUM           3

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

/*
 *  Attribute value types
 */
typedef enum _sai_attribute_value_type_t {
    SAI_ATTR_VAL_TYPE_UNDETERMINED,
    SAI_ATTR_VAL_TYPE_BOOL,
    SAI_ATTR_VAL_TYPE_CHARDATA,
    SAI_ATTR_VAL_TYPE_U8,
    SAI_ATTR_VAL_TYPE_S8,
    SAI_ATTR_VAL_TYPE_U16,
    SAI_ATTR_VAL_TYPE_S16,
    SAI_ATTR_VAL_TYPE_U32,
    SAI_ATTR_VAL_TYPE_S32,
    SAI_ATTR_VAL_TYPE_U64,
    SAI_ATTR_VAL_TYPE_S64,
    SAI_ATTR_VAL_TYPE_MAC,
    SAI_ATTR_VAL_TYPE_IPV4,
    SAI_ATTR_VAL_TYPE_IPV6,
    SAI_ATTR_VAL_TYPE_IPADDR,
    SAI_ATTR_VAL_TYPE_OID,
    SAI_ATTR_VAL_TYPE_OBJLIST,
    SAI_ATTR_VAL_TYPE_U8LIST,
    SAI_ATTR_VAL_TYPE_S8LIST,
    SAI_ATTR_VAL_TYPE_U16LIST,
    SAI_ATTR_VAL_TYPE_S16LIST,
    SAI_ATTR_VAL_TYPE_U32LIST,
    SAI_ATTR_VAL_TYPE_S32LIST,
    SAI_ATTR_VAL_TYPE_U32RANGE,
    SAI_ATTR_VAL_TYPE_S32RANGE,
    SAI_ATTR_VAL_TYPE_VLANLIST,
    SAI_ATTR_VAL_TYPE_ACLFIELD_BOOLDATA,
    SAI_ATTR_VAL_TYPE_ACLFIELD_U8,
    SAI_ATTR_VAL_TYPE_ACLFIELD_S8,
    SAI_ATTR_VAL_TYPE_ACLFIELD_U16,
    SAI_ATTR_VAL_TYPE_ACLFIELD_S16,
    SAI_ATTR_VAL_TYPE_ACLFIELD_U32,
    SAI_ATTR_VAL_TYPE_ACLFIELD_S32,
    SAI_ATTR_VAL_TYPE_ACLFIELD_MAC,
    SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4,
    SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6,
    SAI_ATTR_VAL_TYPE_ACLFIELD_OID,
    SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST,
    SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST,
    SAI_ATTR_VAL_TYPE_ACLACTION_U8,
    SAI_ATTR_VAL_TYPE_ACLACTION_S8,
    SAI_ATTR_VAL_TYPE_ACLACTION_U16,
    SAI_ATTR_VAL_TYPE_ACLACTION_S16,
    SAI_ATTR_VAL_TYPE_ACLACTION_U32,
    SAI_ATTR_VAL_TYPE_ACLACTION_S32,
    SAI_ATTR_VAL_TYPE_ACLACTION_MAC,
    SAI_ATTR_VAL_TYPE_ACLACTION_IPV4,
    SAI_ATTR_VAL_TYPE_ACLACTION_IPV6,
    SAI_ATTR_VAL_TYPE_ACLACTION_OID,
    SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST,
    SAI_ATTR_VAL_TYPE_ACLACTION_NONE,
    SAI_ATTR_VAL_TYPE_PORTBREAKOUT,
    SAI_ATTR_VAL_TYPE_QOSMAP,
    SAI_ATTR_VAL_TYPE_TUNNELMAP,
    SAI_ATTR_VAL_TYPE_ACLCAPABILITY
} sai_attribute_value_type_t;
typedef struct _sai_attribute_entry_t {
    sai_attr_id_t              id;
    bool                       mandatory_on_create;
    bool                       valid_for_create;
    bool                       valid_for_set;
    bool                       valid_for_get;
    const char                *attrib_name;
    sai_attribute_value_type_t type;
} sai_attribute_entry_t;

#define EXTENDED_DATA_SIZE 3
typedef struct _mlnx_object_id_t {
    sai_uint8_t  object_type;
    sai_uint8_t  extended_data[EXTENDED_DATA_SIZE];
    sai_uint32_t data;
} mlnx_object_id_t;

#define SAI_TYPE_CHECK_RANGE(type) (type < SAI_OBJECT_TYPE_MAX)

#define SAI_TYPE_STR(type) SAI_TYPE_CHECK_RANGE(type) ? sai_type2str_arr[type] : "Unknown object type"

static __attribute__((__used__)) const char *sai_type2str_arr[] = {
    /* SAI_OBJECT_TYPE_NULL = 0 */
    "NULL",

    /*SAI_OBJECT_TYPE_PORT = 1 */
    "Port",

    /*SAI_OBJECT_TYPE_LAG = 2 */
    "LAG",

    /*SAI_OBJECT_TYPE_VIRTUAL_ROUTER = 3 */
    "Virtual router",

    /* SAI_OBJECT_TYPE_NEXT_HOP = 4 */
    "Next hop",

    /* SAI_OBJECT_TYPE_NEXT_HOP_GROUP = 5 */
    "Next hop group",

    /* SAI_OBJECT_TYPE_ROUTER_INTERFACE = 6 */
    "Router interface",

    /* SAI_OBJECT_TYPE_ACL_TABLE = 7 */
    "ACL table",

    /* SAI_OBJECT_TYPE_ACL_ENTRY = 8 */
    "ACL entry",

    /* SAI_OBJECT_TYPE_ACL_COUNTER = 9 */
    "ACL counter",

    /* SAI_OBJECT_TYPE_ACL_RANGE = 10 */
    "ACL range",

    /* SAI_OBJECT_TYPE_HOST_INTERFACE = 11 */
    "Host interface",

    /* SAI_OBJECT_TYPE_MIRROR = 12 */
    "Mirror",

    /* SAI_OBJECT_TYPE_SAMPLEPACKET = 13 */
    "Sample packet",

    /* SAI_OBJECT_TYPE_STP_INSTANCE = 14 */
    "Stp instance",

    /* SAI_OBJECT_TYPE_TRAP_GROUP = 15 */
    "Trap group",

    /* SAI_OBJECT_TYPE_ACL_TABLE_GROUP = 16 */
    "ACL table group",

    /* SAI_OBJECT_TYPE_POLICER = 17 */
    "Policer",

    /* SAI_OBJECT_TYPE_WRED = 18 */
    "WRED",

    /* SAI_OBJECT_TYPE_QOS_MAPS = 19 */
    "QoS Map",

    /* SAI_OBJECT_TYPE_QUEUE = 20 */
    "Queue",

    /* SAI_OBJECT_TYPE_SCHEDULER = 21 */
    "Scheduler",

    /* SAI_OBJECT_TYPE_SCHEDULER_GROUP = 22 */
    "Scheduler group",

    /* SAI_OBJECT_TYPE_BUFFER_POOL = 23 */
    "Buffer pool",

    /* SAI_OBJECT_TYPE_BUFFER_PROFILE = 24 */
    "Buffer profile",

    /* SAI_OBJECT_TYPE_PRIORITY_GROUP = 25 */
    "Priority group",

    /* SAI_OBJECT_TYPE_LAG_MEMBER = 26 */
    "LAG member",

    /* SAI_OBJECT_TYPE_HASH = 27 */
    "Hash",

    /* SAI_OBJECT_TYPE_UDF = 28 */
    "UDF",

    /* SAI_OBJECT_TYPE_UDF_MATCH = 29 */
    "UDF match",

    /* SAI_OBJECT_TYPE_UDF_GROUP = 30 */
    "UDF group",

    /* SAI_OBJECT_TYPE_FDB = 31 */
    "FDB",

    /*SAI_OBJECT_TYPE_SWITCH = 32 */
    "Switch",

    /* SAI_OBJECT_TYPE_TRAP = 33 */
    "Trap",

    /* SAI_OBJECT_TYPE_TRAP_USER_DEF = 34 */
    "User def trap",

    /* SAI_OBJECT_TYPE_NEIGHBOR = 35 */
    "Neighbor",

    /* SAI_OBJECT_TYPE_ROUTE = 36 */
    "Route",

    /* SAI_OBJECT_TYPE_VLAN = 37 */
    "VLAN",

    /* SAI_OBJECT_TYPE_VLAN_MEMBER = 38 */
    "VLAN member",

    /* SAI_OBJECT_TYPE_PACKET = 39 */
    "Packet",

    /* SAI_OBJECT_TYPE_TUNNEL_MAP = 40 */
    "Tunnel map",

    /* SAI_OBJECT_TYPE_TUNNEL = 41 */
    "Tunnel",

    /* SAI_OBJECT_TYPE_TUNNEL_TABLE_ENTRY = 42 */
    "Tunnel table entry"

    /* SAI_OBJECT_TYPE_MAX = 43 */
};

typedef union {
    const sai_fdb_entry_t          * fdb_entry;
    const sai_neighbor_entry_t     * neighbor_entry;
    const sai_unicast_route_entry_t* unicast_route_entry;
    const sai_vlan_id_t              vlan_id;
    const uint32_t                   trap_id;
    const sai_object_id_t            object_id;
} sai_object_key_t;
typedef sai_status_t (*sai_attribute_set_fn)(_In_ const sai_object_key_t *key, _In_ const sai_attribute_value_t *value,
                                             void *arg);
typedef struct _mlnx_fdb_cache_t {
    sx_port_id_t               log_port;    /**< Logical port */
    sx_fdb_uc_mac_entry_type_t entry_type;  /**< FDB Entry Type */
    sx_fdb_action_t            action;
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

#define MLNX_QOS_MAP_COLOR_MAX 2
#define MLNX_QOS_MAP_TYPES_MAX 10
#define MLNX_QOS_MAP_CODES_MAX (SX_COS_PORT_DSCP_MAX + 1)

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
} mlnx_qos_map_t;
typedef enum {
    /* TODO: IS_PHY_NONE_MEMBER */
    ATTR_PORT_IS_ENABLED = 1 << 0,
        /* TODO: IS_PHY_NONE_MEMBER_OR_LAG */
        ATTR_PORT_IS_LAG_ENABLED = 1 << 1,
        /* TODO: IS_PHY_OR_LAG_MEMBER */
        ATTR_PORT_IS_IN_LAG_ENABLED = 1 << 2,
} attr_port_type_check_t;

sai_status_t check_port_type_attr(const sai_object_id_t *ports,
                                  uint32_t               count,
                                  attr_port_type_check_t check,
                                  sai_attr_id_t          attr_id,
                                  uint32_t               idx);

sai_status_t check_attribs_metadata(_In_ uint32_t                            attr_count,
                                    _In_ const sai_attribute_t              *attr_list,
                                    _In_ const sai_attribute_entry_t        *functionality_attr,
                                    _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                    _In_ sai_common_api_t                    oper);

sai_status_t find_attrib_in_list(_In_ uint32_t                       attr_count,
                                 _In_ const sai_attribute_t         *attr_list,
                                 _In_ sai_attr_id_t                  attrib_id,
                                 _Out_ const sai_attribute_value_t **attr_value,
                                 _Out_ uint32_t                     *index);

sai_status_t sai_set_attribute(_In_ const sai_object_key_t             *key,
                               _In_ const char                         *key_str,
                               _In_ const sai_attribute_entry_t        *functionality_attr,
                               _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                               _In_ const sai_attribute_t              *attr);

sai_status_t sai_get_attributes(_In_ const sai_object_key_t             *key,
                                _In_ const char                         *key_str,
                                _In_ const sai_attribute_entry_t        *functionality_attr,
                                _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                _In_ uint32_t                            attr_count,
                                _Inout_ sai_attribute_t                 *attr_list);

#define MAX_KEY_STR_LEN        100
#define MAX_VALUE_STR_LEN      100
#define MAX_LIST_VALUE_STR_LEN 1000

sai_status_t sai_value_to_str(_In_ sai_attribute_value_t      value,
                              _In_ sai_attribute_value_type_t type,
                              _In_ uint32_t                   max_length,
                              _Out_ char                     *value_str);
sai_status_t sai_attr_list_to_str(_In_ uint32_t                     attr_count,
                                  _In_ const sai_attribute_t       *attr_list,
                                  _In_ const sai_attribute_entry_t *functionality_attr,
                                  _In_ uint32_t                     max_length,
                                  _Out_ char                       *list_str);
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


sai_status_t mlnx_object_to_type(sai_object_id_t   object_id,
                                 sai_object_type_t type,
                                 uint32_t         *data,
                                 uint8_t           extended_data[]);
sai_status_t mlnx_create_object(sai_object_type_t type,
                                uint32_t          data,
                                uint8_t           extended_data[],
                                sai_object_id_t  *object_id);

sai_status_t mlnx_object_to_log_port(sai_object_id_t object_id, sx_port_log_id_t *port_id);

sai_status_t mlnx_log_port_to_object(sx_port_log_id_t port_id, sai_object_id_t *object_id);

bool mlnx_route_entries_are_equal(_In_ const sai_unicast_route_entry_t *u1, _In_ const sai_unicast_route_entry_t *u2);
sai_status_t mlnx_translate_sdk_trap_to_sai(_In_ sx_trap_id_t           sdk_trap_id,
                                            _Out_ sai_hostif_trap_id_t *trap_id,
                                            _Out_ const char          **trap_name);

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

sai_status_t mlnx_register_trap(const sx_access_cmd_t cmd, uint32_t index);
sai_status_t mlnx_trap_set(uint32_t index, sai_packet_action_t sai_action, sai_object_id_t trap_group);

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

sai_status_t mlnx_fill_objlist(sai_object_id_t *data, uint32_t count, sai_object_list_t *list);
sai_status_t mlnx_fill_u8list(uint8_t *data, uint32_t count, sai_u8_list_t *list);
sai_status_t mlnx_fill_s8list(int8_t *data, uint32_t count, sai_s8_list_t *list);
sai_status_t mlnx_fill_u16list(uint16_t *data, uint32_t count, sai_u16_list_t *list);
sai_status_t mlnx_fill_s16list(int16_t *data, uint32_t count, sai_s16_list_t *list);
sai_status_t mlnx_fill_u32list(uint32_t *data, uint32_t count, sai_u32_list_t *list);
sai_status_t mlnx_fill_s32list(int32_t *data, uint32_t count, sai_s32_list_t *list);
sai_status_t mlnx_fill_vlanlist(sai_vlan_id_t *data, uint32_t count, sai_vlan_list_t *list);
sai_status_t mlnx_fill_tunnelmaplist(sai_tunnel_map_t *data, uint32_t count, sai_tunnel_map_list_t *list);

sai_status_t mlnx_wred_apply(sai_object_id_t wred_id, sai_object_id_t to_obj_id);
sai_status_t mlnx_wred_init();
sai_status_t mlnx_wred_get_wred_id(sai_object_id_t port_id, sai_object_id_t *wred_id);

sai_status_t mlnx_scheduler_to_queue_apply(sai_object_id_t scheduler_id, sai_object_id_t queue_id);

sai_status_t mlnx_scheduler_to_port_apply(sai_object_id_t scheduler_id, sai_object_id_t port_id);
/* DB write lock is needed */
sai_status_t mlnx_scheduler_to_group_apply(sai_object_id_t scheduler_id, sai_object_id_t group_id);

sai_status_t mlnx_create_queue(_In_ sx_port_log_id_t port_id, _In_ uint8_t index, _Out_ sai_object_id_t *id);
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

sai_status_t mlnx_acl_init();
sai_status_t mlnx_acl_deinit();
void mlnx_acl_foreground_ipc_deinit();

sai_status_t mlnx_hash_initialize();

extern const sai_attribute_entry_t host_interface_packet_attribs[];
#define END_TRAP_INFO_ID 0xFFFFFFFF
typedef enum _mlnx_trap_type_t {
    MLNX_TRAP_TYPE_REGULAR,
    MLNX_TRAP_TYPE_USER_DEFINED
} mlnx_trap_type_t;

#define MAX_SDK_TRAPS_PER_SAI_TRAP 6
typedef struct _mlnx_trap_info_t {
    sai_hostif_trap_id_t trap_id;
    uint8_t              sdk_traps_num;
    sx_trap_id_t         sdk_trap_ids[MAX_SDK_TRAPS_PER_SAI_TRAP];
    sai_packet_action_t  action;
    const char          *trap_name;
    mlnx_trap_type_t     trap_type;
} mlnx_trap_info_t;
extern const mlnx_trap_info_t mlnx_traps_info[];

#define MAX_PORTS       64
#define MAX_LANES       4
#define MAX_FDS         100
#define MAX_POLICERS    100
#define MAX_TRAP_GROUPS 32

#define DEFAULT_INGRESS_SX_POOL_ID 0
#define DEFAULT_EGRESS_SX_POOL_ID  4
#define EGRESS_CPU_PORT_SX_POOL_ID 7

#define SENTINEL_BUFFER_DB_ENTRY_INDEX 0

#define MAX_SCHED_LEVELS       3
#define MAX_SCHED_CHILD_GROUPS 8
#define MAX_PORT_SCHED_GROUPS  17
#define MAX_ETS_ELEMENTS       (g_resource_limits.cos_port_ets_elements_num)

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
    uint32_t                    sx_pool_id;
    sai_buffer_pool_type_t      pool_type;
    sai_buffer_threshold_mode_t pool_mode;
    /*size in bytes*/
    uint32_t pool_size;
} mlnx_sai_buffer_pool_attr_t;
typedef struct _mlnx_sai_shared_max_size_t {
    sai_buffer_threshold_mode_t mode;
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
    MLNX_SCHED_OBJ_GROUP,
    MLNX_SCHED_OBJ_QUEUE,
} mlnx_sched_obj_type_t;
typedef struct mlnx_sched_obj {
    mlnx_sched_obj_type_t  type;
    sai_object_id_t        scheduler_id;
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
typedef struct _mlnx_port_config_t {
    uint32_t                        local;
    uint32_t                        module;
    uint32_t                        width;
    mlnx_port_breakout_capability_t breakout_modes;
    sx_port_speed_t                 port_speed;
    sx_port_log_id_t                logical;
    sai_object_id_t                 saiport;
    uint8_t                         default_tc;
    uint32_t                        qos_maps[MLNX_QOS_MAP_TYPES_MAX];

    /*  SAI Port can have up to MLNX_PORT_POLICER_TYPE_MAX SDK port storm policers in use internally.
     *   For each storm item we keep type of traffic it'll handle and SAI policer id which contains the policer attributes (cbs, pir, etc.)
     *   if SAI_NULL_OBJECT_ID == policer_id then given storm item is not in use currently.
     */
    sai_object_id_t  port_policers[MLNX_PORT_POLICER_TYPE_MAX];
    sx_port_log_id_t lag_id;
    uint32_t         internal_ingress_samplepacket_obj_idx;
    uint32_t         internal_egress_samplepacket_obj_idx;
    sai_object_id_t  wred_id;
    sai_object_id_t  scheduler_id;
    /* index of the 1st queue in the queue_db array */
    uint32_t               start_queues_index;
    mlnx_sched_hierarchy_t sched_hierarchy;
    uint16_t               rifs;
    uint16_t               vlans;
    uint32_t               fdbs;
} mlnx_port_config_t;


sai_status_t mlnx_buffer_port_profile_list_get(_In_ const sai_object_id_t     port_id,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ bool                      is_ingress);
sai_status_t mlnx_buffer_port_profile_list_set(_In_ const sai_object_id_t        port_id,
                                               _In_ const sai_attribute_value_t *value,
                                               _In_ bool                         is_ingress);

sai_status_t mlnx_port_tc_set(mlnx_port_config_t *port, _In_ const uint8_t tc);

sai_status_t mlnx_sai_buffer_load_current_config();
sai_status_t get_buffer_profile_db_index(_In_ sai_object_id_t oid, _Out_ uint32_t* db_index);
sai_status_t mlnx_buffer_apply(_In_ sai_object_id_t sai_buffer, _In_ sai_object_id_t to_obj_id);

#define mlnx_ports_db (g_sai_db_ptr->ports_db)

#define mlnx_port_phy_foreach(port, idx) \
    for (idx = 0; idx < MAX_PORTS && \
         (port = &mlnx_ports_db[idx]); idx++) \
        if (port->logical)

#define mlnx_port_foreach(port, idx) \
    for (idx = 0; idx < (MAX_PORTS * 2) && \
         (port = &mlnx_ports_db[idx]); idx++) \
        if (port->logical)

#define mlnx_port_not_in_lag_foreach(port, idx) \
    for (idx = 0; idx < (MAX_PORTS * 2) && \
         (port = &mlnx_ports_db[idx]); idx++) \
        if (port->logical && !port->lag_id)

#define mlnx_lag_foreach(lag, idx) \
    for (idx = MAX_PORTS; idx < (MAX_PORTS * 2) && \
         (lag = &mlnx_ports_db[idx]); idx++) \
        if (lag->logical)

typedef struct _mlnx_trap_t {
    sai_packet_action_t       action;
    sai_hostif_trap_channel_t trap_channel;
    sai_object_id_t           fd;
    sai_object_id_t           trap_group;
} mlnx_trap_t;

typedef struct _mlnx_wred_profile_t {
    sx_cos_redecn_profile_t green_profile_id;
    sx_cos_redecn_profile_t yellow_profile_id;
    sx_cos_redecn_profile_t red_profile_id;
    bool                    ecn_enabled;
    bool                    in_use;
} mlnx_wred_profile_t;

#define MAX_QOS_MAPS           MAX_PORTS
#define SAI_INVALID_PROFILE_ID 0xFFFFFFFF
#define MAX_SCHED              ((g_resource_limits.cos_port_ets_elements_num) * MAX_PORTS)
#define MAX_QUEUES             (g_resource_limits.cos_port_ets_traffic_class_max + 1)
#define MAX_SUB_GROUPS         (g_resource_limits.cos_port_ets_sub_group_max + 1)
#define MAX_ETS_TC             (g_resource_limits.cos_port_ets_traffic_class_max)
#define MAX_USED_TC            8
#define MAX_PORT_PRIO          (g_resource_limits.cos_port_prio_max)
#define MAX_PCP_PRIO           7

#define MAX_SCHED_LEVELS       3
#define MAX_SCHED_CHILD_GROUPS 8
#define MAX_PORT_SCHED_GROUPS  17
#define MAX_ETS_ELEMENTS       (g_resource_limits.cos_port_ets_elements_num)

#define ACL_GROUP_SIZE          (g_resource_limits.acl_groups_size_max)
#define ACL_GROUP_NUMBER        2
#define ACL_INGRESS_GROUP_INDEX 0
#define ACL_EGRESS_GROUP_INDEX  1
#define MAX_INGRESS_TABLE_SIZE  512
#define MAX_EGRESS_TABLE_SIZE   128
#define MAX_ACL_STAGE           2
#define MAX_ACL_GROUP           2

#define MAX_ACL_COUNTER_NUM    1000
#define MAX_ACL_ENTRY_NUM      1000
#define DEFAULT_ACL_TABLE_SIZE 1000

#define ACL_USER_META_RANGE_MIN 0
#define ACL_USER_META_RANGE_MAX UINT16_MAX

#define ACL_MIN_TABLE_PRIO   0
#define ACL_MAX_TABLE_PRIO   UINT32_MAX
#define ACL_MAX_ENTRY_NUMBER 16000
#define ACL_MAX_ENTRY_PRIO   ACL_MAX_ENTRY_NUMBER
#define ACL_MIN_ENTRY_PRIO   1
#define ACL_MAX_TABLE_NUMBER (ACL_GROUP_SIZE * ACL_GROUP_NUMBER)

#define ACL_MAX_COUNTER_BYTE_NUM   ACL_MAX_ENTRY_NUMBER
#define ACL_MAX_COUNTER_PACKET_NUM ACL_MAX_ENTRY_NUMBER
#define ACL_MAX_COUNTER_NUM        (ACL_MAX_COUNTER_BYTE_NUM + ACL_MAX_COUNTER_PACKET_NUM)

#define ACL_PBS_MAP_PREDEF_REG_SIZE 65 /* 64 ports + flood */
#define ACL_MAX_PBS_NUMBER          (g_resource_limits.acl_pbs_entries_max)
#define ACL_PBS_MAP_RESERVE_PERCENT 1.2

#define SAI_HASH_MAX_OBJ_COUNT 32


typedef struct _acl_table_db_t {
    bool               is_used;
    bool               is_lock_inited;
    uint32_t           queued;
    sx_acl_id_t        table_id;
    sai_acl_stage_t    stage;
    uint32_t           priority;
    sx_acl_size_t      table_size;
    sx_acl_region_id_t region_id;
    sx_acl_size_t      region_size;
    sx_acl_key_type_t  key_type;
    bool               is_dynamic_sized;
    uint32_t           created_entry_count;
    uint32_t           created_rule_count;
    uint32_t           head_entry_index;
    psort_handle_t     psort_handle;
    cl_plock_t         lock;
} acl_table_db_t;

typedef struct _acl_group_db_t {
    sx_acl_id_t group_id;
    uint32_t    acl_table_count;
    uint32_t    table_indexes[];
} acl_group_db_t;

typedef struct _acl_counter_db_t {
    sx_flow_counter_id_t counter_id;
    bool                 byte_counter_flag;
    bool                 packet_counter_flag;
    bool                 is_valid;
} acl_counter_db_t;

typedef struct _pbs_index_t {
    bool     is_simple;
    uint32_t index;
} pbs_index_t;

typedef struct _acl_entry_db_t {
    sx_acl_rule_offset_t offset;
    uint8_t              num_rules;
    uint16_t             priority;
    uint32_t             counter_id;
    pbs_index_t          pbs_index;
    uint32_t             next;
    uint32_t             prev;
    bool                 is_used;
} acl_entry_db_t;

typedef struct _acl_setting_tbl_t {
    bool       bg_stop;
    bool       initialized;
    cl_plock_t lock;
#ifndef _WIN32
    pthread_cond_t background_thread_init_cond;
#endif
    bool background_thread_start_flag;
#ifndef _WIN32
    pthread_cond_t rpc_thread_init_cond;
#endif
    bool rpc_thread_start_flag;
#ifndef _WIN32
    pthread_mutex_t cond_mutex;
#endif
} acl_setting_tbl_t;

typedef uint64_t acl_pbs_map_key_t;
typedef struct _acl_pbs_map_db_t {
    acl_pbs_map_key_t key;
    sx_acl_pbs_id_t   pbs_id;
    uint32_t          ref_counter;
} acl_pbs_map_db_t;

typedef struct _mlnx_acl_db_t {
    uint8_t           *db_base_ptr;
    acl_group_db_t    *acl_ingress_group_db;
    acl_group_db_t    *acl_egress_group_db;
    acl_table_db_t    *acl_table_db;
    acl_counter_db_t  *acl_counter_db;
    acl_entry_db_t    *acl_entry_db;
    acl_setting_tbl_t *acl_settings_tbl;
    acl_pbs_map_db_t  *acl_pbs_map_db;
    acl_pbs_map_db_t  *acl_port_comb_pbs_map_db;
} mlnx_acl_db_t;

extern mlnx_acl_db_t *g_sai_acl_db_ptr;
extern uint32_t       g_sai_acl_db_pbs_map_size;

typedef struct _mlnx_policer_to_trap_group_bind_params {
    sai_attribute_value_t attr_prio_value;
} mlnx_policer_to_trap_group_bind_params;
typedef struct _mlnx_hash_obj_t {
    sai_object_id_t hash_id;
    uint64_t        field_mask;
} mlnx_hash_obj_t;
typedef enum _mlnx_switch_hash_object_id {
    SAI_HASH_ECMP_ID = 0,
    SAI_HASH_ECMP_IP4_ID,
    SAI_HASH_ECMP_IPINIP_ID,
    SAI_HASH_LAG_ID,
    SAI_HASH_LAG_IP4_ID,
    SAI_HASH_LAG_IPINIP_ID,
    SAI_HASH_MAX_OBJ_ID
} mlnx_switch_usage_hash_object_id_t;

sai_status_t mlnx_hash_ecmp_attr_apply(const sai_attr_id_t attr_id, const sai_attribute_value_t* value);

sai_status_t mlnx_hash_object_apply(const sai_object_id_t                    hash_id,
                                    const mlnx_switch_usage_hash_object_id_t hash_oper_id);

sai_status_t mlnx_hash_ecmp_cfg_apply_on_port(sx_port_log_id_t port_log_id);

sai_status_t mlnx_hash_get_oper_ecmp_fields(sx_router_ecmp_port_hash_params_t  *port_hash_param,
                                            sx_router_ecmp_hash_field_enable_t *hash_enable_list,
                                            uint32_t                           *enable_count,
                                            sx_router_ecmp_hash_field_t        *hash_field_list,
                                            uint32_t                           *field_count);

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
sai_status_t mlnx_sai_unbind_policer(_In_ sai_object_id_t           sai_object,
                                     _In_ sai_object_id_t           sai_policer,
                                     _In_ mlnx_policer_bind_params* bind_params);
sai_status_t mlnx_sai_get_or_create_regular_sx_policer_for_bind(_In_ sai_object_id_t   sai_policer,
                                                                _In_ bool              is_host_if_policer,
                                                                _Out_ sx_policer_id_t* sx_policer_id);

void log_sx_policer_attributes(_In_ sx_policer_id_t sx_policer, _In_ sx_policer_attributes_t* sx_attribs);

sai_status_t mlnx_sai_buffer_log_set(_In_ sx_verbosity_level_t level);

#define SAI_LAG_NUM_MAX 64

#define MLNX_INVALID_SAMPLEPACKET_SESSION 0
#define MLNX_SAMPLEPACKET_SESSION_MIN     1
#define MLNX_SAMPLEPACKET_SESSION_MAX     256

typedef struct _mlnx_samplepacket_t {
    bool                    in_use;
    uint32_t                sai_sample_rate;
    sai_samplepacket_type_t sai_type;
    sai_samplepacket_mode_t sai_mode;
} mlnx_samplepacket_t;

#define MLNX_TUNNELTABLE_SIZE 256

typedef struct _mlnx_tunneltable_t {
    bool                        in_use;
    sx_tunnel_decap_entry_key_t sdk_tunnel_decap_key;
} mlnx_tunneltable_t;

typedef struct _tunnel_db_entry_t {
    bool           is_used;
    sx_tunnel_id_t sx_tunnel_id;
} tunnel_db_entry_t;

/* TODO:  What is sufficient size for tunnel_db */
#define MAX_TUNNEL_DB_SIZE 100

#define MLNX_TUNNEL_MAP_LIST_MAX          50
#define MLNX_TUNNEL_MAP_DEFAULT_ECN_ENCAP 0
#define MLNX_TUNNEL_MAP_DEFAULT_ECN_DECAP 1
#define MLNX_TUNNEL_MAP_MIN               2
#define MLNX_TUNNEL_MAP_MAX               50

typedef struct _tunnel_map_t {
    bool                  in_use;
    sai_tunnel_map_type_t tunnel_map_type;
    uint32_t              tunnel_map_list_count;
    sai_tunnel_map_t      tunnel_map_list[MLNX_TUNNEL_MAP_LIST_MAX];
} mlnx_tunnel_map_t;

typedef struct sai_db {
    cl_plock_t         p_lock;
    sx_mac_addr_t      base_mac_addr;
    char               dev_mac[18];
    uint32_t           ports_number;
    uint32_t           ports_configured;
    mlnx_port_config_t ports_db[MAX_PORTS * 2];
    sx_fd_t            fd_db[MAX_FDS];
    sai_object_id_t    default_trap_group;
    sai_object_id_t    default_vrid;
    sx_user_channel_t  callback_channel;
    bool               trap_group_valid[MAX_TRAP_GROUPS];
    /* index is according to index in mlnx_traps_info */
    mlnx_trap_t             traps_db[SXD_TRAP_ID_ACL_MAX];
    mlnx_qos_map_t          qos_maps_db[MAX_QOS_MAPS];
    uint32_t                switch_qos_maps[MLNX_QOS_MAP_TYPES_MAX];
    uint8_t                 switch_default_tc;
    mlnx_policer_db_entry_t policers_db[MAX_POLICERS];
    mlnx_hash_obj_t         hash_list[SAI_HASH_MAX_OBJ_COUNT];
    sai_object_id_t         oper_hash_list[SAI_HASH_MAX_OBJ_ID];
    mlnx_samplepacket_t     mlnx_samplepacket_session[MLNX_SAMPLEPACKET_SESSION_MAX];
    mlnx_tunneltable_t      mlnx_tunneltable[MLNX_TUNNELTABLE_SIZE];
    tunnel_db_entry_t       tunnel_db[MAX_TUNNEL_DB_SIZE];
    mlnx_tunnel_map_t       mlnx_tunnel_map[MLNX_TUNNEL_MAP_MAX];
} sai_db_t;

extern sai_db_t *g_sai_db_ptr;

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

#define BUFFER_DB_POOL_FLAG_ARRAY_SIZE 1
#define BUFFER_DB_POOL_E_CPU_POOL_IND  0

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
     *  Array of size BUFFER_DB_POOL_FLAG_ARRAY_SIZE + 1
     *  if pool_allocation[BUFFER_DB_POOL_E_CPU_POOL_IND] == true - then the e_cpu pool has been created.
     *  if pool_allocation[BUFFER_DB_POOL_E_CPU_POOL_IND] == false - then the e_cpu pool not created.
     *  pool_allocation[BUFFER_DB_POOL_E_CPU_POOL_IND + 1] - contains the size of e_cpu pool#7 on SDK startup.
     *  When user deletes this pool, its size is set back to the original size SDK startup size.
     *
     *  pool_allocation[BUFFER_DB_POOL_FLAG_ARRAY_SIZE]
     *  When SAI starts up it will load current buffer configuration into SAI buffer infrastructure,
     *  so user would be able to use it. However on the first user request to create a pool all
     *  existring buffer configuration will be deleted.
     *  This item will be set initially to 0, and after first create pool request will be set to true.
     *  Once set to true, it cannot be modified.
     */
    bool     *pool_allocation;
    uint32_t *e_cpu_pool_startup_size;
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
sai_status_t mlnx_sched_group_port_init(mlnx_port_config_t *port);

sai_status_t mlnx_queue_cfg_lookup(sx_port_log_id_t log_port_id, uint32_t queue_idx, mlnx_qos_queue_config_t **cfg);

/* DB read lock is needed */
sai_status_t mlnx_port_by_log_id(sx_port_log_id_t log_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_port_by_obj_id(sai_object_id_t obj_id, mlnx_port_config_t **port);
/* DB read lock is needed */
sai_status_t mlnx_port_idx_by_log_id(sx_port_log_id_t log_port_id, uint32_t *index);
/* DB read lock is needed */
sai_status_t mlnx_port_idx_by_obj_id(sai_object_id_t obj_id, uint32_t *index);

/* DB read lock is needed */
sai_status_t mlnx_port_config_init(mlnx_port_config_t *port);

bool mlnx_port_is_net(mlnx_port_config_t *port);
bool mlnx_port_is_virt(mlnx_port_config_t *port);
bool mlnx_port_is_lag(mlnx_port_config_t *port);
bool mlnx_port_is_lag_member(mlnx_port_config_t *port);
char * mlnx_port_type_str(mlnx_port_config_t *port);

/* DB read lock is needed */
sai_status_t __mlnx_wred_apply_to_port(mlnx_port_config_t *port, sai_object_id_t wred_oid);
sai_status_t __mlnx_wred_apply_to_queue_idx(mlnx_port_config_t *port, uint8_t qi, sai_object_id_t wred_oid);

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

/*
 *  SAI host if type
 *  Values must not be bigger than 255
 */
typedef enum _sai_host_object_type_t {
    SAI_HOSTIF_OBJECT_TYPE_VLAN,
    SAI_HOSTIF_OBJECT_TYPE_ROUTER_PORT,
    SAI_HOSTIF_OBJECT_TYPE_L2_PORT,
    SAI_HOSTIF_OBJECT_TYPE_FD
} sai_host_object_type_t;

#define KV_DEVICE_MAC_ADDRESS "DEVICE_MAC_ADDRESS"
#define KV_INITIAL_FAN_SPEED  "INITIAL_FAN_SPEED"
#define MIN_FAN_PERCENT       30
#define MAX_FAN_PERCENT       100

#define MLNX_MIRROR_VLAN_TPID           0x8100
#define MLNX_GRE_PROTOCOL_TYPE          0x6558
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

sai_status_t mlnx_translate_sdk_tunnel_id_to_sai_tunnel_id(_In_ const sx_tunnel_id_t sdk_tunnel_id,
                                                           _Out_ sai_object_id_t    *sai_tunnel_id);

#endif /* __MLNXSAI_H_ */
