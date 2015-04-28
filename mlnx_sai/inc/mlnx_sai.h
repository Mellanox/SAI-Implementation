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
#include <sx/sdk/sx_api_flow_counter.h>
#include <sx/sdk/sx_api_span.h>
#include <resource_manager/resource_manager.h>
#include <sai.h>

extern sx_api_handle_t gh_sdk;
extern service_method_table_t g_services;
extern rm_resources_t g_resource_limits;

sai_status_t sdk_to_sai(sx_status_t status);
extern const sai_route_api_t route_api;
extern const sai_virtual_router_api_t router_api;
extern const sai_switch_api_t switch_api;
extern const sai_port_api_t port_api;
extern const sai_fdb_api_t fdb_api;
extern const sai_neighbor_api_t neighbor_api;
extern const sai_next_hop_api_t next_hop_api;
extern const sai_next_hop_group_api_t next_hop_group_api;
extern const sai_router_interface_api_t router_interface_api;
extern const sai_vlan_api_t vlan_api;
extern const sai_host_interface_api_t host_interface_api;

#define DEFAULT_ETH_SWID 0
#define DEFAULT_VRID 0
#define DEFAULT_RIF_MTU 1500
#define DEFAULT_MULTICAST_TTL_THRESHOLD 1
#define FIRST_PORT (0x10000 | (1 << 8))
#define PORT_MAC_BITMASK (~0x3F)
#define SWITCH_PORT_NUM 36
#define SWITCH_MAX_VR 1
#define PORT_SPEED_56 56000
#define PORT_SPEED_40 40000
#define PORT_SPEED_20 20000
#define PORT_SPEED_10 10000
#define PORT_SPEED_1  1000
#define CPU_PORT 0
#define ECMP_MAX_PATHS 64

/*
*  SAI operation type
*  Values must start with 0 base and be without gaps
*/
typedef enum sai_operation_t
{
    SAI_OPERATION_CREATE,
    SAI_OPERATION_REMOVE,
    SAI_OPERATION_SET,
    SAI_OPERATION_GET,
    SAI_OPERATION_MAX
} sai_operation_t;

/*
*  Attribute value types
*/
typedef enum _sai_attribute_value_type_t
{
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
    SAI_ATTR_VAL_TYPE_PORTLIST,
    SAI_ATTR_VAL_TYPE_NHLIST,
    SAI_ATTR_VAL_TYPE_ACLFIELD,
    SAI_ATTR_VAL_TYPE_ACLDATA,
} sai_attribute_value_type_t;

typedef struct _sai_attribute_entry_t {
    sai_attr_id_t id;
    bool mandatory_on_create;
    bool valid_for_create;
    bool valid_for_set;
    const char *attrib_name;
    sai_attribute_value_type_t type;
} sai_attribute_entry_t;

typedef struct _sai_qos_key_t
{
    sai_port_id_t port_id;
    sai_cos_t cos_value;
} sai_qos_key_t;

typedef union {
    const sai_acl_entry_id_t acl_entry_id;
    const sai_fdb_entry_t* fdb_entry;
    const sai_neighbor_entry_t* neighbor_entry;
    const sai_next_hop_id_t next_hop_id;
    const sai_next_hop_group_id_t next_hop_group_id;
    const sai_port_id_t port_id;
    const sai_qos_key_t *qos_key;
    const sai_unicast_route_entry_t* unicast_route_entry;
    const sai_virtual_router_id_t vr_id;
    const sai_router_interface_id_t rif_id;
    const sai_vlan_id_t vlan_id;
    const sai_host_interface_id_t host_interface_id;
} sai_object_key_t;

typedef sai_status_t(*sai_attribute_set_fn)(
    _In_ const sai_object_key_t *key,
    _In_ const sai_attribute_value_t *value,
    void *arg
    );

typedef struct _mlnx_fdb_cache_t
{
    sx_port_id_t log_port;                  /**< Logical port */
    sx_fdb_uc_mac_entry_type_t entry_type;  /**< FDB Entry Type */
    sx_fdb_action_t action;
    bool fdb_cache_set;
} mlnx_fdb_cache_t;

typedef union {
    mlnx_fdb_cache_t fdb_cache;
} vendor_cache_t;

typedef sai_status_t(*sai_attribute_get_fn)(
    _In_ const sai_object_key_t *key,
    _Inout_ sai_attribute_value_t *value,
    _In_ uint32_t attr_index,
    _Inout_ vendor_cache_t *cache,
    void *arg
    );

typedef struct _sai_vendor_attribute_entry_t {
    sai_attr_id_t id;
    bool is_implemented[SAI_OPERATION_MAX];
    bool is_supported[SAI_OPERATION_MAX];
    sai_attribute_get_fn getter;
    void *getter_arg;
    sai_attribute_set_fn setter;
    void *setter_arg;
} sai_vendor_attribute_entry_t;

#define END_FUNCTIONALITY_ATTRIBS_ID 0xFFFFFFFF

sai_status_t check_attribs_metadata(_In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    _In_ const sai_attribute_entry_t *functionality_attr,
    _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
    _In_ sai_operation_t oper);

sai_status_t find_attrib_in_list(_In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    _In_ sai_attr_id_t attrib_id,
    _Out_ const sai_attribute_value_t **attr_value,
    _Out_ uint32_t *index);

sai_status_t sai_set_attribute(_In_ const sai_object_key_t *key,
    _In_ const char *key_str,
    _In_ const sai_attribute_entry_t *functionality_attr,
    _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
    _In_ const sai_attribute_t *attr);

sai_status_t sai_get_attributes(_In_ const sai_object_key_t *key,
    _In_ const char *key_str,
    _In_ const sai_attribute_entry_t *functionality_attr,
    _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list);

#define MAX_KEY_STR_LEN 100
#define MAX_VALUE_STR_LEN 100
#define MAX_LIST_VALUE_STR_LEN 1000

sai_status_t sai_value_to_str(_In_ sai_attribute_value_t value,
    _In_ sai_attribute_value_type_t type,
    _In_ uint32_t max_length,
    _Out_ char *value_str);
sai_status_t sai_attr_list_to_str(_In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    _In_ const sai_attribute_entry_t *functionality_attr,
    _In_ uint32_t max_length,
    _Out_ char *list_str);
sai_status_t sai_ipprefix_to_str(_In_ sai_ip_prefix_t value,
    _In_ uint32_t max_length,
    _Out_ char *value_str);
sai_status_t sai_ipaddr_to_str(_In_ sai_ip_address_t value,
    _In_ uint32_t max_length,
    _Out_ char *value_str,
    _Out_ int *chars_written);
sai_status_t sai_nexthops_to_str(_In_ uint32_t next_hop_count,
    _In_ const sai_next_hop_id_t* nexthops,
    _In_ uint32_t max_length,
    _Out_ char *str);
sai_status_t mlnx_translate_sai_router_action_to_sdk(sai_int32_t action, sx_router_action_t *router_action, uint32_t param_index);
sai_status_t mlnx_translate_sdk_router_action_to_sai(sx_router_action_t router_action,
    sai_int32_t *sai_action);

void db_init_next_hop_group();
sai_status_t db_get_next_hop_group(_In_ sai_next_hop_group_id_t next_hop_group_id,
    _Out_ sai_next_hop_list_t *next_hop_list);

#ifndef _WIN32
#define UNREFERENCED_PARAMETER(X)
#else
#define PRId64 "lld"
unsigned int if_nametoindex(const char *ifname);
char *if_indextoname(unsigned int ifindex, char *ifname);
#define IF_NAMESIZE 32
#endif

#endif // __MLNXSAI_H_
