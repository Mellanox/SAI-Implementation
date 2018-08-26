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
#include <saimetadata.h>
#include <saimetadatatypes.h>
#include <saimetadatautils.h>
#include "assert.h"
#include "inttypes.h"
#ifndef WIN32
#include <arpa/inet.h>
#else
#include <Ws2tcpip.h>
#endif

#undef  __MODULE__
#define __MODULE__ SAI_UTILS

#define MLNX_UTILS_BOOL_TO_STR(a) ((a) ? "true" : "false")

#define MLNX_SAI_UTILS_NULL_OBJECT_ALLOWED

/*
 * All the attributes have a long and short names.
 * Short names for ACL UDF attributes can be fetch via adding an offset (19) to the long name beggining
 * e.g. short name for SAI_ACL_TABLE_ATTR_(USER_DEFINED_FIELD_GROUP_0) is USER_DEFINED_FIELD_GROUP_0
 *
 * It will be removed after adding a proper metadata for these attributes
 */
#define MLNX_UDF_ACL_ATTR_SHORT_NAME_OFFSET (19)

static const sai_u32_list_t        mlnx_sai_not_mandatory_attrs[SAI_OBJECT_TYPE_MAX] = {
    [SAI_OBJECT_TYPE_QOS_MAP] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST}
    },

    [SAI_OBJECT_TYPE_SCHEDULER_GROUP] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE}
    },

    [SAI_OBJECT_TYPE_TUNNEL] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_TUNNEL_ATTR_ENCAP_TTL_VAL}
    },

    [SAI_OBJECT_TYPE_NEXT_HOP] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID}
    },
};
static const sai_u32_list_t        mlnx_sai_attrs_valid_for_set[SAI_OBJECT_TYPE_MAX] = {
    [SAI_OBJECT_TYPE_TUNNEL] =
    {.count = 1, .list = (sai_attr_id_t[1]) {SAI_TUNNEL_ATTR_DECAP_MAPPERS}
    },
};
static const sai_u32_list_t        mlnx_sai_attrs_with_empty_list[SAI_OBJECT_TYPE_MAX] = {
    [SAI_OBJECT_TYPE_PORT] = {.count = 3, .list = (sai_attr_id_t[3])
                              {SAI_PORT_ATTR_INGRESS_MIRROR_SESSION, SAI_PORT_ATTR_EGRESS_MIRROR_SESSION,
                               SAI_PORT_ATTR_EGRESS_BLOCK_PORT_LIST}
    },

    [SAI_OBJECT_TYPE_ACL_ENTRY] = {.count = 3, .list = (sai_attr_id_t[3])
                                   { SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS, SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
                                     SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE}
    },
    [SAI_OBJECT_TYPE_HASH] = {.count = 1, .list = (sai_attr_id_t[1]) {SAI_HASH_ATTR_UDF_GROUP_LIST}
    },
};
static const sai_u32_list_t        mlnx_sai_hostif_table_valid_obj_types[] = {
    [SAI_HOSTIF_TABLE_ENTRY_ATTR_OBJ_ID] =
    {.count = 1, .list = (uint32_t[1]) {SAI_OBJECT_TYPE_VLAN}
    },
};
static const sai_u32_list_t        mlnx_sai_tunnel_valid_obj_types[] = {
    [SAI_TUNNEL_ATTR_OVERLAY_INTERFACE] =
    {.count = 1, .list = (uint32_t[1]) {SAI_OBJECT_TYPE_PORT}
    },
};
static const sai_u32_list_t        mlnx_sai_valid_obj_types[SAI_OBJECT_TYPE_MAX] = {
    [SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY] =
    {.count = ARRAY_SIZE(mlnx_sai_hostif_table_valid_obj_types), .list = (void*)mlnx_sai_hostif_table_valid_obj_types},
    [SAI_OBJECT_TYPE_TUNNEL] =
    {.count = ARRAY_SIZE(mlnx_sai_tunnel_valid_obj_types), .list = (void*)mlnx_sai_tunnel_valid_obj_types},
};
static sai_attr_metadata_t         mlnx_udf_acl_table_attr_metadata_list[MLNX_UDF_ACL_ATTR_COUNT];
static sai_attr_metadata_t         mlnx_udf_acl_entry_attr_metadata_list[MLNX_UDF_ACL_ATTR_COUNT];
static const sai_attr_metadata_t   mlnx_udf_acl_entry_attr_metadata = {
    .objecttype               = SAI_OBJECT_TYPE_ACL_ENTRY,
    .attrid                   = SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN,
    .attridname               = "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN",
    .attrvaluetype            = SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST,
    .flags                    = (sai_attr_flags_t)(SAI_ATTR_FLAGS_CREATE_AND_SET),
    .allowedobjecttypes       = NULL,
    .allowedobjecttypeslength = 0,
    .allowrepetitiononlist    = false,
    .allowmixedobjecttypes    = false,
    .allowemptylist           = false,
    .allownullobjectid        = false,
    .defaultvaluetype         = SAI_DEFAULT_VALUE_TYPE_EMPTY_LIST,
    .defaultvalue             = NULL,
    .defaultvalueobjecttype   = SAI_OBJECT_TYPE_NULL,
    .defaultvalueattrid       = SAI_INVALID_ATTRIBUTE_ID,
    .isenum                   = false,
    .isenumlist               = false,
    .enummetadata             = NULL,
    .conditiontype            = SAI_ATTR_CONDITION_TYPE_NONE,
    .conditions               = NULL,
    .conditionslength         = 0,
    .isconditional            = (0 != 0),
    .validonlytype            = SAI_ATTR_CONDITION_TYPE_NONE,
    .validonly                = NULL,
    .validonlylength          = 0,
    .getsave                  = false,
    .isvlan                   = false,
    .isaclfield               = false,
    .isaclaction              = false,
};
static const sai_object_type_t     mlnx_udf_acl_table_attr_allowed_objects[] = {
    SAI_OBJECT_TYPE_UDF_GROUP,
};
static const sai_attribute_value_t mlnx_udf_acl_table_attr_default_value = { .oid = SAI_NULL_OBJECT_ID };
static const sai_attr_metadata_t   mlnx_udf_acl_table_attr_metadata = {
    .objecttype               = SAI_OBJECT_TYPE_ACL_TABLE,
    .attrid                   = SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN,
    .attridname               = "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN",
    .attrvaluetype            = SAI_ATTR_VALUE_TYPE_OBJECT_ID,
    .flags                    = (sai_attr_flags_t)(SAI_ATTR_FLAGS_CREATE_ONLY),
    .allowedobjecttypes       = mlnx_udf_acl_table_attr_allowed_objects,
    .allowedobjecttypeslength = 1,
    .allowrepetitiononlist    = false,
    .allowmixedobjecttypes    = false,
    .allowemptylist           = false,
    .allownullobjectid        = true,
    .defaultvaluetype         = SAI_DEFAULT_VALUE_TYPE_CONST,
    .defaultvalue             = &mlnx_udf_acl_table_attr_default_value,
    .defaultvalueobjecttype   = SAI_OBJECT_TYPE_NULL,
    .defaultvalueattrid       = SAI_INVALID_ATTRIBUTE_ID,
    .isenum                   = false,
    .isenumlist               = false,
    .enummetadata             = NULL,
    .conditiontype            = SAI_ATTR_CONDITION_TYPE_NONE,
    .conditions               = NULL,
    .conditionslength         = 0,
    .isconditional            = (0 != 0),
    .validonlytype            = SAI_ATTR_CONDITION_TYPE_NONE,
    .validonly                = NULL,
    .validonlylength          = 0,
    .getsave                  = false,
    .isvlan                   = false,
    .isaclfield               = false,
    .isaclaction              = false,
};
static const char                * mlnx_udf_acl_table_attr_names[] = {
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_0",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_1",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_2",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_3",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_4",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_5",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_6",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_7",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_8",
    "SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_9",
};
static const char                * mlnx_udf_acl_entry_attr_names[] = {
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_0",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_1",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_2",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_3",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_4",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_5",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_6",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_7",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_8",
    "SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_9",
};

/* Data needed for sai_query_attribute_capability and sai_query_attribute_enum_values_capability APIs */
extern const mlnx_obj_type_attrs_info_t mlnx_port_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_lag_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_router_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_next_hop_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_rif_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_table_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_counter_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_range_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_table_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_acl_table_group_mem_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_mirror_session_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_samplepacket_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_stp_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_trap_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_policer_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_wred_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_qos_map_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_queue_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_scheduler_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_sched_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_buffer_pool_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_buffer_profile_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_ingress_pg_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_lag_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hash_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_udf_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_udf_match_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_udf_group_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_fdb_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_switch_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_trap_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_table_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_neighbor_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_route_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_vlan_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_vlan_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_packet_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_map_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_term_table_entry_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_fdb_flush_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_nh_group_member_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_stp_port_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_hostif_user_defined_trap_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_bridge_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_bridge_port_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_tunnel_map_entry_obj_type_info;
extern const mlnx_obj_type_attrs_info_t mlnx_port_pool_obj_type_info;

static const mlnx_obj_type_attrs_info_t* mlnx_obj_types_info[] = {
    [SAI_OBJECT_TYPE_PORT] = &mlnx_port_obj_type_info,
    [SAI_OBJECT_TYPE_LAG] = &mlnx_lag_obj_type_info,
    [SAI_OBJECT_TYPE_VIRTUAL_ROUTER] = &mlnx_router_obj_type_info,
    [SAI_OBJECT_TYPE_NEXT_HOP] = &mlnx_next_hop_obj_type_info,
    [SAI_OBJECT_TYPE_ROUTER_INTERFACE] = &mlnx_rif_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_TABLE] = &mlnx_acl_table_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_ENTRY] = &mlnx_acl_entry_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_COUNTER] = &mlnx_acl_counter_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_RANGE] = &mlnx_acl_range_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_TABLE_GROUP] = &mlnx_acl_table_group_obj_type_info,
    [SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER] = &mlnx_acl_table_group_mem_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF] = &mlnx_hostif_obj_type_info,
    [SAI_OBJECT_TYPE_MIRROR_SESSION] = &mlnx_mirror_session_obj_type_info,
    [SAI_OBJECT_TYPE_SAMPLEPACKET] = &mlnx_samplepacket_obj_type_info,
    [SAI_OBJECT_TYPE_STP] = &mlnx_stp_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP] = &mlnx_hostif_trap_group_obj_type_info,
    [SAI_OBJECT_TYPE_POLICER] = &mlnx_policer_obj_type_info,
    [SAI_OBJECT_TYPE_WRED] = &mlnx_wred_obj_type_info,
    [SAI_OBJECT_TYPE_QOS_MAP] = &mlnx_qos_map_obj_type_info,
    [SAI_OBJECT_TYPE_QUEUE] = &mlnx_queue_obj_type_info,
    [SAI_OBJECT_TYPE_SCHEDULER] = &mlnx_scheduler_obj_type_info,
    [SAI_OBJECT_TYPE_SCHEDULER_GROUP] = &mlnx_sched_group_obj_type_info,
    [SAI_OBJECT_TYPE_BUFFER_POOL] = &mlnx_buffer_pool_obj_type_info,
    [SAI_OBJECT_TYPE_BUFFER_PROFILE] = &mlnx_buffer_profile_obj_type_info,
    [SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP] = &mlnx_ingress_pg_obj_type_info,
    [SAI_OBJECT_TYPE_LAG_MEMBER] = &mlnx_lag_member_obj_type_info,
    [SAI_OBJECT_TYPE_HASH] = &mlnx_hash_obj_type_info,
    [SAI_OBJECT_TYPE_UDF] = &mlnx_udf_obj_type_info,
    [SAI_OBJECT_TYPE_UDF_MATCH] = &mlnx_udf_match_obj_type_info,
    [SAI_OBJECT_TYPE_UDF_GROUP] = &mlnx_udf_group_obj_type_info,
    [SAI_OBJECT_TYPE_FDB_ENTRY] = &mlnx_fdb_entry_obj_type_info,
    [SAI_OBJECT_TYPE_SWITCH] = &mlnx_switch_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_TRAP] = &mlnx_hostif_trap_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY] = &mlnx_hostif_table_entry_obj_type_info,
    [SAI_OBJECT_TYPE_NEIGHBOR_ENTRY] = &mlnx_neighbor_obj_type_info,
    [SAI_OBJECT_TYPE_ROUTE_ENTRY] = &mlnx_route_obj_type_info,
    [SAI_OBJECT_TYPE_VLAN] = &mlnx_vlan_obj_type_info,
    [SAI_OBJECT_TYPE_VLAN_MEMBER] = &mlnx_vlan_member_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_PACKET] = &mlnx_hostif_packet_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL_MAP] = &mlnx_tunnel_map_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL] = &mlnx_tunnel_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY] = &mlnx_tunnel_term_table_entry_type_info,
    [SAI_OBJECT_TYPE_FDB_FLUSH] = &mlnx_fdb_flush_obj_type_info,
    [SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER] = &mlnx_nh_group_member_obj_type_info,
    [SAI_OBJECT_TYPE_STP_PORT] = &mlnx_stp_port_obj_type_info,
    [SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP] = &mlnx_hostif_user_defined_trap_obj_type_info,
    [SAI_OBJECT_TYPE_BRIDGE] = &mlnx_bridge_obj_type_info,
    [SAI_OBJECT_TYPE_BRIDGE_PORT] = &mlnx_bridge_port_obj_type_info,
    [SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY] = &mlnx_tunnel_map_entry_obj_type_info,
    [SAI_OBJECT_TYPE_PORT_POOL] = &mlnx_port_pool_obj_type_info,
};
static const uint32_t mlnx_obj_types_info_arr_size = ARRAY_SIZE(mlnx_obj_types_info);

static sai_status_t sai_vendor_attr_index_find(_In_ const sai_attr_id_t                 attr_id,
                                               _In_ const sai_vendor_attribute_entry_t *vendor_attr,
                                               _Out_ uint32_t                          *index);
static uint32_t sai_attr_capability_to_str(_In_ const sai_attr_capability_t *val,
                                           _In_ uint32_t                     max_length,
                                           _Out_ char                       *value_str);
static sai_status_t sai_value_to_str(_In_ sai_attribute_value_t value,
                                     _In_ sai_attr_value_type_t type,
                                     _In_ uint32_t              max_length,
                                     _Out_ char                *value_str);
static sai_status_t sai_attr_metadata_to_str(_In_ const sai_attr_metadata_t   *meta_data,
                                             _In_ const sai_attribute_value_t *value,
                                             _In_ uint32_t                     max_length,
                                             _Out_ char                       *value_str);
static sai_status_t sai_attr_meta_enum_value_to_str(_In_ const sai_attr_metadata_t *meta_data,
                                                    _In_ sai_int32_t                value,
                                                    _In_ uint32_t                   max_length,
                                                    _Out_ char                     *value_str);
static sai_status_t sai_attr_meta_enum_to_str(_In_ const sai_attr_metadata_t   *meta_data,
                                              _In_ const sai_attribute_value_t *value,
                                              _In_ uint32_t                     max_length,
                                              _Out_ char                       *value_str);
static sai_status_t sai_attr_meta_enumlist_s32_to_str(_In_ const sai_attr_metadata_t *meta_data,
                                                       _In_ const sai_s32_list_t     *values,
                                                       _In_ uint32_t                  max_length,
                                                       _Out_ char                    *list_str);
static sai_status_t sai_object_type_attr_count_meta_get(_In_ const sai_object_type_t object_type,
                                                        _Out_ uint32_t              *attr_count);
static sai_status_t sai_attribute_short_name_fetch(_In_ sai_object_type_t object_type,
                                                   _In_ sai_attr_id_t     attr_id,
                                                   _Out_ const char     **attr_short_name);
static sai_status_t sai_attribute_value_allowed_objects_str_fetch(_In_ const sai_attr_metadata_t *meta_data,
                                                                  _In_ uint32_t                   max_length,
                                                                  _In_ char                      *list_str);
static sai_status_t sai_attribute_allowed_objects_validate(_In_ const sai_attr_metadata_t   *meta_data,
                                                           _In_ const sai_attribute_value_t *value,
                                                           _In_ uint32_t                     attr_index);
static sai_status_t sai_attribute_value_list_elem_compare(_In_reads_z_(list_count * elem_size) const void *list,
                                                          _In_ uint32_t                                    list_count,
                                                          _In_ sai_attr_value_type_t                       value_type,
                                                          _In_ uint32_t                                    index_a,
                                                          _In_ uint32_t                                    index_b,
                                                          _In_ size_t                                      elem_size,
                                                          _Out_ bool                                      *is_equeal);
static sai_status_t sai_attribute_value_list_is_unique(_In_ const sai_attr_metadata_t                  *meta_data,
                                                       _In_ uint32_t                                    attr_index,
                                                       _In_reads_z_(list_count * elem_size) const void *list_ptr,
                                                       _In_ uint32_t                                    list_elems_count,
                                                       _In_ sai_attr_value_type_t                       value_type,
                                                       _In_ size_t                                      elem_size);
static sai_status_t sai_attribute_value_list_type_validate(_In_ const sai_attr_metadata_t   *meta_data,
                                                           _In_ const sai_attribute_value_t *value,
                                                           _In_ sai_common_api_t             oper,
                                                           _In_ uint32_t                     attr_index);
static sai_status_t sai_attribute_is_obj_type_allowed(_In_ const sai_attr_metadata_t *attr_metadata,
                                                      _In_ sai_object_type_t          object_type,
                                                      _Out_ bool                     *is_object_type_allowed);
static sai_status_t sai_attribute_is_not_mandatory(_In_ const sai_attr_metadata_t *attr_metadata,
                                                   _Out_ bool                     *is_not_mandatory);
static sai_status_t sai_attribute_is_valid_for_set(_In_ const sai_attr_metadata_t *attr_metadata,
                                                   _Out_ bool                     *is_valid);
static sai_status_t sai_attribute_is_empty_list_allowed(_In_ const sai_attr_metadata_t *attr_metadata,
                                                        _Out_ bool                     *is_allowed);
static sai_status_t sai_attrlist_mandatory_attrs_check(
    _In_reads_z_(attr_count_meta) const bool       *attr_present_meta,
    _In_ uint32_t                                   attr_count_meta,
    _In_reads_z_(attr_count) const sai_attribute_t *attr_list,
    _In_ uint32_t                                   attr_count,
    _In_ sai_object_type_t                          object_type);
static sai_status_t sai_attribute_values_compare(_In_ const sai_attribute_value_t *v1,
                                                 _In_ const sai_attribute_value_t *v2,
                                                 _In_ const sai_attr_metadata_t   *attr_metadata,
                                                 _Out_ bool                       *is_equeal);
static sai_status_t sai_attr_list_check_condition(_In_ const sai_attr_condition_t *condition,
                                                  _In_ sai_object_type_t           object_type,
                                                  _In_ const sai_attribute_t      *attr_list,
                                                  _In_ uint32_t                    attr_count,
                                                  _Out_ bool                      *condition_value);
static sai_status_t sai_attribute_conditions_check(_In_ sai_attr_condition_type_t                 condition_type,
                                                   _In_ const sai_attr_condition_t* const * const conditions,
                                                   _In_ size_t                                    conditionslength,
                                                   _In_ sai_object_type_t                         object_type,
                                                   _In_ const sai_attribute_t                    *attr_list,
                                                   _In_ uint32_t                                  attr_count,
                                                   _Out_ bool                                    *conditions_valid);
static sai_status_t sai_attr_metadata_conditions_print(_In_ sai_attr_condition_type_t                 condition_type,
                                                       _In_ const sai_attr_condition_t* const * const conditions,
                                                       _In_ size_t                                    conditionslength,
                                                       _In_ sai_object_type_t                         object_type,
                                                       _In_ size_t                                    max_length,
                                                       _Out_writes_(max_length) char                 *str);
static sai_status_t sai_attribute_valid_condition_check(_In_ const sai_attr_metadata_t *attr_metadata,
                                                        _In_ uint32_t                   attr_count,
                                                        _In_ const sai_attribute_t     *attr_list);
static bool sai_attribute_is_acl_field_or_action(_In_ const sai_attr_metadata_t *meta_data);
static bool sai_objet_type_is_acl_table_or_entry(_In_ sai_object_type_t object_type);
static bool sai_attr_is_acl_udf(_In_ sai_object_type_t object_type, _In_ sai_attr_id_t attr_id);
static const sai_attr_metadata_t* mlnx_sai_udf_attr_metadata_get(_In_ sai_object_type_t object_type,
                                                                 _In_ sai_attr_id_t     attr_id);
static const sai_attr_metadata_t* mlnx_sai_attr_metadata_get_impl(_In_ sai_object_type_t object_type,
                                                                  _In_ sai_attr_id_t     attr_id);
static sai_status_t mlnx_sai_udf_attr_short_name_fetch(_In_ sai_object_type_t object_type,
                                                       _In_ sai_attr_id_t     attr_id,
                                                       _Out_ const char     **attr_short_name);
static sai_status_t sai_qos_map_to_str_oid(_In_ sai_object_id_t       qos_map_id,
                                           _In_ sai_attribute_value_t value,
                                           _In_ uint32_t              max_length,
                                           _Out_ char                *value_str);
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t sdk_to_sai(sx_status_t status)
{
    switch (status) {
    case SX_STATUS_SUCCESS:
        return SAI_STATUS_SUCCESS;

    case SX_STATUS_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_SDK_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_INVALID_HANDLE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_COMM_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_NO_RESOURCES:
        return SAI_STATUS_INSUFFICIENT_RESOURCES;

    case SX_STATUS_NO_MEMORY:
        return SAI_STATUS_NO_MEMORY;

    case SX_STATUS_MEMORY_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_INCOMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_CMD_UNPERMITTED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARAM_NULL:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_ERROR:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_EXCEEDS_RANGE:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_MESSAGE_SIZE_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_MESSAGE_SIZE_EXCEEDS_LIMIT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_DB_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_DB_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_DB_NOT_EMPTY:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_END_OF_DB:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_NOT_FOUND:
        return SAI_STATUS_ITEM_NOT_FOUND;

    case SX_STATUS_ENTRY_ALREADY_EXISTS:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_ENTRY_NOT_BOUND:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_ALREADY_BOUND:
        return SAI_STATUS_OBJECT_IN_USE;

    case SX_STATUS_WRONG_POLICER_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_UNEXPECTED_EVENT_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_TRAP_ID_NOT_CONFIGURED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_INT_COMM_CLOSE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_RESOURCE_IN_USE:
        return SAI_STATUS_OBJECT_IN_USE;

    case SX_STATUS_EVENT_TRAP_ALREADY_ASSOCIATED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_TIMEOUT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_MODULE_UNINITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_SX_UTILS_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARTIALLY_COMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_SXD_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    default:
        SX_LOG_NTC("Unexpected status code %d, mapping to failure\n", status);
        return SAI_STATUS_FAILURE;
    }
}

static const mlnx_obj_type_attrs_info_t* mlnx_obj_type_attr_info_get(_In_ sai_object_type_t object_type)
{
    if (mlnx_obj_types_info_arr_size <= (uint32_t)object_type) {
        return NULL;
    }

    return mlnx_obj_types_info[object_type];
}

static bool mlnx_query_attr_api_unsupported_udf_check(_In_ sai_object_type_t object_type,
                                                     _In_ sai_attr_id_t     attr_id)
{
    return sai_attr_is_acl_udf(object_type, attr_id) && mlnx_udf_acl_attribute_id_is_not_supported(attr_id);
}

static sai_status_t mlnx_query_attr_api_get_metadata(_In_ sai_object_type_t                   object_type,
                                                     _In_ sai_attr_id_t                       attr_id,
                                                     _Out_ const sai_attr_metadata_t        **attr_metadata,
                                                     _Out_ const mlnx_obj_type_attrs_info_t **obj_type_attr_info,
                                                     _Out_ uint32_t                          *vendor_attr_idx,
                                                     _Out_ const char                       **obj_type_str,
                                                     _Out_ const char                       **attr_id_str,
                                                     _Out_ bool                              *is_implemented)
{
    sai_status_t                        status;
    const sai_object_type_info_t       *obj_type_info;
    const sai_vendor_attribute_entry_t *vendor_attr_entry;
    uint32_t                            api_idx;

    obj_type_info = sai_metadata_get_object_type_info(object_type);
    if (!obj_type_info) {
        SX_LOG_ERR("Invalid object type - %d\n", object_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *obj_type_str = obj_type_info->objecttypename;

    if (mlnx_query_attr_api_unsupported_udf_check(object_type, attr_id)) {
        SX_LOG_ERR("UDF attribute index %d is out of supported range [%d, %d]\n", attr_id, 0, MLNX_UDF_ACL_ATTR_MAX_ID);
        *is_implemented = false;
        return SAI_STATUS_FAILURE;
    }

    *attr_metadata = mlnx_sai_attr_metadata_get_impl(object_type, attr_id);
    if (!(*attr_metadata)) {
        SX_LOG_ERR("Failed to fetch metadata - invalid attribute %d\n", attr_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *attr_id_str = (*attr_metadata)->attridname;

    *obj_type_attr_info = mlnx_obj_type_attr_info_get(object_type);
    if (!(*obj_type_attr_info)) {
        SX_LOG_NTC("Failed to find attr info - object API is not implemented\n");
        *is_implemented = false;
        return SAI_STATUS_SUCCESS;
    }

    status = sai_vendor_attr_index_find(attr_id, (*obj_type_attr_info)->vendor_data, vendor_attr_idx);
    if (SAI_ERR(status)) {
        *is_implemented = false;
        SX_LOG_NTC("Failed to find vendor data - attribute is not implemented\n");
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    vendor_attr_entry = &(*obj_type_attr_info)->vendor_data[*vendor_attr_idx];

    /* Check if at least one API is implemented */
    for (api_idx = SAI_COMMON_API_CREATE; api_idx < SAI_COMMON_API_MAX; api_idx++) {
        if (vendor_attr_entry->is_implemented[api_idx]) {
            *is_implemented = true;
            return SAI_STATUS_SUCCESS;
        }
    }

    *is_implemented = false;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_query_attribute_capability_impl(_In_ sai_object_id_t         switch_id,
                                                      _In_ sai_object_type_t       object_type,
                                                      _In_ sai_attr_id_t           attr_id,
                                                      _Out_ sai_attr_capability_t *attr_capability)
{
    sai_status_t                        status;
    const sai_attr_metadata_t          *attr_metadata;
    const mlnx_obj_type_attrs_info_t   *obj_type_attr_info;
    const sai_vendor_attribute_entry_t *vendor_attr_entry;
    const char                         *obj_type_str = "Invalid", *attr_id_str = "Invalid";
    char                                value_str[MAX_VALUE_STR_LEN] = {0};
    uint32_t                            vendor_attr_index;
    bool                                is_implemented = false;

    if (!attr_capability) {
        SX_LOG_ERR("NULL value attr_capability\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_query_attr_api_get_metadata(object_type, attr_id, &attr_metadata, &obj_type_attr_info, &vendor_attr_index,
                                              &obj_type_str, &attr_id_str, &is_implemented);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_NTC("Querying attribute capabilities for [%s:%s]\n", obj_type_str, attr_id_str);

    attr_capability->create_implemented = false;
    attr_capability->get_implemented    = false;
    attr_capability->set_implemented    = false;

    if (is_implemented) {
        vendor_attr_entry = &obj_type_attr_info->vendor_data[vendor_attr_index];

        attr_capability->create_implemented = vendor_attr_entry->is_implemented[SAI_COMMON_API_CREATE];
        attr_capability->get_implemented    = vendor_attr_entry->is_implemented[SAI_COMMON_API_GET];
        attr_capability->set_implemented    = vendor_attr_entry->is_implemented[SAI_COMMON_API_SET];
    }

    sai_attr_capability_to_str(attr_capability, MAX_VALUE_STR_LEN, value_str);
    SX_LOG_NTC("Got attribute capability [%s:%s]: %s\n", obj_type_str, attr_id_str, value_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_attr_enum_supported_values_get(_In_ const sai_attr_metadata_t              *attr_metadata,
                                                        _In_ const mlnx_obj_type_attrs_enums_info_t *enum_infos,
                                                        _Inout_ sai_s32_list_t                      *enum_values_capability)
{
    sai_attr_id_t                attr_id;
    const mlnx_attr_enum_info_t *enum_info;
    const sai_enum_metadata_t   *enum_metadata;
    const int32_t               *attrs;
    uint32_t                     attrs_count;

    assert(attr_metadata);
    assert(enum_infos);
    assert(enum_values_capability);
    assert(attr_metadata->isenum || attr_metadata->isenumlist);

    attr_id = attr_metadata->attrid;

    if (enum_infos->count <= attr_id) {
        SX_LOG_ERR("Attribute is not found in mlnx_obj_type_attrs_enum_infos_t\n");
        return SAI_STATUS_FAILURE;
    }

    enum_info = &enum_infos->info[attr_id];

    if (!ATTR_ENUM_INFO_IS_VALID(enum_info)) {
        SX_LOG_ERR("Attribute is not found in mlnx_obj_type_attrs_enum_infos_t\n");
        return SAI_STATUS_FAILURE;
    }

    if (enum_info->all) {
        enum_metadata = attr_metadata->enummetadata;
        if (!enum_metadata) {
            SX_LOG_ERR("sai_enum_metadata_t is NULL\n");
            return SAI_STATUS_FAILURE;
        }

        attrs       = enum_metadata->values;
        attrs_count = (uint32_t) enum_metadata->valuescount;
    } else {
        attrs       = enum_info->attrs;
        attrs_count = enum_info->count;
    }

    return mlnx_fill_s32list(attrs, attrs_count, enum_values_capability);
}

sai_status_t mlnx_sai_query_attribute_enum_values_capability_impl(_In_ sai_object_id_t    switch_id,
                                                                  _In_ sai_object_type_t  object_type,
                                                                  _In_ sai_attr_id_t      attr_id,
                                                                  _Inout_ sai_s32_list_t *enum_values_capability)
{
    sai_status_t                      status;
    const sai_attr_metadata_t        *attr_metadata;
    const mlnx_obj_type_attrs_info_t *obj_type_attr_info;
    const char                       *obj_type_str = "Invalid", *attr_id_str = "Invalid";
    uint32_t                          vendor_attr_index;
    bool                              is_implemented = false;
    char                              value_str[MAX_VALUE_STR_LEN] = {0};

    if (!enum_values_capability) {
        SX_LOG_ERR("NULL value enum_values_capability\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_query_attr_api_get_metadata(object_type, attr_id, &attr_metadata, &obj_type_attr_info, &vendor_attr_index,
                                              &obj_type_str, &attr_id_str, &is_implemented);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_NTC("Querying attribute enum capabilities for [%s:%s]\n", obj_type_str, attr_id_str);

    if ((!attr_metadata->isenum) && (!attr_metadata->isenumlist)) {
        SX_LOG_ERR("Attribute is not enum nor enum list\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!is_implemented) {
        enum_values_capability->count = 0;
    } else {
        status = mlnx_attr_enum_supported_values_get(attr_metadata, &obj_type_attr_info->enums_info, enum_values_capability);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return status;
        }
    }

    status = sai_attr_meta_enumlist_s32_to_str(attr_metadata, enum_values_capability, MAX_VALUE_STR_LEN, value_str);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_NTC("Got attribute enum capability [%s:%s]: %s\n", obj_type_str, attr_id_str, value_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;

}

static sai_status_t sai_object_type_attr_index_find(_In_ const sai_attr_id_t     attr_id,
                                                    _In_ const sai_object_type_t object_type,
                                                    _Out_ uint32_t              *index)
{
    const sai_attr_metadata_t* const *md;
    uint32_t                          ii;

    SX_LOG_ENTER();

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!sai_metadata_is_object_type_valid(object_type)) {
        SX_LOG_ERR("Invalid object type (%d)\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    md = sai_metadata_attr_by_object_type[object_type];
    if (NULL == md) {
        SX_LOG_ERR("Faield to fetch meta data array for object type - %d\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    for (ii = 0; md[ii] != NULL; ii++) {
        if (md[ii]->attrid == attr_id) {
            *index = ii;
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    /* Currnetly, metadata for ACL UDF attributes is not generated */
    if (sai_attr_is_acl_udf(object_type, attr_id)) {
        assert((attr_id - SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN) <= MLNX_UDF_ACL_ATTR_MAX_ID);
        *index = ii + (attr_id - SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN);
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

static sai_status_t sai_vendor_attr_index_find(_In_ const sai_attr_id_t                 attr_id,
                                               _In_ const sai_vendor_attribute_entry_t *vendor_attr,
                                               _Out_ uint32_t                          *index)
{
    uint32_t ii;

    SX_LOG_ENTER();

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == vendor_attr) {
        SX_LOG_ERR("NULL value vendor_attrs\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (ii = 0; END_FUNCTIONALITY_ATTRIBS_ID != vendor_attr[ii].id; ii++) {
        if (attr_id == vendor_attr[ii].id) {
            *index = ii;
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

sai_status_t check_port_type_attr(const sai_object_id_t *ports,
                                  uint32_t               count,
                                  attr_port_type_check_t check,
                                  sai_attr_id_t          attr_id,
                                  uint32_t               idx)
{
    mlnx_port_config_t *port;
    uint32_t            ii;

    if (!ports) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < count; ii++) {
        sai_status_t     status;
        sai_object_id_t  obj_id = ports[ii];
        sx_port_log_id_t log_id;

        if (obj_id == SAI_NULL_OBJECT_ID) {
            continue;
        }

        status = mlnx_object_to_log_port(obj_id, &log_id);
        if (SAI_ERR(status)) {
            return status;
        }
        if (log_id == CPU_PORT) {
            continue;
        }

        status = mlnx_port_by_obj_id(obj_id, &port);
        if (SAI_ERR(status)) {
            goto err;
        }

        if (!(check & ATTR_PORT_IS_LAG_ENABLED) && mlnx_port_is_lag(port)) {
            SX_LOG_ERR("LAG object id %" PRIx64 " is not supported by attr id %u\n",
                       obj_id, attr_id);

            goto err;
        }
        if (!(check & ATTR_PORT_IS_IN_LAG_ENABLED) && mlnx_port_is_lag_member(port)) {
            SX_LOG_ERR("Port LAG member object id %" PRIx64 " is not supported by attr id %u\n",
                       obj_id, attr_id);

            goto err;
        }
    }

    return SAI_STATUS_SUCCESS;

err:
    return SAI_STATUS_INVALID_PORT_NUMBER;
}

static sai_status_t sai_object_type_attr_count_meta_get(_In_ const sai_object_type_t object_type,
                                                        _Out_ uint32_t              *attr_count)
{
    const sai_attr_metadata_t* const *md;
    uint32_t                          ii;

    SX_LOG_ENTER();

    assert(attr_count);

    if (!sai_metadata_is_object_type_valid(object_type)) {
        SX_LOG_ERR("Invalid object type (%d)\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == attr_count) {
        SX_LOG_ERR("NULL value attr_count\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    md = sai_metadata_attr_by_object_type[object_type];
    if (NULL == md) {
        SX_LOG_ERR("Faield to fetch meta data array for object type - %d\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    for (ii = 0; md[ii] != NULL; ii++) {
    }

    *attr_count = ii;

    /* Currnetly, metadata for ACL UDF attributes is not generated */
    if (sai_objet_type_is_acl_table_or_entry(object_type)) {
        *attr_count += MLNX_UDF_ACL_ATTR_COUNT;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_short_name_fetch(_In_ sai_object_type_t object_type,
                                                   _In_ sai_attr_id_t     attr_id,
                                                   _Out_ const char     **attr_short_name)
{
    const sai_object_type_info_t *object_type_info;
    const sai_enum_metadata_t    *enum_meta_data;
    uint32_t                      enum_values_count, ii;
    bool                          is_name_found;

    SX_LOG_ENTER();

    assert(attr_short_name);

    if (!sai_metadata_is_object_type_valid(object_type)) {
        SX_LOG_ERR("Invalid object type (%d)\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (sai_attr_is_acl_udf(object_type, attr_id)) {
        return mlnx_sai_udf_attr_short_name_fetch(object_type, attr_id, attr_short_name);
    }

    object_type_info = sai_metadata_all_object_type_infos[object_type];
    if (NULL == object_type_info) {
        SX_LOG_ERR("Failed to fetch object type info for %d\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    enum_meta_data = object_type_info->enummetadata;
    if (NULL == enum_meta_data) {
        SX_LOG_ERR("Bad enum meta data for object type %s\n", object_type_info->objecttypename);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    enum_values_count = (uint32_t)enum_meta_data->valuescount;

    if ((attr_id < object_type_info->attridstart) || (object_type_info->attridend < attr_id)) {
        SX_LOG_ERR("Attribute id (%d) is out of range [%s, %s] for object type %s\n", attr_id,
                   enum_meta_data->valuesnames[0], enum_meta_data->valuesnames[enum_values_count - 1],
                   SAI_TYPE_STR(attr_id));
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    is_name_found = false;

    for (ii = 0; ii < enum_values_count; ii++) {
        if ((sai_attr_id_t)enum_meta_data->values[ii] == attr_id) {
            *attr_short_name = enum_meta_data->valuesshortnames[ii];
            is_name_found    = true;
            break;
        }
    }

    if (!is_name_found) {
        SX_LOG_ERR("Failed to find a short name for attribute %d - bad object info\n", attr_id);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_value_allowed_objects_str_fetch(_In_ const sai_attr_metadata_t *meta_data,
                                                                  _In_ uint32_t                   max_length,
                                                                  _In_ char                      *list_str)
{
    uint32_t ii, pos;

    assert(meta_data);
    assert(list_str);
    assert(0 < meta_data->allowedobjecttypeslength);

    pos = snprintf(list_str, max_length, "[");

    for (ii = 0; ii < meta_data->allowedobjecttypeslength; ii++) {
        pos += snprintf(list_str + pos, max_length - pos, "%s ",
                        SAI_TYPE_STR(meta_data->allowedobjecttypes[ii]));
        if (pos > max_length) {
            break;
        }
    }

    if (pos < max_length) {
        snprintf(list_str + pos, max_length - pos, "]");
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_allowed_objects_validate(_In_ const sai_attr_metadata_t   *meta_data,
                                                           _In_ const sai_attribute_value_t *value,
                                                           _In_ uint32_t                     attr_index)
{
    sai_status_t           status;
    sai_attr_value_type_t  value_type;
    const sai_object_id_t *value_object_ids = NULL;
    sai_object_type_t      value_object_type;
    uint32_t               objects_count                             = 0, ii;
    bool                   object_types_present[SAI_OBJECT_TYPE_MAX] = {false};
    bool                   object_type_allowed, unique_object_type_present;
    char                   allwed_object_types_str[MAX_VALUE_STR_LEN] = {0};

    assert(meta_data);
    assert(value);

    if (0 == meta_data->allowedobjecttypeslength) {
        return SAI_STATUS_SUCCESS;
    }

    value_type = meta_data->attrvaluetype;

    if (sai_attribute_is_acl_field_or_action(meta_data)) {
        if (meta_data->isaclfield) {
            /* Ignore if value is not enabled */
            if (!value->aclfield.enable) {
                return SAI_STATUS_SUCCESS;
            }

            if (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_ID == value_type) {
                value_object_ids = &value->aclfield.data.oid;
                objects_count    = 1;
            } else if (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_LIST == value_type) {
                value_object_ids = value->aclfield.data.objlist.list;
                objects_count    = value->aclfield.data.objlist.count;
            } else {
                SX_LOG_ERR("Bad meta data for attribute %s\n", meta_data->attridname);
                return SAI_STATUS_FAILURE;
            }
        }

        if (meta_data->isaclaction) {
            /* Ignore if value is not enabled */
            if (!value->aclaction.enable) {
                return SAI_STATUS_SUCCESS;
            }

            if (SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_ID == value_type) {
                value_object_ids = &value->aclaction.parameter.oid;
                objects_count    = 1;
            } else if (SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_LIST == value_type) {
                value_object_ids = value->aclaction.parameter.objlist.list;
                objects_count    = value->aclaction.parameter.objlist.count;
            } else {
                SX_LOG_ERR("Bad meta data for attribute %s\n", meta_data->attridname);
                return SAI_STATUS_FAILURE;
            }
        }
    } else {
        if (SAI_ATTR_VALUE_TYPE_OBJECT_ID == value_type) {
            value_object_ids = &value->oid;
            objects_count    = 1;
        } else if (SAI_ATTR_VALUE_TYPE_OBJECT_LIST == value_type) {
            value_object_ids = value->objlist.list;
            objects_count    = value->objlist.count;
        } else {
            SX_LOG_ERR("Bad meta data for attribute %s\n", meta_data->attridname);
            return SAI_STATUS_FAILURE;
        }
    }

    for (ii = 0; ii < objects_count; ii++) {
        if (SAI_NULL_OBJECT_ID == value_object_ids[ii]) {
            if (meta_data->allownullobjectid) {
                continue;
            }

#ifdef MLNX_SAI_UTILS_NULL_OBJECT_ALLOWED
            continue;
#else
            SX_LOG_ERR("NULL object id in not allowed for attribute %s at index %d\n",
                       meta_data->attridname, attr_index);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
#endif /* MLNX_SAI_UTILS_NULL_OBJECT_ALLOWED */
        }

        value_object_type = sai_object_type_query(value_object_ids[ii]);
        if (SAI_OBJECT_TYPE_NULL == value_object_type) {
            SX_LOG_ERR("Failed to validate %s value - Unknown object type\n", meta_data->attridname);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }

        object_type_allowed = sai_metadata_is_allowed_object_type(meta_data, value_object_type);

        if (!object_type_allowed) {
            status = sai_attribute_is_obj_type_allowed(meta_data, value_object_type, &object_type_allowed);
            if (SAI_ERR(status)) {
                return status;
            }
        }

        if (!object_type_allowed) {
            status = sai_attribute_value_allowed_objects_str_fetch(meta_data,
                                                                   MAX_VALUE_STR_LEN,
                                                                   allwed_object_types_str);
            if (SAI_ERR(status)) {
                return status;
            }

            SX_LOG_ERR("Failed to validate %s value - invalid object type %s. Allowed object types: %s\n",
                       meta_data->attridname, SAI_TYPE_STR(value_object_type), allwed_object_types_str);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }

        object_types_present[value_object_type] = true;
    }

    unique_object_type_present = false;

    if ((meta_data->allowedobjecttypeslength > 1) && (!meta_data->allowmixedobjecttypes)) {
        for (ii = 0; ii < SAI_OBJECT_TYPE_MAX; ii++) {
            if (object_types_present[ii]) {
                if (unique_object_type_present) {
                    SX_LOG_ERR("Mixed object types for attribute %s at index %d\n", meta_data->attridname, attr_index);
                    return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
                }

                unique_object_type_present = true;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_value_list_elem_compare(_In_reads_z_(list_count * elem_size) const void *list,
                                                          _In_ uint32_t                                    list_count,
                                                          _In_ sai_attr_value_type_t                       value_type,
                                                          _In_ uint32_t                                    index_a,
                                                          _In_ uint32_t                                    index_b,
                                                          _In_ size_t                                      elem_size,
                                                          _Out_ bool                                      *is_equeal)
{
    assert(list);
    assert(is_equeal);
    assert(index_a != index_b);
    assert(index_a < list_count);
    assert(index_b < list_count);

    if (SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST == value_type) {
        *is_equeal = false;
        return SAI_STATUS_SUCCESS;
    }

    *is_equeal = (memcmp((char*)list + (elem_size * index_a), (char*)list + (elem_size * index_b), elem_size) == 0);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_value_list_is_unique(_In_ const sai_attr_metadata_t                  *meta_data,
                                                       _In_ uint32_t                                    attr_index,
                                                       _In_reads_z_(list_count * elem_size) const void *list_ptr,
                                                       _In_ uint32_t                                    list_elems_count,
                                                       _In_ sai_attr_value_type_t                       value_type,
                                                       _In_ size_t                                      elem_size)
{
    sai_status_t status;
    uint32_t     ii, jj;
    bool         is_list_elems_equal;

    assert(list_ptr);

    /* No need to check a list with size 0 or 1 */
    if (list_elems_count < 2) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < list_elems_count - 1; ii++) {
        for (jj = ii + 1; jj < list_elems_count; jj++) {
            status = sai_attribute_value_list_elem_compare(list_ptr, list_elems_count, value_type,
                                                           ii, jj, elem_size, &is_list_elems_equal);
            if (SAI_ERR(status)) {
                return status;
            }

            if (is_list_elems_equal) {
                SX_LOG_ERR("Attribute %s contains equal elements at indexes %d and %d\n", meta_data->attridname, ii,
                           jj);
                return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_value_list_type_validate(_In_ const sai_attr_metadata_t   *meta_data,
                                                           _In_ const sai_attribute_value_t *value,
                                                           _In_ sai_common_api_t             oper,
                                                           _In_ uint32_t                     attr_index)
{
    sai_status_t          status;
    sai_attr_value_type_t value_type;
    size_t                list_type_size;
    uint32_t              list_elems_count;
    const void           *list_ptr;
    bool                  is_value_type_list, is_empty_list_allowed;

    assert(meta_data);
    assert(value);

    value_type         = meta_data->attrvaluetype;
    is_value_type_list = true;

    switch (value_type) {
    case SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
        list_type_size   = sizeof(value->objlist.list[0]);
        list_ptr         = value->objlist.list;
        list_elems_count = value->objlist.count;
        break;

    case SAI_ATTR_VALUE_TYPE_UINT8_LIST:
        list_type_size   = sizeof(value->u8list.list[0]);
        list_ptr         = value->u8list.list;
        list_elems_count = value->u8list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_INT8_LIST:
        list_type_size   = sizeof(value->s8list.list[0]);
        list_ptr         = value->s8list.list;
        list_elems_count = value->s8list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_UINT16_LIST:
        list_type_size   = sizeof(value->u16list.list[0]);
        list_ptr         = value->u16list.list;
        list_elems_count = value->u16list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_INT16_LIST:
        list_type_size   = sizeof(value->s16list.list[0]);
        list_ptr         = value->s16list.list;
        list_elems_count = value->s16list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_UINT32_LIST:
        list_type_size   = sizeof(value->u32list.list[0]);
        list_ptr         = value->u32list.list;
        list_elems_count = value->u32list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_VLAN_LIST:
        list_type_size   = sizeof(value->vlanlist.list[0]);
        list_ptr         = value->vlanlist.list;
        list_elems_count = value->vlanlist.count;
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_LIST:
        list_type_size   = sizeof(value->aclfield.data.objlist.list[0]);
        list_ptr         = value->aclfield.data.objlist.list;
        list_elems_count = value->aclfield.data.objlist.count;
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST:
        list_type_size   = sizeof(value->aclfield.data.u8list.list[0]);
        list_ptr         = value->aclfield.data.u8list.list;
        list_elems_count = value->aclfield.data.u8list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_LIST:
        list_type_size   = sizeof(value->aclaction.parameter.objlist.list[0]);
        list_ptr         = value->aclaction.parameter.objlist.list;
        list_elems_count = value->aclaction.parameter.objlist.count;
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
        list_type_size   = sizeof(value->aclcapability.action_list.list[0]);
        list_ptr         = value->aclcapability.action_list.list;
        list_elems_count = value->aclcapability.action_list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST:
        list_type_size   = sizeof(value->qosmap.list[0]);
        list_ptr         = value->qosmap.list;
        list_elems_count = value->qosmap.count;
        break;

    case SAI_ATTR_VALUE_TYPE_MAP_LIST:
        list_type_size   = sizeof(value->maplist.list[0]);
        list_ptr         = value->maplist.list;
        list_elems_count = value->maplist.count;
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
        list_type_size   = sizeof(value->aclresource.list[0]);
        list_ptr         = value->aclresource.list;
        list_elems_count = value->aclresource.count;
        break;

    case SAI_ATTR_VALUE_TYPE_TLV_LIST:
        list_type_size   = sizeof(value->tlvlist.list[0]);
        list_ptr         = value->tlvlist.list;
        list_elems_count = value->tlvlist.count;
        break;

    case SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
        list_type_size   = sizeof(value->segmentlist.list[0]);
        list_ptr         = value->segmentlist.list;
        list_elems_count = value->segmentlist.count;
        break;

    default:
        is_value_type_list = false;
        break;
    }

    if (!is_value_type_list) {
        return SAI_STATUS_SUCCESS;
    }

    if ((NULL == list_ptr) && (list_elems_count > 0)) {
        SX_LOG_ERR("Null list attribute %s at index %d\n", meta_data->attridname, attr_index);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST == value_type) {
        if (value->aclfield.data.u8list.count != value->aclfield.mask.u8list.count) {
            SX_LOG_ERR("Mismatch between data list count %u and mask list count %u attribute %s at index %d\n",
                       value->aclfield.data.u8list.count,
                       value->aclfield.mask.u8list.count,
                       meta_data->attridname,
                       attr_index);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }
    }

    if ((SAI_COMMON_API_CREATE == oper) || (SAI_COMMON_API_SET == oper)) {
        if ((!meta_data->allowemptylist) && (0 == list_elems_count)) {
            status = sai_attribute_is_empty_list_allowed(meta_data, &is_empty_list_allowed);
            if (SAI_ERR(status)) {
                return status;
            }

            if (!is_empty_list_allowed) {
                SX_LOG_ERR("Empty list is not allowed for attribute %s at index %d\n",
                           meta_data->attridname,
                           attr_index);
                return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
            }
        }

        if (list_ptr && (!meta_data->allowrepetitiononlist)) {
            status = sai_attribute_value_list_is_unique(meta_data, attr_index, list_ptr, list_elems_count,
                                                        value_type, list_type_size);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_atribute_value_type_enum_validate(_In_ const sai_attr_metadata_t   *meta_data,
                                                          _In_ const sai_attribute_value_t *value,
                                                          _In_ uint32_t                     attr_index)
{
    const sai_enum_metadata_t *enum_metadata;
    const sai_int32_t         *enum_values;
    uint32_t                   enum_values_count, ii;
    bool                       is_enum_value_allowed;

    assert(meta_data);
    assert(value);

    if ((!meta_data->isenum) && (!meta_data->isenumlist)) {
        return SAI_STATUS_SUCCESS;
    }

    if (meta_data->isaclfield && meta_data->isaclaction) {
        SX_LOG_ERR("Bad meta data for attribute %s - both aclfield and aclaction are true\n", meta_data->attridname);
        return SAI_STATUS_FAILURE;
    }

    if (NULL == meta_data->enummetadata) {
        SX_LOG_ERR("Bad meta data for attribute %s - enummetadata is NULL\n", meta_data->attridname);
        return SAI_STATUS_FAILURE;
    }

    if (meta_data->isenum && meta_data->isenumlist) {
        SX_LOG_ERR("Bad meta data for attribute %s - both isenum and isenumlist are true\n", meta_data->attridname);
        return SAI_STATUS_FAILURE;
    }

    switch (meta_data->attrvaluetype) {
    case SAI_ATTR_VALUE_TYPE_INT32:
        enum_values       = &value->s32;
        enum_values_count = 1;
        break;

    case SAI_ATTR_VALUE_TYPE_INT32_LIST:
        enum_values       = value->s32list.list;
        enum_values_count = value->s32list.count;
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_INT32:
        enum_values       = &value->aclfield.data.s32;
        enum_values_count = 1;
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_INT32:
        enum_values       = &value->aclaction.parameter.s32;
        enum_values_count = 1;
        break;

    default:
        SX_LOG_ERR("Unexpected type of %s value for enum\n", meta_data->attridname);
        return SAI_STATUS_FAILURE;
    }

    if (NULL == enum_values) {
        SX_LOG_ERR("Failed to validate %s value - enum list is NULL\n", meta_data->attridname);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    enum_metadata = meta_data->enummetadata;

    for (ii = 0; ii < enum_values_count; ii++) {
        is_enum_value_allowed = sai_metadata_is_allowed_enum_value(meta_data, enum_values[ii]);
        if (!is_enum_value_allowed) {
            SX_LOG_ERR("Failed to validate %s value - enum value %d is out of range [%s, %s]\n",
                       meta_data->attridname, enum_values[ii], enum_metadata->valuesnames[0],
                       enum_metadata->valuesnames[enum_metadata->valuescount - 1]);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_value_validate(_In_ const sai_attr_metadata_t   *meta_data,
                                                 _In_ const sai_attribute_value_t *value,
                                                 _In_ sai_common_api_t             oper,
                                                 _In_ uint32_t                     attr_index)
{
    sai_status_t status;

    assert(meta_data);
    assert(value);

    status = sai_attribute_value_list_type_validate(meta_data, value, oper, attr_index);
    if (SAI_ERR(status)) {
        return status;
    }

    if ((SAI_COMMON_API_CREATE == oper) || (SAI_COMMON_API_SET == oper)) {
        status = sai_atribute_value_type_enum_validate(meta_data, value, attr_index);
        if (SAI_ERR(status)) {
            return status;
        }

        status = sai_attribute_allowed_objects_validate(meta_data, value, attr_index);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_attr_list_attr_find(_In_ const sai_u32_list_t *values,
                                                 _In_ uint32_t              key,
                                                 _In_ uint32_t              value,
                                                 _Out_ bool                *is_present)
{
    const sai_u32_list_t *values_for_key;
    uint32_t              ii;

    assert(values);
    assert(is_present);

    values_for_key = &values[key];

    *is_present = false;

    for (ii = 0; ii < values_for_key->count; ii++) {
        if (value == values_for_key->list[ii]) {
            *is_present = true;
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_is_obj_type_allowed(_In_ const sai_attr_metadata_t *attr_metadata,
                                                      _In_ sai_object_type_t          object_type,
                                                      _Out_ bool                     *is_object_type_allowed)
{
    const sai_u32_list_t *attrs;
    const sai_u32_list_t *object_types;

    assert(attr_metadata);
    assert(is_object_type_allowed);
    assert(sai_metadata_is_object_type_valid(object_type));

    *is_object_type_allowed = false;

    attrs = &mlnx_sai_valid_obj_types[attr_metadata->objecttype];

    if (attrs->count <= attr_metadata->attrid) {
        return SAI_STATUS_SUCCESS;
    }

    object_types = (const sai_u32_list_t*)attrs->list;

    return mlnx_sai_attr_list_attr_find(object_types, attr_metadata->attrid, object_type, is_object_type_allowed);
}

/*
 * Some of the attributes have a complex condition for mandatority
 * But their meta-data have a flag MANDATORY_ON_CREATE
 * This function returns 'is_not_mandatory = true' for these attributes, so they can be ignored
 */
static sai_status_t sai_attribute_is_not_mandatory(_In_ const sai_attr_metadata_t *attr_metadata,
                                                   _Out_ bool                     *is_not_mandatory)
{
    assert(attr_metadata);
    assert(is_not_mandatory);

    return mlnx_sai_attr_list_attr_find(mlnx_sai_not_mandatory_attrs, attr_metadata->objecttype,
                                        attr_metadata->attrid, is_not_mandatory);
}

static sai_status_t sai_attribute_is_valid_for_set(_In_ const sai_attr_metadata_t *attr_metadata,
                                                   _Out_ bool                     *is_valid)
{
    assert(attr_metadata);
    assert(is_valid);

    return mlnx_sai_attr_list_attr_find(mlnx_sai_attrs_valid_for_set, attr_metadata->objecttype,
                                        attr_metadata->attrid, is_valid);
}

static sai_status_t sai_attribute_is_empty_list_allowed(_In_ const sai_attr_metadata_t *attr_metadata,
                                                        _Out_ bool                     *is_allowed)
{
    assert(attr_metadata);
    assert(is_allowed);

    return mlnx_sai_attr_list_attr_find(mlnx_sai_attrs_with_empty_list, attr_metadata->objecttype,
                                        attr_metadata->attrid, is_allowed);
}

static sai_status_t sai_attrlist_mandatory_attrs_check(
    _In_reads_z_(attr_count_meta) const bool       *attr_present_meta,
    _In_ uint32_t                                   attr_count_meta,
    _In_reads_z_(attr_count) const sai_attribute_t *attr_list,
    _In_ uint32_t                                   attr_count,
    _In_ sai_object_type_t                          object_type)
{
    sai_status_t                      status;
    char                              conditions_str[MAX_LIST_VALUE_STR_LEN] = {0};
    const sai_attr_metadata_t* const *md;
    uint32_t                          ii;
    bool                              is_mandatory_condtitions_valid, is_not_mandatory;

    assert(attr_present_meta);

    if (!sai_metadata_is_object_type_valid(object_type)) {
        SX_LOG_ERR("Invalid object type (%d)\n", object_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /*
     * Currnetly, metadata for ACL UDF attributes is not generated
     * attr_count_meta in increased by MLNX_UDF_ACL_ATTR_COUNT in sai_object_type_attr_count_meta_get
     */
    if (sai_objet_type_is_acl_table_or_entry(object_type)) {
        attr_count_meta -= MLNX_UDF_ACL_ATTR_COUNT;
    }

    md = sai_metadata_attr_by_object_type[object_type];

    for (ii = 0; ii < attr_count_meta; ii++) {
        if (NULL == md[ii]) {
            SX_LOG_ERR("ii %d , count %d\n", ii, attr_count_meta);
            SX_LOG_ERR("Meta data array for object type %s is broken\n", SAI_TYPE_STR(object_type));
            return SAI_STATUS_FAILURE;
        }

        if (md[ii]->flags & SAI_ATTR_FLAGS_MANDATORY_ON_CREATE) {
            status = sai_attribute_is_not_mandatory(md[ii], &is_not_mandatory);
            if (SAI_ERR(status)) {
                return status;
            }

            if (is_not_mandatory) {
                continue;
            }

            /* Empty attr list is not allowed when API contains mandatory attr */
            if (NULL == attr_list) {
                SX_LOG_ERR("Missing mandatory attribute %s on create (attr_list is null)\n", md[ii]->attridname);
                return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            }

            if (md[ii]->isconditional) {
                status = sai_attribute_conditions_check(md[ii]->conditiontype,
                                                        md[ii]->conditions,
                                                        md[ii]->conditionslength,
                                                        md[ii]->objecttype,
                                                        attr_list,
                                                        attr_count,
                                                        &is_mandatory_condtitions_valid);
                if (SAI_ERR(status)) {
                    return status;
                }

                if (is_mandatory_condtitions_valid && (!attr_present_meta[ii])) {
                    status = sai_attr_metadata_conditions_print(md[ii]->conditiontype,
                                                                md[ii]->conditions,
                                                                md[ii]->conditionslength,
                                                                md[ii]->objecttype,
                                                                MAX_LIST_VALUE_STR_LEN,
                                                                conditions_str);
                    if (SAI_ERR(status)) {
                        return status;
                    }

                    SX_LOG_ERR("Missing mandatory attribute %s on create. Attribute is mandatory when: {%s}\n",
                               md[ii]->attridname,
                               conditions_str);
                    return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
                }
            } else {
                if (!attr_present_meta[ii]) {
                    SX_LOG_ERR("Missing mandatory attribute %s on create\n", md[ii]->attridname);
                    return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
                }
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_values_compare(_In_ const sai_attribute_value_t *v1,
                                                 _In_ const sai_attribute_value_t *v2,
                                                 _In_ const sai_attr_metadata_t   *attr_metadata,
                                                 _Out_ bool                       *is_equeal)
{
    assert(v1 && v2);
    assert(attr_metadata);
    assert(is_equeal);

    switch (attr_metadata->attrvaluetype) {
    case SAI_ATTR_VALUE_TYPE_INT32:
        *is_equeal = v1->s32 == v2->s32;
        break;

    case SAI_ATTR_VALUE_TYPE_BOOL:
        *is_equeal = v1->booldata == v2->booldata;
        break;

    default:
        SX_LOG_ERR("Failed to compare values for condition checking - %s type in not handled\n",
                   attr_metadata->attridname);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attr_list_check_condition(_In_ const sai_attr_condition_t *condition,
                                                  _In_ sai_object_type_t           object_type,
                                                  _In_ const sai_attribute_t      *attr_list,
                                                  _In_ uint32_t                    attr_count,
                                                  _Out_ bool                      *condition_value)
{
    sai_status_t                 status;
    const sai_attribute_value_t *value;
    const sai_attr_metadata_t   *cond_attr_metadata;
    uint32_t                     index;

    assert(condition);
    assert(attr_list);

    status = find_attrib_in_list(attr_count, attr_list, condition->attrid, &value, &index);
    if (SAI_ERR(status)) {
        *condition_value = false;
        return SAI_STATUS_SUCCESS;
    }

    cond_attr_metadata = sai_metadata_get_attr_metadata(object_type, condition->attrid);
    if (NULL == cond_attr_metadata) {
        SX_LOG_ERR("Failed to fetch meta data for attr (%d)\n", condition->attrid);
        return SAI_STATUS_UNKNOWN_ATTRIBUTE_0;
    }

    status = sai_attribute_values_compare(&condition->condition, value, cond_attr_metadata, condition_value);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_conditions_check(_In_ sai_attr_condition_type_t                 condition_type,
                                                   _In_ const sai_attr_condition_t* const * const conditions,
                                                   _In_ size_t                                    conditionslength,
                                                   _In_ sai_object_type_t                         object_type,
                                                   _In_ const sai_attribute_t                    *attr_list,
                                                   _In_ uint32_t                                  attr_count,
                                                   _Out_ bool                                    *conditions_valid)
{
    sai_status_t status;
    uint32_t     ii;
    bool         condition_value;

    assert(attr_list);
    assert(conditions_valid);

    if (0 == conditionslength) {
        SX_LOG_ERR("Failed to validate attr conditions - conditionslength is zero\n");
        return SAI_STATUS_FAILURE;
    }

    if ((SAI_ATTR_CONDITION_TYPE_OR != condition_type) && (SAI_ATTR_CONDITION_TYPE_AND != condition_type)) {
        SX_LOG_ERR("Failed to validate attr conditions - invalid type of condition (%d)\n", condition_type);
        return SAI_STATUS_FAILURE;
    }

    *conditions_valid = false;

    for (ii = 0; ii < conditionslength; ii++) {
        status = sai_attr_list_check_condition(conditions[ii], object_type, attr_list, attr_count, &condition_value);
        if (SAI_ERR(status)) {
            return status;
        }

        if (condition_value && (SAI_ATTR_CONDITION_TYPE_OR == condition_type)) {
            *conditions_valid = true;
            return SAI_STATUS_SUCCESS;
        }

        if ((!condition_value) && (SAI_ATTR_CONDITION_TYPE_AND == condition_type)) {
            *conditions_valid = false;
            return SAI_STATUS_SUCCESS;
        }

        *conditions_valid = condition_value;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attr_metadata_conditions_print(_In_ sai_attr_condition_type_t                condition_type,
                                                       _In_ const sai_attr_condition_t* const* const conditions,
                                                       _In_ size_t                                   conditionslength,
                                                       _In_ sai_object_type_t                        object_type,
                                                       _In_ size_t                                   max_length,
                                                       _Out_writes_(max_length) char                *str)
{
    sai_status_t               status;
    char                       value_str[MAX_VALUE_STR_LEN] = {0};
    const char                *condition_type_str;
    const sai_attr_metadata_t *attr_metadata;
    uint32_t                   pos, ii;

    if (sai_metadata_enum_sai_attr_condition_type_t.valuescount <= condition_type) {
        SX_LOG_ERR("Bad meta data - condition type (%d) is out of range\n", condition_type);
        return SAI_STATUS_FAILURE;
    }

    condition_type_str = sai_metadata_enum_sai_attr_condition_type_t.valuesshortnames[condition_type];
    pos                = 0;

    for (ii = 0; ii < conditionslength; ii++) {
        attr_metadata = sai_metadata_get_attr_metadata(object_type, conditions[ii]->attrid);
        assert(NULL != attr_metadata);

        if (attr_metadata->isenum) {
            status =
                sai_attr_meta_enum_to_str(attr_metadata, &conditions[ii]->condition, MAX_VALUE_STR_LEN, value_str);
            if (SAI_ERR(status)) {
                return status;
            }
        } else if (attr_metadata->attrvaluetype == SAI_ATTR_VALUE_TYPE_BOOL) {
            snprintf(value_str, MAX_VALUE_STR_LEN, "%s", MLNX_UTILS_BOOL_TO_STR(conditions[ii]->condition.booldata));
        } else {
            SX_LOG_ERR("Failed to print conditions for attr %s - unhandled value type %d\n",
                       attr_metadata->attridname, attr_metadata->attrvaluetype);
            return SAI_STATUS_FAILURE;
        }

        pos += snprintf(str + pos,
                        max_length - pos,
                        "(%s : %s)",
                        attr_metadata->attridname,
                        value_str);
        if (pos > max_length) {
            break;
        }

        if (ii < (conditionslength - 1)) {
            pos += snprintf(str + pos,
                            max_length - pos,
                            " %s ",
                            condition_type_str);
            if (pos > max_length) {
                break;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attribute_valid_condition_check(_In_ const sai_attr_metadata_t *attr_metadata,
                                                        _In_ uint32_t                   attr_count,
                                                        _In_ const sai_attribute_t     *attr_list)
{
    sai_status_t status;
    char         conditions_str[MAX_LIST_VALUE_STR_LEN] = {0};
    bool         is_valid_only_conditions_valid;

    assert(attr_metadata);
    assert(attr_list);

    if (SAI_ATTR_CONDITION_TYPE_NONE != attr_metadata->validonlytype) {
        status = sai_attribute_conditions_check(attr_metadata->validonlytype,
                                                attr_metadata->validonly,
                                                attr_metadata->validonlylength,
                                                attr_metadata->objecttype,
                                                attr_list,
                                                attr_count,
                                                &is_valid_only_conditions_valid);
        if (SAI_ERR(status)) {
            return status;
        }

        if (!is_valid_only_conditions_valid) {
            status = sai_attr_metadata_conditions_print(attr_metadata->validonlytype,
                                                        attr_metadata->validonly,
                                                        attr_metadata->validonlylength,
                                                        attr_metadata->objecttype,
                                                        MAX_LIST_VALUE_STR_LEN,
                                                        conditions_str);
            if (SAI_ERR(status)) {
                return status;
            }

            SX_LOG_ERR("Attribute %s doesn't match a valid conditions: {%s}\n",
                       attr_metadata->attridname,
                       conditions_str);
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static bool sai_attribute_is_acl_field_or_action(_In_ const sai_attr_metadata_t *meta_data)
{
    if (meta_data == NULL) {
        return false;
    }

    if (meta_data->objecttype == SAI_OBJECT_TYPE_ACL_ENTRY) {
        if ((meta_data->attrid >= SAI_ACL_ENTRY_ATTR_FIELD_START) &&
            (meta_data->attrid <= SAI_ACL_ENTRY_ATTR_FIELD_END)) {
            return true;
        }

        if ((meta_data->attrid >= SAI_ACL_ENTRY_ATTR_ACTION_START) &&
            (meta_data->attrid <= SAI_ACL_ENTRY_ATTR_ACTION_END)) {
            return true;
        }
    }

    return false;
}

static bool sai_objet_type_is_acl_table_or_entry(_In_ sai_object_type_t object_type)
{
    if ((SAI_OBJECT_TYPE_ACL_TABLE == object_type) ||
        (SAI_OBJECT_TYPE_ACL_ENTRY == object_type)) {
        return true;
    }

    return false;
}

static bool sai_attr_is_acl_udf(_In_ sai_object_type_t object_type, _In_ sai_attr_id_t attr_id)
{
    if (((SAI_OBJECT_TYPE_ACL_ENTRY == object_type) || (SAI_OBJECT_TYPE_ACL_TABLE == object_type)) &&
        ((SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN <= attr_id) &&
         (attr_id <= SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MAX))) {
        return true;
    }

    return false;
}

void mlnx_udf_acl_attrs_metadata_init()
{
    uint32_t ii;

    assert(ARRAY_SIZE(mlnx_udf_acl_table_attr_metadata_list) == MLNX_UDF_ACL_ATTR_COUNT);
    assert(ARRAY_SIZE(mlnx_udf_acl_table_attr_names) == MLNX_UDF_ACL_ATTR_COUNT);
    assert(ARRAY_SIZE(mlnx_udf_acl_entry_attr_metadata_list) == MLNX_UDF_ACL_ATTR_COUNT);
    assert(ARRAY_SIZE(mlnx_udf_acl_entry_attr_names) == MLNX_UDF_ACL_ATTR_COUNT);

    for (ii = 0; ii < MLNX_UDF_ACL_ATTR_COUNT; ii++) {
        /* Init metedata for SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP* attributes */

        memcpy(&mlnx_udf_acl_table_attr_metadata_list[ii], &mlnx_udf_acl_table_attr_metadata,
               sizeof(mlnx_udf_acl_table_attr_metadata_list[ii]));

        mlnx_udf_acl_table_attr_metadata_list[ii].attrid = SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN + ii;

        *((const char**)&mlnx_udf_acl_table_attr_metadata_list[ii].attridname) = mlnx_udf_acl_table_attr_names[ii];

        /* Init metedata for SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP* attributes */
        memcpy(&mlnx_udf_acl_entry_attr_metadata_list[ii], &mlnx_udf_acl_entry_attr_metadata,
               sizeof(mlnx_udf_acl_entry_attr_metadata_list[ii]));

        mlnx_udf_acl_entry_attr_metadata_list[ii].attrid = SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN + ii;

        *((const char**)&mlnx_udf_acl_entry_attr_metadata_list[ii].attridname) = mlnx_udf_acl_entry_attr_names[ii];
    }
}

bool mlnx_udf_acl_attribute_id_is_not_supported(_In_ sai_attr_id_t attr_id)
{
    return (((SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN + MLNX_UDF_ACL_ATTR_MAX_ID) < attr_id) &&
            (attr_id <= SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MAX));
}

static const sai_attr_metadata_t* mlnx_sai_udf_attr_metadata_get(_In_ sai_object_type_t object_type,
                                                                 _In_ sai_attr_id_t     attr_id)
{
    bool attr_id_not_supported;

    assert(sai_attr_is_acl_udf(object_type, attr_id));

    attr_id_not_supported = mlnx_udf_acl_attribute_id_is_not_supported(attr_id);

    if (SAI_OBJECT_TYPE_ACL_TABLE == object_type) {
        if (attr_id_not_supported) {
            SX_LOG_ERR(
                "Attribute SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN_%d is out of supported range (0, %d)\n",
                attr_id - SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN,
                MLNX_UDF_ACL_ATTR_MAX_ID);
            return NULL;
        }

        return &mlnx_udf_acl_table_attr_metadata_list[attr_id - SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN];
    }

    if (SAI_OBJECT_TYPE_ACL_ENTRY == object_type) {
        if (attr_id_not_supported) {
            SX_LOG_ERR(
                "Attribute SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN_%d is out of supported range (0, %d)\n",
                attr_id - SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN,
                MLNX_UDF_ACL_ATTR_MAX_ID);
            return NULL;
        }

        return &mlnx_udf_acl_entry_attr_metadata_list[attr_id - SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN];
    }

    return NULL;
}

static const sai_attr_metadata_t* mlnx_sai_attr_metadata_get_impl(_In_ sai_object_type_t object_type,
                                                                  _In_ sai_attr_id_t     attr_id)
{
    if (sai_attr_is_acl_udf(object_type, attr_id)) {
        return mlnx_sai_udf_attr_metadata_get(object_type, attr_id);
    } else {
        return sai_metadata_get_attr_metadata(object_type, attr_id);
    }
}

static sai_status_t mlnx_sai_udf_attr_short_name_fetch(_In_ sai_object_type_t object_type,
                                                       _In_ sai_attr_id_t     attr_id,
                                                       _Out_ const char     **attr_short_name)
{
    const char **names;
    uint32_t     attr_index;

    assert(sai_attr_is_acl_udf(object_type, attr_id));
    assert(attr_short_name);

    attr_index = attr_id - SAI_ACL_ENTRY_ATTR_USER_DEFINED_FIELD_GROUP_MIN;

    if (MLNX_UDF_ACL_ATTR_MAX_ID < attr_index) {
        *attr_short_name = "UDF_ATTR_OUT_OF_RANGE";
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_OBJECT_TYPE_ACL_TABLE == object_type) {
        names = mlnx_udf_acl_table_attr_names;
    }

    if (SAI_OBJECT_TYPE_ACL_ENTRY == object_type) {
        names = mlnx_udf_acl_entry_attr_names;
    }

    *attr_short_name = names[attr_index] + MLNX_UDF_ACL_ATTR_SHORT_NAME_OFFSET;

    return SAI_STATUS_SUCCESS;
}

sai_status_t check_attribs_metadata(_In_ uint32_t                            attr_count,
                                    _In_ const sai_attribute_t              *attr_list,
                                    _In_ sai_object_type_t                   object_type,
                                    _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                    _In_ sai_common_api_t                    oper)
{
    sai_status_t               status;
    const sai_attr_metadata_t *meta_data;
    sai_attr_flags_t           attr_flags;
    uint32_t                   attr_count_meta, meta_data_index, vendor_attr_index, ii;
    bool                      *attr_present_meta = NULL, is_valid_for_set;

    SX_LOG_ENTER();

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (NULL == functionality_vendor_attr) {
        SX_LOG_ERR("NULL value functionality vendor attrib\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (SAI_COMMON_API_MAX <= oper) {
        SX_LOG_ERR("Invalid operation %d\n", oper);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (SAI_COMMON_API_REMOVE == oper) {
        /* No attributes expected for remove at this point */
        status = SAI_STATUS_NOT_IMPLEMENTED;
        goto out;
    }

    if (SAI_COMMON_API_SET == oper) {
        if (1 != attr_count) {
            SX_LOG_ERR("Set operation supports only single attribute\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
    }

    if (!sai_metadata_is_object_type_valid(object_type)) {
        SX_LOG_ERR("Invalid object type (%d)\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = sai_object_type_attr_count_meta_get(object_type, &attr_count_meta);
    if (SAI_ERR(status)) {
        goto out;
    }

    attr_present_meta = calloc(attr_count_meta, sizeof(bool));
    if (NULL == attr_present_meta) {
        SX_LOG_ERR("Can't allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (ii = 0; ii < attr_count; ii++) {
        meta_data = mlnx_sai_attr_metadata_get_impl(object_type, attr_list[ii].id);
        if (NULL == meta_data) {
            SX_LOG_ERR("Invalid attribute %d (meta data not found)\n", attr_list[ii].id);
            status = SAI_STATUS_UNKNOWN_ATTRIBUTE_0 + ii;
            goto out;
        }

        status = sai_object_type_attr_index_find(attr_list[ii].id, object_type, &meta_data_index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Invalid attribute %d (meta data index not found)\n", attr_list[ii].id);
            status = SAI_STATUS_UNKNOWN_ATTRIBUTE_0 + ii;
            goto out;
        }

        status = sai_vendor_attr_index_find(attr_list[ii].id, functionality_vendor_attr, &vendor_attr_index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Not implemented attribute %s (vendor data not found)\n", meta_data->attridname);
            status = SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
            goto out;
        }

        attr_flags = meta_data->flags;

        if (SAI_COMMON_API_CREATE == oper) {
            if (!(attr_flags & (SAI_ATTR_FLAGS_CREATE_ONLY | SAI_ATTR_FLAGS_CREATE_AND_SET))) {
                SX_LOG_ERR("Invalid attribute %s for create\n", meta_data->attridname);
                status = SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
                goto out;
            }
        }

        if (SAI_COMMON_API_SET == oper) {
            /* Some of the attributes in not supported for set in SAI header but supported in MLNX impl
             * e.g SAI_PORT_ATTR_AUTO_NEG_MODE
             */
            status = sai_attribute_is_valid_for_set(meta_data, &is_valid_for_set);
            if (SAI_ERR(status)) {
                status = SAI_STATUS_FAILURE;
                goto out;
            }

            if ((!(attr_flags & SAI_ATTR_FLAGS_CREATE_AND_SET) && (!is_valid_for_set))) {
                SX_LOG_ERR("Invalid attribute %s for set\n", meta_data->attridname);
                status = SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
                goto out;
            }
        }

        if (!(functionality_vendor_attr[vendor_attr_index].is_supported[oper])) {
            SX_LOG_ERR("Not supported attribute %s\n", meta_data->attridname);
            status = SAI_STATUS_ATTR_NOT_SUPPORTED_0 + ii;
            goto out;
        }

        if (!(functionality_vendor_attr[vendor_attr_index].is_implemented[oper])) {
            SX_LOG_ERR("Not implemented attribute %s\n", meta_data->attridname);
            status = SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
            goto out;
        }

        if (attr_present_meta[meta_data_index]) {
            SX_LOG_ERR("Attribute %s appears twice in attribute list at index %d\n",
                       meta_data->attridname,
                       ii);
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
            goto out;
        }

        status = sai_attribute_value_validate(meta_data, &attr_list[ii].value, oper, ii);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (SAI_COMMON_API_CREATE == oper) {
            status = sai_attribute_valid_condition_check(meta_data, attr_count, attr_list);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        attr_present_meta[meta_data_index] = true;
    }

    if (SAI_COMMON_API_CREATE == oper) {
        status = sai_attrlist_mandatory_attrs_check(attr_present_meta,
                                                    attr_count_meta,
                                                    attr_list,
                                                    attr_count,
                                                    object_type);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    free(attr_present_meta);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t set_dispatch_attrib_handler(_In_ const sai_attribute_t              *attr,
                                                _In_ sai_object_type_t                   object_type,
                                                _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                                _In_ const sai_object_key_t             *key,
                                                _In_ const char                         *key_str)
{
    sai_status_t               status;
    const sai_attr_metadata_t *meta_data;
    const char                *short_attr_name;
    char                       value_str[MAX_VALUE_STR_LEN];
    uint32_t                   index;
    sx_log_severity_t          log_level = SX_LOG_NOTICE;

    SX_LOG_ENTER();

    if (NULL == attr) {
        SX_LOG_ERR("NULL value attr\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_vendor_attr) {
        SX_LOG_ERR("NULL value functionality vendor attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = sai_vendor_attr_index_find(attr->id, functionality_vendor_attr, &index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    meta_data = mlnx_sai_attr_metadata_get_impl(object_type, attr->id);
    if (NULL == meta_data) {
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    status = sai_attribute_short_name_fetch(object_type, attr->id, &short_attr_name);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    if (!functionality_vendor_attr[index].setter) {
        SX_LOG_ERR("Attribute %s not implemented on set and defined incorrectly\n",
                   meta_data->attridname);
        return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0;
    }

    if (SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST == meta_data->attrvaluetype) {
        sai_qos_map_to_str_oid(key->key.object_id, attr->value, MAX_VALUE_STR_LEN, value_str);
    } else {
        sai_attr_metadata_to_str(meta_data, &attr->value, MAX_VALUE_STR_LEN, value_str);
    }

    /* lower log level for route entry next hop updated often in Sonic */
#ifdef ACS_OS
    if ((SAI_OBJECT_TYPE_ROUTE_ENTRY == object_type) &&
        (SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID == attr->id)) {
        log_level = SX_LOG_INFO;
    }
#endif

    SX_LOG(log_level, "Set %s, key:%s, val:%s\n", short_attr_name, key_str, value_str);
    status = functionality_vendor_attr[index].setter(key, &(attr->value), functionality_vendor_attr[index].setter_arg);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t get_dispatch_attribs_handler(_In_ uint32_t                            attr_count,
                                                 _Inout_ sai_attribute_t                 *attr_list,
                                                 _In_ sai_object_type_t                   object_type,
                                                 _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                                 _In_ const sai_object_key_t             *key,
                                                 _In_ const char                         *key_str)
{
    sai_status_t               status;
    sai_attr_id_t              attr_id;
    uint32_t                   ii, index;
    vendor_cache_t             cache;
    const sai_attr_metadata_t *meta_data;
    const char                *short_attr_name;
    void                      *vendor_getter_arg;
    char                       value_str[MAX_VALUE_STR_LEN];
    sx_log_severity_t          log_level;

    SX_LOG_ENTER();

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_vendor_attr) {
        SX_LOG_ERR("NULL value functionality vendor attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memset(&cache, 0, sizeof(cache));

    for (ii = 0; ii < attr_count; ii++) {
        attr_id = attr_list[ii].id;

        status = sai_vendor_attr_index_find(attr_id, functionality_vendor_attr, &index);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return status;
        }

        vendor_getter_arg = functionality_vendor_attr[index].getter_arg;

        meta_data = mlnx_sai_attr_metadata_get_impl(object_type, attr_id);
        if (NULL == meta_data) {
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }

        status = sai_attribute_short_name_fetch(object_type, attr_id, &short_attr_name);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return status;
        }

        if (!functionality_vendor_attr[index].getter) {
            SX_LOG_ERR("Attribute %s not implemented on get and defined incorrectly\n",
                       meta_data->attridname);
            return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
        }

        log_level = SX_LOG_NOTICE;
        /* lower log level for all gets in Sonic */
#ifdef ACS_OS
        log_level = SX_LOG_INFO;
#endif

        status = functionality_vendor_attr[index].getter(key, &(attr_list[ii].value), ii, &cache,
                                                         vendor_getter_arg);
        if (SAI_ERR(status)) {
            if (MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST == status) {
                SX_LOG(log_level, "Queried list length %s\n", meta_data->attridname);
            } else {
                SX_LOG_ERR("Failed getting attrib %s\n", meta_data->attridname);
            }
            SX_LOG_EXIT();
            return status;
        }

        if (SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST == meta_data->attrvaluetype) {
            sai_qos_map_to_str_oid(key->key.object_id, attr_list[ii].value, MAX_VALUE_STR_LEN, value_str);
        } else {
            sai_attr_metadata_to_str(meta_data, &attr_list[ii].value, MAX_VALUE_STR_LEN, value_str);
        }

        /* lower log level for ACL counter stats */
        if ((SAI_OBJECT_TYPE_ACL_COUNTER == object_type) &&
            ((SAI_ACL_COUNTER_ATTR_BYTES == attr_id) || (SAI_ACL_COUNTER_ATTR_PACKETS == attr_id))) {
            log_level = SX_LOG_DEBUG;
        }
        /* lower log level for frequent attribs used in Sonic */
#ifdef ACS_OS
        if ((SAI_OBJECT_TYPE_SWITCH == object_type) &&
            ((SAI_SWITCH_ATTR_PORT_NUMBER == attr_id) || (SAI_SWITCH_ATTR_PORT_LIST == attr_id))) {
            log_level = SX_LOG_DEBUG;
        }
#endif

        SX_LOG(log_level, "Got #%u, %s, key:%s, val:%s\n", ii, short_attr_name, key_str, value_str);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t find_attrib_in_list(_In_ uint32_t                       attr_count,
                                 _In_ const sai_attribute_t         *attr_list,
                                 _In_ sai_attr_id_t                  attrib_id,
                                 _Out_ const sai_attribute_value_t **attr_value,
                                 _Out_ uint32_t                     *index)
{
    uint32_t ii;

    SX_LOG_ENTER();

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == attr_value) {
        SX_LOG_ERR("NULL value attr value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (ii = 0; ii < attr_count; ii++) {
        if (attr_list[ii].id == attrib_id) {
            *attr_value = &(attr_list[ii].value);
            *index      = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

sai_status_t sai_set_attribute(_In_ const sai_object_key_t             *key,
                               _In_ const char                         *key_str,
                               _In_ sai_object_type_t                   object_type,
                               _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                               _In_ const sai_attribute_t              *attr)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(1, attr, object_type, functionality_vendor_attr, SAI_COMMON_API_SET))) {
        SX_LOG_ERR("Failed attribs check, key:%s\n", key_str);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = set_dispatch_attrib_handler(attr, object_type, functionality_vendor_attr, key, key_str))) {
        SX_LOG_ERR("Failed set attrib dispatch\n");
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_attributes(_In_ const sai_object_key_t             *key,
                                _In_ const char                         *key_str,
                                _In_ sai_object_type_t                   object_type,
                                _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                _In_ uint32_t                            attr_count,
                                _Inout_ sai_attribute_t                 *attr_list)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, object_type, functionality_vendor_attr,
                                    SAI_COMMON_API_GET))) {
        SX_LOG_ERR("Failed attribs check, key:%s\n", key_str);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             get_dispatch_attribs_handler(attr_count, attr_list, object_type, functionality_vendor_attr, key,
                                          key_str))) {
        if (MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST == status) {
            status = SAI_STATUS_BUFFER_OVERFLOW;
        } else {
            SX_LOG_ERR("Failed attribs dispatch\n");
        }
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bulk_attrs_validate(_In_ uint32_t                 object_count,
                                      _In_ const uint32_t          *attr_count,
                                      _In_ const sai_attribute_t  **attr_list_for_create,
                                      _In_ sai_attribute_t        **attr_list_for_get,
                                      _In_ const sai_attribute_t   *attr_list_for_set,
                                      _In_ sai_bulk_op_error_mode_t mode,
                                      _In_ sai_status_t            *object_statuses,
                                      _In_ sai_common_api_t         api,
                                      _Out_ bool                   *stop_on_error)
{
    assert((api == SAI_COMMON_API_BULK_CREATE) || (api == SAI_COMMON_API_BULK_REMOVE) ||
           (api == SAI_COMMON_API_BULK_GET) || (api == SAI_COMMON_API_BULK_SET));
    assert((api != SAI_COMMON_API_BULK_CREATE) || (!attr_list_for_get && !attr_list_for_set));
    assert((api != SAI_COMMON_API_BULK_REMOVE) ||
           (!attr_count && !attr_list_for_create && !attr_list_for_get && !attr_list_for_set));
    assert((api != SAI_COMMON_API_BULK_GET) || (!attr_list_for_create && !attr_list_for_set));
    assert((api != SAI_COMMON_API_BULK_SET) || (!attr_count && !attr_list_for_create && !attr_list_for_get));
    assert(stop_on_error);

    if (api == SAI_COMMON_API_BULK_CREATE) {
        if (!attr_count) {
            SX_LOG_ERR("attr_count is NULL\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if (!attr_list_for_create) {
            SX_LOG_ERR("attrs is NULL\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    if (api == SAI_COMMON_API_BULK_GET) {
        if (!attr_count) {
            SX_LOG_ERR("attr_count is NULL\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if (!attr_list_for_get) {
            SX_LOG_ERR("attrs is NULL\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    if (api == SAI_COMMON_API_BULK_SET) {
        if (!attr_list_for_set) {
            SX_LOG_ERR("attrs is NULL\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    if (0 == object_count) {
        SX_LOG_ERR("object_count is 0\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!object_statuses) {
        SX_LOG_ERR("object_statuses is NULL\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR < mode) {
        SX_LOG_ERR("Invalid value for sai_bulk_op_type_t - %d\n", mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *stop_on_error = (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bulk_create_attrs_validate(_In_ uint32_t                 object_count,
                                             _In_ const uint32_t          *attr_count,
                                             _In_ const sai_attribute_t  **attr_list,
                                             _In_ sai_bulk_op_error_mode_t mode,
                                             _In_ sai_status_t            *object_statuses,
                                             _Out_ bool                   *stop_on_error)
{
    return mlnx_bulk_attrs_validate(object_count, attr_count, attr_list, NULL, NULL, mode,
                                    object_statuses, SAI_COMMON_API_BULK_CREATE, stop_on_error);
}

sai_status_t mlnx_bulk_remove_attrs_validate(_In_ uint32_t                 object_count,
                                             _In_ sai_bulk_op_error_mode_t mode,
                                             _In_ sai_status_t            *object_statuses,
                                             _Out_ bool                   *stop_on_error)
{
    return mlnx_bulk_attrs_validate(object_count, NULL, NULL, NULL, NULL, mode,
                                    object_statuses, SAI_COMMON_API_BULK_REMOVE, stop_on_error);
}

sai_status_t mlnx_bulk_statuses_print(_In_ const char         *object_type_str,
                                      _In_ const sai_status_t *object_statuses,
                                      _In_ uint32_t            object_count,
                                      _In_ sai_common_api_t    api)
{
    const char *api_str;
    uint32_t    success_count, not_executed_count, failed_count, ii;

    assert(object_type_str);
    assert(object_statuses);
    assert((api == SAI_COMMON_API_BULK_CREATE) || (api == SAI_COMMON_API_BULK_REMOVE) ||
           (api == SAI_COMMON_API_BULK_GET) || (api == SAI_COMMON_API_BULK_SET));

    api_str = sai_metadata_enum_sai_common_api_t.valuesshortnames[api];

    success_count = not_executed_count = failed_count = 0;

    for (ii = 0; ii < object_count; ii++) {
        if (SAI_STATUS_SUCCESS == object_statuses[ii]) {
            success_count++;
            continue;
        }

        if (SAI_STATUS_NOT_EXECUTED == object_statuses[ii]) {
            not_executed_count++;
            continue;
        }

        failed_count++;
    }

    SX_LOG_NTC("[%s] %d %s: %d success, %d not executed, %d failed\n",
               api_str, object_count, object_type_str, success_count, not_executed_count, failed_count);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_ipv4_to_str(_In_ sai_ip4_t value,
                                    _In_ uint32_t  max_length,
                                    _Out_ char    *value_str,
                                    _Out_opt_ int *chars_written)
{
    inet_ntop(AF_INET, &value, value_str, max_length);

    if (NULL != chars_written) {
        *chars_written = (int)strlen(value_str);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_ipv6_to_str(_In_ sai_ip6_t value,
                                    _In_ uint32_t  max_length,
                                    _Out_ char    *value_str,
                                    _Out_opt_ int *chars_written)
{
    inet_ntop(AF_INET6, value, value_str, max_length);

    if (NULL != chars_written) {
        *chars_written = (int)strlen(value_str);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_ipaddr_to_str(_In_ sai_ip_address_t value,
                               _In_ uint32_t         max_length,
                               _Out_ char           *value_str,
                               _Out_opt_ int        *chars_written)
{
    int res;

    if (SAI_IP_ADDR_FAMILY_IPV4 == value.addr_family) {
        sai_ipv4_to_str(value.addr.ip4, max_length, value_str, chars_written);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == value.addr_family) {
        sai_ipv6_to_str(value.addr.ip6, max_length, value_str, chars_written);
    } else {
        res = snprintf(value_str, max_length, "Invalid ipaddr family %d", value.addr_family);
        if (NULL != chars_written) {
            *chars_written = res;
        }
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_ipprefix_to_str(_In_ sai_ip_prefix_t value, _In_ uint32_t max_length, _Out_ char *value_str)
{
    int      chars_written;
    uint32_t pos = 0;

    if (SAI_IP_ADDR_FAMILY_IPV4 == value.addr_family) {
        sai_ipv4_to_str(value.addr.ip4, max_length, value_str, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, " ");
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        sai_ipv4_to_str(value.mask.ip4, max_length - pos, value_str + pos, &chars_written);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == value.addr_family) {
        sai_ipv6_to_str(value.addr.ip6, max_length, value_str, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, " ");
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        sai_ipv6_to_str(value.mask.ip6, max_length - pos, value_str + pos, &chars_written);
    } else {
        snprintf(value_str, max_length, "Invalid addr family %d", value.addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sai_ip_address_to_sdk(_In_ const sai_ip_address_t *sai_addr, _Out_ sx_ip_addr_t *sdk_addr)
{
    int       ii;
    uint32_t *from, *to;

    if (SAI_IP_ADDR_FAMILY_IPV4 == sai_addr->addr_family) {
        /* SDK IPv4 is in host order, while SAI is in network order */
        sdk_addr->version          = SX_IP_VERSION_IPV4;
        sdk_addr->addr.ipv4.s_addr = ntohl(sai_addr->addr.ip4);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_addr->addr_family) {
        /* SDK IPv6 is 4*uint32. Each uint32 is in host order. Between uint32s there is network byte order */
        sdk_addr->version = SX_IP_VERSION_IPV6;
        from              = (uint32_t*)sai_addr->addr.ip6;
        to                = (uint32_t*)sdk_addr->addr.ipv6.s6_addr32;

        for (ii = 0; ii < 4; ii++) {
            to[ii] = ntohl(from[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sai_addr->addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sdk_ip_address_to_sai(_In_ const sx_ip_addr_t *sdk_addr, _Out_ sai_ip_address_t *sai_addr)
{
    int       ii;
    uint32_t *from, *to;

    if (SX_IP_VERSION_IPV4 == sdk_addr->version) {
        sai_addr->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sai_addr->addr.ip4    = htonl(sdk_addr->addr.ipv4.s_addr);
    } else if (SX_IP_VERSION_IPV6 == sdk_addr->version) {
        sai_addr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        from                  = (uint32_t*)sdk_addr->addr.ipv6.s6_addr32;
        to                    = (uint32_t*)sai_addr->addr.ip6;

        for (ii = 0; ii < 4; ii++) {
            to[ii] = htonl(from[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sdk_addr->version);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sai_ip_prefix_to_sdk(_In_ const sai_ip_prefix_t *sai_prefix,
                                                 _Out_ sx_ip_prefix_t       *sdk_prefix)
{
    int       ii;
    uint32_t *from_addr, *to_addr, *from_mask, *to_mask;

    if (SAI_IP_ADDR_FAMILY_IPV4 == sai_prefix->addr_family) {
        sdk_prefix->version                 = SX_IP_VERSION_IPV4;
        sdk_prefix->prefix.ipv4.addr.s_addr = ntohl(sai_prefix->addr.ip4);
        sdk_prefix->prefix.ipv4.mask.s_addr = ntohl(sai_prefix->mask.ip4);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_prefix->addr_family) {
        sdk_prefix->version = SX_IP_VERSION_IPV6;

        from_addr = (uint32_t*)sai_prefix->addr.ip6;
        to_addr   = (uint32_t*)sdk_prefix->prefix.ipv6.addr.s6_addr32;

        from_mask = (uint32_t*)sai_prefix->mask.ip6;
        to_mask   = (uint32_t*)sdk_prefix->prefix.ipv6.mask.s6_addr32;

        for (ii = 0; ii < 4; ii++) {
            to_addr[ii] = htonl(from_addr[ii]);
            to_mask[ii] = htonl(from_mask[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sai_prefix->addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_translate_sdk_ip_prefix_to_sai(_In_ const sx_ip_prefix_t *sdk_prefix,
                                                 _Out_ sai_ip_prefix_t     *sai_prefix)
{
    int       ii;
    uint32_t *from_addr, *to_addr, *from_mask, *to_mask;

    if (SX_IP_VERSION_IPV4 == sdk_prefix->version) {
        sai_prefix->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sai_prefix->addr.ip4    = htonl(sdk_prefix->prefix.ipv4.addr.s_addr);
        sai_prefix->mask.ip4    = htonl(sdk_prefix->prefix.ipv4.mask.s_addr);
    } else if (SX_IP_VERSION_IPV6 == sdk_prefix->version) {
        sai_prefix->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        from_addr               = (uint32_t*)sdk_prefix->prefix.ipv6.addr.s6_addr32;
        to_addr                 = (uint32_t*)sai_prefix->addr.ip6;

        from_mask = (uint32_t*)sdk_prefix->prefix.ipv6.mask.s6_addr32;
        to_mask   = (uint32_t*)sai_prefix->mask.ip6;

        for (ii = 0; ii < 4; ii++) {
            to_addr[ii] = htonl(from_addr[ii]);
            to_mask[ii] = htonl(from_mask[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sdk_prefix->version);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_nexthops_to_str(_In_ uint32_t               next_hop_count,
                                 _In_ const sai_object_id_t* nexthops,
                                 _In_ uint32_t               max_length,
                                 _Out_ char                 *str)
{
    uint32_t     ii;
    uint32_t     pos = 0;
    uint32_t     nexthop_id;
    sai_status_t status;

    pos += snprintf(str, max_length, "%u hops : [", next_hop_count);
    if (pos > max_length) {
        return SAI_STATUS_SUCCESS;
    }
    for (ii = 0; ii < next_hop_count; ii++) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(nexthops[ii], SAI_OBJECT_TYPE_NEXT_HOP, &nexthop_id, NULL))) {
            snprintf(str + pos, max_length - pos, " invalid next hop]");
            return status;
        }

        pos += snprintf(str + pos, max_length - pos, " %u", nexthop_id);
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
    }
    snprintf(str + pos, max_length - pos, "]");

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_qos_map_to_str(_In_ const sai_qos_map_list_t *qosmap,
                                _In_ sai_qos_map_type_t        type,
                                _In_ uint32_t                  max_length,
                                _Out_ char                    *value_str)
{
    sai_qos_map_t *list;
    uint32_t       count;
    sai_status_t   status = SAI_STATUS_SUCCESS;
    uint32_t       pos    = 0;
    uint32_t       ii;

    if (NULL == value_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *value_str = '\0';

    if (!qosmap) {
        return SAI_STATUS_SUCCESS;
    }

    list  = qosmap->list;
    count = qosmap->count;

    if (!count || !list) {
        return SAI_STATUS_SUCCESS;
    }

    pos += snprintf(value_str + pos, max_length - pos, ", type %u, ", type);
    if (pos > max_length) {
        return SAI_STATUS_SUCCESS;
    }

    pos += snprintf(value_str + pos, max_length - pos, "%u : [", count);
    if (pos > max_length) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < count; ii++) {
        switch (type) {
        case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dot1p, list[ii].value.tc);
            break;

        case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dot1p, list[ii].value.color);
            break;

        case SAI_QOS_MAP_TYPE_DSCP_TO_TC:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dscp, list[ii].value.tc);
            break;

        case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dscp, list[ii].value.color);
            break;

        case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.tc, list[ii].value.queue_index);
            break;

        case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:
            pos += snprintf(value_str + pos, max_length - pos, "(%u,%u)->%u",
                            list[ii].key.tc, list[ii].key.color,
                            list[ii].value.dscp);
            break;

        case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:
            pos += snprintf(value_str + pos, max_length - pos, "(%u,%u)->%u",
                            list[ii].key.tc, list[ii].key.color,
                            list[ii].value.dot1p);
            break;

        case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.tc, list[ii].value.pg);
            break;

        case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.prio, list[ii].value.pg);
            break;

        case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.prio, list[ii].value.queue_index);
            break;

        default:
            status = SAI_STATUS_NOT_SUPPORTED;
            break;
        }

        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        if (ii < count - 1) {
            pos += snprintf(value_str + pos, max_length - pos, ",");
        }
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
    }

    snprintf(value_str + pos, max_length - pos, "]");
    return status;
}

static sai_status_t sai_qos_map_to_str_oid(_In_ sai_object_id_t       qos_map_id,
                                           _In_ sai_attribute_value_t value,
                                           _In_ uint32_t              max_length,
                                           _Out_ char                *value_str)
{
    mlnx_qos_map_t *qos_map;
    sai_status_t    status;

    if (NULL == value_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *value_str = '\0';

    if (!value.qosmap.count || !value.qosmap.list) {
        return SAI_STATUS_SUCCESS;
    }

    sai_db_read_lock();

    status = mlnx_qos_map_get_by_id(qos_map_id, &qos_map);
    if (status != SAI_STATUS_SUCCESS) {
        sai_db_unlock();
        return status;
    }

    sai_db_unlock();

    return sai_qos_map_to_str(&value.qosmap, qos_map->type, max_length, value_str);
}

static uint32_t sai_oid_to_str(sai_object_id_t oid, uint32_t opt, uint32_t max_length, char *value_str)
{
    mlnx_object_id_t *mlnx_id = (mlnx_object_id_t*)&oid;

    return snprintf(value_str, max_length, "%s,(%d:%d),%x,%02x%02x,%x",
                    SAI_TYPE_STR(mlnx_id->object_type),
                    mlnx_id->field.swid, mlnx_id->field.sub_type, mlnx_id->id.u32,
                    mlnx_id->ext.bytes[1], mlnx_id->ext.bytes[0], opt);
}

static uint32_t sai_attr_capability_to_str(_In_ const sai_attr_capability_t  *val,
                                           _In_ uint32_t                      max_length,
                                           _Out_ char                        *value_str)
{
    return snprintf(value_str, max_length, "create_implemented: %s, set_implemented: %s, get_implemented: %s",
                    MLNX_UTILS_BOOL_TO_STR(val->create_implemented), MLNX_UTILS_BOOL_TO_STR(val->set_implemented),
                    MLNX_UTILS_BOOL_TO_STR(val->get_implemented));
}

static sai_status_t sai_value_to_str(_In_ sai_attribute_value_t value,
                                     _In_ sai_attr_value_type_t type,
                                     _In_ uint32_t              max_length,
                                     _Out_ char                *value_str)
{
    uint32_t ii;
    uint32_t pos = 0;
    uint32_t count;
    int      chars_written;

    if (NULL == value_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *value_str = '\0';

    switch (type) {
    case SAI_ATTR_VALUE_TYPE_BOOL:
        snprintf(value_str, max_length, "%s", MLNX_UTILS_BOOL_TO_STR(value.booldata));
        break;

    case SAI_ATTR_VALUE_TYPE_CHARDATA:
        snprintf(value_str, max_length, "%s", value.chardata);
        break;

    case SAI_ATTR_VALUE_TYPE_UINT8:
        snprintf(value_str, max_length, "%u", value.u8);
        break;

    case SAI_ATTR_VALUE_TYPE_INT8:
        snprintf(value_str, max_length, "%d", value.s8);
        break;

    case SAI_ATTR_VALUE_TYPE_UINT16:
        snprintf(value_str, max_length, "%u", value.u16);
        break;

    case SAI_ATTR_VALUE_TYPE_INT16:
        snprintf(value_str, max_length, "%d", value.s16);
        break;

    case SAI_ATTR_VALUE_TYPE_UINT32:
        snprintf(value_str, max_length, "%u", value.u32);
        break;

    case SAI_ATTR_VALUE_TYPE_INT32:
        snprintf(value_str, max_length, "%d", value.s32);
        break;

    case SAI_ATTR_VALUE_TYPE_UINT64:
        snprintf(value_str, max_length, "%" PRIu64, value.u64);
        break;

    case SAI_ATTR_VALUE_TYPE_INT64:
        snprintf(value_str, max_length, "%" PRId64, value.s64);
        break;

    case SAI_ATTR_VALUE_TYPE_POINTER:
        snprintf(value_str, max_length, "%" PRIx64, (int64_t)value.ptr);
        break;

    case SAI_ATTR_VALUE_TYPE_MAC:
        snprintf(value_str, max_length, "[%02x:%02x:%02x:%02x:%02x:%02x]",
                 value.mac[0],
                 value.mac[1],
                 value.mac[2],
                 value.mac[3],
                 value.mac[4],
                 value.mac[5]);
        break;

    /* IP is in network order */
    case SAI_ATTR_VALUE_TYPE_IPV4:
        sai_ipv4_to_str(value.ip4, max_length, value_str, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_IPV6:
        sai_ipv6_to_str(value.ip6, max_length, value_str, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_IP_ADDRESS:
        sai_ipaddr_to_str(value.ipaddr, max_length, value_str, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_IP_PREFIX:
        sai_ipprefix_to_str(value.ipprefix, max_length, value_str);
        break;

    case SAI_ATTR_VALUE_TYPE_OBJECT_ID:
        sai_oid_to_str(value.oid, 0, max_length, value_str);
        break;

    case SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
    case SAI_ATTR_VALUE_TYPE_UINT8_LIST:
    case SAI_ATTR_VALUE_TYPE_INT8_LIST:
    case SAI_ATTR_VALUE_TYPE_UINT16_LIST:
    case SAI_ATTR_VALUE_TYPE_INT16_LIST:
    case SAI_ATTR_VALUE_TYPE_UINT32_LIST:
    case SAI_ATTR_VALUE_TYPE_INT32_LIST:
    case SAI_ATTR_VALUE_TYPE_VLAN_LIST:
    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_LIST:
    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST:
    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_LIST:
    case SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
    case SAI_ATTR_VALUE_TYPE_MAP_LIST:
    case SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
    case SAI_ATTR_VALUE_TYPE_TLV_LIST:
    case SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
        if (SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY == type) {
            pos += snprintf(value_str,
                            max_length,
                            "%d.",
                            value.aclcapability.is_action_list_mandatory);
        }
        if ((SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_LIST == type) ||
            (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST == type)) {
            pos += snprintf(value_str, max_length, "%u", value.aclfield.enable);
        }
        if (SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_LIST == type) {
            pos += snprintf(value_str, max_length, "%u", value.aclaction.enable);
        }
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }

        count = (SAI_ATTR_VALUE_TYPE_OBJECT_LIST == type) ? value.objlist.count :
                (SAI_ATTR_VALUE_TYPE_UINT8_LIST == type) ? value.u8list.count :
                (SAI_ATTR_VALUE_TYPE_INT8_LIST == type) ? value.s8list.count :
                (SAI_ATTR_VALUE_TYPE_UINT16_LIST == type) ? value.u16list.count :
                (SAI_ATTR_VALUE_TYPE_INT16_LIST == type) ? value.s16list.count :
                (SAI_ATTR_VALUE_TYPE_UINT32_LIST == type) ? value.u32list.count :
                (SAI_ATTR_VALUE_TYPE_INT32_LIST == type) ? value.s32list.count :
                (SAI_ATTR_VALUE_TYPE_VLAN_LIST == type) ? value.vlanlist.count :
                (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_LIST == type) ? value.aclfield.data.objlist.count :
                (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST == type) ? value.aclfield.data.u8list.count :
                (SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_LIST == type) ? value.aclaction.parameter.objlist.count :
                (SAI_ATTR_VALUE_TYPE_MAP_LIST == type) ? value.maplist.count :
                (SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST == type) ? value.aclresource.count :
                (SAI_ATTR_VALUE_TYPE_TLV_LIST == type) ? value.tlvlist.count :
                (SAI_ATTR_VALUE_TYPE_SEGMENT_LIST == type) ? value.segmentlist.count :
                value.aclcapability.action_list.count;
        pos += snprintf(value_str + pos, max_length - pos, "%u : [", count);
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }

        for (ii = 0; ii < count; ii++) {
            if (SAI_ATTR_VALUE_TYPE_OBJECT_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %" PRIx64, value.objlist.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_UINT8_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.u8list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_INT8_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.s8list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_UINT16_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.u16list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_INT16_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.s16list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_UINT32_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.u32list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_INT32_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.s32list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_VLAN_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.vlanlist.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %" PRIx64, value.aclfield.data.objlist.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %02x,%02x",
                                value.aclfield.data.u8list.list[ii], value.aclfield.mask.u8list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_LIST == type) {
                pos +=
                    snprintf(value_str + pos, max_length - pos, " %" PRIx64,
                             value.aclaction.parameter.objlist.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_MAP_LIST == type) {
                pos += snprintf(value_str + pos,
                                max_length - pos,
                                " %u->%d",
                                value.maplist.list[ii].key,
                                value.maplist.list[ii].value);
            } else if (SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.aclcapability.action_list.list[ii]);
            } else if (SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST == type) {
                pos += snprintf(value_str + pos,
                                max_length - pos,
                                " %d,%d,%u",
                                value.aclresource.list[ii].stage,
                                value.aclresource.list[ii].bind_point,
                                value.aclresource.list[ii].avail_num);
            } else if (SAI_ATTR_VALUE_TYPE_TLV_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.tlvlist.list[ii].tlv_type);
            } else if (SAI_ATTR_VALUE_TYPE_SEGMENT_LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " ");
                if (pos > max_length) {
                    return SAI_STATUS_SUCCESS;
                }
                sai_ipv6_to_str(value.segmentlist.list[ii], max_length - pos, value_str + pos, &chars_written);
                pos += chars_written;
            }

            if (pos > max_length) {
                return SAI_STATUS_SUCCESS;
            }
        }
        snprintf(value_str + pos, max_length - pos, "]");
        break;

    case SAI_ATTR_VALUE_TYPE_UINT32_RANGE:
        snprintf(value_str, max_length, "[%u,%u]", value.u32range.min, value.u32range.max);
        break;

    case SAI_ATTR_VALUE_TYPE_INT32_RANGE:
        snprintf(value_str, max_length, "[%d,%d]", value.s32range.min, value.s32range.max);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_BOOL:
        snprintf(value_str,
                 max_length,
                 "%s,%02x",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.booldata);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8:
        snprintf(value_str,
                 max_length,
                 "%s,%02x,%02x",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.u8,
                 value.aclfield.mask.u8);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT16:
        snprintf(value_str,
                 max_length,
                 "%s,%04x,%04x",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.u16,
                 value.aclfield.mask.u16);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT32:
        snprintf(value_str,
                 max_length,
                 "%s,%08x,%08x",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.u32,
                 value.aclfield.mask.u32);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_INT8:
        snprintf(value_str,
                 max_length,
                 "%s,%02x,%02x",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.s8,
                 value.aclfield.mask.s8);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_INT16:
        snprintf(value_str,
                 max_length,
                 "%s,%04x,%04x",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.s16,
                 value.aclfield.mask.s16);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_INT32:
        snprintf(value_str,
                 max_length,
                 "%s,%08x,%08x",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.s32,
                 value.aclfield.mask.s32);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_MAC:
        snprintf(value_str, max_length, "%s,[%02x:%02x:%02x:%02x:%02x:%02x],[%02x:%02x:%02x:%02x:%02x:%02x]",
                 MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable),
                 value.aclfield.data.mac[0],
                 value.aclfield.data.mac[1],
                 value.aclfield.data.mac[2],
                 value.aclfield.data.mac[3],
                 value.aclfield.data.mac[4],
                 value.aclfield.data.mac[5],
                 value.aclfield.mask.mac[0],
                 value.aclfield.mask.mac[1],
                 value.aclfield.mask.mac[2],
                 value.aclfield.mask.mac[3],
                 value.aclfield.mask.mac[4],
                 value.aclfield.mask.mac[5]);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_IPV4:
        pos += snprintf(value_str, max_length, "%s,", MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable));
        sai_ipv4_to_str(value.aclfield.data.ip4, max_length - pos, value_str + pos, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, ",");
        sai_ipv4_to_str(value.aclfield.mask.ip4, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_IPV6:
        pos += snprintf(value_str, max_length, "%s,", MLNX_UTILS_BOOL_TO_STR(value.aclfield.enable));
        sai_ipv6_to_str(value.aclfield.data.ip6, max_length - pos, value_str + pos, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, ",");
        sai_ipv6_to_str(value.aclfield.mask.ip6, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_ID:
        sai_oid_to_str(value.aclfield.data.oid, value.aclfield.enable, max_length, value_str);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_BOOL:
        snprintf(value_str, max_length, "%s,%s", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 MLNX_UTILS_BOOL_TO_STR(value.aclaction.parameter.booldata));
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_UINT8:
        snprintf(value_str, max_length, "%s,%u", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 value.aclaction.parameter.u8);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_UINT16:
        snprintf(value_str, max_length, "%s,%u", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 value.aclaction.parameter.u16);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_UINT32:
        snprintf(value_str, max_length, "%s,%u", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 value.aclaction.parameter.u32);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_INT8:
        snprintf(value_str, max_length, "%s,%d", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 value.aclaction.parameter.s8);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_INT16:
        snprintf(value_str, max_length, "%s,%d", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 value.aclaction.parameter.s16);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_INT32:
        snprintf(value_str, max_length, "%s,%d", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 value.aclaction.parameter.s32);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_MAC:
        snprintf(value_str, max_length, "%s,[%02x:%02x:%02x:%02x:%02x:%02x]",
                 MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable),
                 value.aclaction.parameter.mac[0],
                 value.aclaction.parameter.mac[1],
                 value.aclaction.parameter.mac[2],
                 value.aclaction.parameter.mac[3],
                 value.aclaction.parameter.mac[4],
                 value.aclaction.parameter.mac[5]);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_IPV4:
        pos += snprintf(value_str, max_length, "%u,", value.aclaction.enable);
        sai_ipv4_to_str(value.aclaction.parameter.ip4, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_IPV6:
        pos += snprintf(value_str, max_length, "%s,", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable));
        sai_ipv6_to_str(value.aclaction.parameter.ip6, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_IP_ADDRESS:
        pos += snprintf(value_str, max_length, "%s,", MLNX_UTILS_BOOL_TO_STR(value.aclaction.enable));
        sai_ipaddr_to_str(value.aclaction.parameter.ipaddr, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_ID:
        sai_oid_to_str(value.aclaction.parameter.oid, value.aclaction.enable, max_length, value_str);
        break;

    default:
        snprintf(value_str, max_length, "Invalid/Unsupported value type %d", type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attr_meta_enum_value_to_str(_In_ const sai_attr_metadata_t *meta_data,
                                                    _In_ sai_int32_t                value,
                                                    _In_ uint32_t                   max_length,
                                                    _Out_ char                     *value_str)
{
    uint32_t index;

    assert(meta_data);
    assert(value_str);

    for (index = 0; index < meta_data->enummetadata->valuescount; index++) {
        if (value == meta_data->enummetadata->values[index]) {
            snprintf(value_str, max_length, "%s", meta_data->enummetadata->valuesshortnames[index]);
            return SAI_STATUS_SUCCESS;
        }
    }

    snprintf(value_str, max_length, "invalid %d", value);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attr_meta_enum_to_str(_In_ const sai_attr_metadata_t   *meta_data,
                                              _In_ const sai_attribute_value_t *value,
                                              _In_ uint32_t                     max_length,
                                              _Out_ char                       *value_str)
{
    sai_int32_t enum_value;
    uint32_t    pos;
    bool        acl_value_present, acl_enable_value;

    assert(meta_data);
    assert(value);
    assert(value_str);

    acl_value_present = false;

    if (meta_data->isaclfield) {
        enum_value        = value->aclfield.data.s32;
        acl_value_present = true;
        acl_enable_value  = value->aclfield.enable;
    } else if (meta_data->isaclaction) {
        enum_value        = value->aclaction.parameter.s32;
        acl_value_present = true;
        acl_enable_value  = value->aclaction.enable;
    } else {
        enum_value = value->s32;
    }

    if (acl_value_present) {
        pos         = snprintf(value_str, max_length, "%s,", MLNX_UTILS_BOOL_TO_STR(acl_enable_value));
        max_length -= pos;
        value_str  += pos;
    }

    return sai_attr_meta_enum_value_to_str(meta_data, enum_value, max_length, value_str);
}

static sai_status_t sai_attr_meta_enumlist_s32_to_str(_In_ const sai_attr_metadata_t *meta_data,
                                                       _In_ const sai_s32_list_t     *values,
                                                       _In_ uint32_t                  max_length,
                                                       _Out_ char                    *list_str)
{
    sai_status_t status;
    char         enum_str[MAX_VALUE_STR_LEN] = {0};
    uint32_t     pos = 0, ii;

    if (0 == values->count) {
        snprintf(list_str + pos, max_length - pos, "[]");
        return SAI_STATUS_SUCCESS;
    }

    pos += snprintf(list_str + pos, max_length - pos, "[");

    for (ii = 0; ii < values->count; ii++) {
        status = sai_attr_meta_enum_value_to_str(meta_data, values->list[ii], MAX_VALUE_STR_LEN, enum_str);
        if (SAI_ERR(status)) {
            return status;
        }

        pos += snprintf(list_str + pos, max_length - pos, "%s ", enum_str);
        if (pos > max_length) {
            break;
        }
    }

    if (pos < max_length) {
        snprintf(list_str + pos, max_length - pos, "]");
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_attr_meta_enumlist_to_str(_In_ const sai_attr_metadata_t   *meta_data,
                                                  _In_ const sai_attribute_value_t *value,
                                                  _In_ uint32_t                     max_length,
                                                  _Out_ char                       *list_str)
{
    const sai_s32_list_t *values;
    uint32_t              pos;
    bool                  acl_value_present, acl_enable_value;

    assert(meta_data);
    assert(value);
    assert(list_str);

    pos               = 0;
    values            = &value->s32list;
    acl_value_present = false;

    if (meta_data->isaclfield) {
        acl_value_present = true;
        acl_enable_value  = value->aclfield.enable;
    } else if (meta_data->isaclaction) {
        acl_value_present = true;
        acl_enable_value  = value->aclaction.enable;
    }

    if (acl_value_present) {
        pos = snprintf(list_str, max_length, "%s,", MLNX_UTILS_BOOL_TO_STR(acl_enable_value));
    }

    return sai_attr_meta_enumlist_s32_to_str(meta_data, values, max_length - pos, list_str + pos);
}

static sai_status_t sai_attr_metadata_to_str(_In_ const sai_attr_metadata_t   *meta_data,
                                             _In_ const sai_attribute_value_t *value,
                                             _In_ uint32_t                     max_length,
                                             _Out_ char                       *value_str)
{
    sai_status_t status;

    assert(meta_data);
    assert(value);
    assert(value_str);

    if (meta_data->isenum) {
        status = sai_attr_meta_enum_to_str(meta_data, value, max_length, value_str);
        if (SAI_ERR(status)) {
            return status;
        }
    } else if (meta_data->isenumlist) {
        status = sai_attr_meta_enumlist_to_str(meta_data, value, max_length, value_str);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = sai_value_to_str(*value, meta_data->attrvaluetype,
                                  max_length, value_str);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_attr_list_to_str(_In_ uint32_t               attr_count,
                                  _In_ const sai_attribute_t *attr_list,
                                  _In_ sai_object_type_t      object_type,
                                  _In_ uint32_t               max_length,
                                  _Out_ char                 *list_str)
{
    sai_status_t               status;
    char                       value_str[MAX_VALUE_STR_LEN] = {0};
    uint32_t                   pos, ii;
    const sai_attr_metadata_t *meta_data;
    const char                *short_attr_name;

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == list_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (0 == attr_count) {
        snprintf(list_str, max_length, "empty list");
        return SAI_STATUS_SUCCESS;
    }

    if (!sai_metadata_is_object_type_valid(object_type)) {
        SX_LOG_ERR("Invalid object type (%d)\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    pos = 0;
    for (ii = 0; ii < attr_count; ii++) {
        meta_data = mlnx_sai_attr_metadata_get_impl(object_type, attr_list[ii].id);
        if (NULL == meta_data) {
            SX_LOG_ERR("Failed to fetch meta data for object_type [%s] attr_id (%d)\n", SAI_TYPE_STR(
                           object_type), attr_list[ii].id);
            return SAI_STATUS_FAILURE;
        }

        status = sai_attr_metadata_to_str(meta_data, &attr_list[ii].value, MAX_VALUE_STR_LEN, value_str);
        if (SAI_ERR(status)) {
            return status;
        }

        status = sai_attribute_short_name_fetch(object_type, attr_list[ii].id, &short_attr_name);
        if (SAI_ERR(status)) {
            return status;
        }

        pos += snprintf(list_str + pos,
                        max_length - pos,
                        "#%u %s=%s ",
                        ii,
                        short_attr_name,
                        value_str);
        if (pos > max_length) {
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_trap_action_to_sdk(sai_int32_t       action,
                                                   sx_trap_action_t *trap_action,
                                                   uint32_t          param_index)
{
    if (NULL == trap_action) {
        SX_LOG_ERR("NULL trap action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_PACKET_ACTION_FORWARD:
        *trap_action = SX_TRAP_ACTION_IGNORE;
        break;

    case SAI_PACKET_ACTION_TRAP:
        *trap_action = SX_TRAP_ACTION_TRAP_2_CPU;
        break;

    case SAI_PACKET_ACTION_LOG:
        *trap_action = SX_TRAP_ACTION_MIRROR_2_CPU;
        break;

    case SAI_PACKET_ACTION_DROP:
        *trap_action = SX_TRAP_ACTION_DISCARD;
        break;

    default:
        SX_LOG_ERR("Invalid packet action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_router_action_to_sdk(sai_int32_t         action,
                                                     sx_router_action_t *router_action,
                                                     uint32_t            param_index)
{
    if (NULL == router_action) {
        SX_LOG_ERR("NULL router action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_PACKET_ACTION_FORWARD:
        *router_action = SX_ROUTER_ACTION_FORWARD;
        break;

    case SAI_PACKET_ACTION_TRAP:
        *router_action = SX_ROUTER_ACTION_TRAP;
        break;

    case SAI_PACKET_ACTION_LOG:
        *router_action = SX_ROUTER_ACTION_MIRROR;
        break;

    case SAI_PACKET_ACTION_DROP:
        *router_action = SX_ROUTER_ACTION_DROP;
        break;

    default:
        SX_LOG_ERR("Invalid packet action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sdk_router_action_to_sai(sx_router_action_t router_action, sai_int32_t *sai_action)
{
    if (NULL == sai_action) {
        SX_LOG_ERR("NULL sai action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (router_action) {
    case SX_ROUTER_ACTION_FORWARD:
        *sai_action = SAI_PACKET_ACTION_FORWARD;
        break;

    case SX_ROUTER_ACTION_TRAP:
        *sai_action = SAI_PACKET_ACTION_TRAP;
        break;

    case SX_ROUTER_ACTION_MIRROR:
        *sai_action = SAI_PACKET_ACTION_LOG;
        break;

    case SX_ROUTER_ACTION_DROP:
        *sai_action = SAI_PACKET_ACTION_DROP;
        break;

    default:
        SX_LOG_ERR("Unexpected router action %d\n", router_action);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_stats_mode_to_sdk(sai_stats_mode_t sai_mode, sx_access_cmd_t *sdk_mode)
{
    if (NULL == sdk_mode) {
        SX_LOG_ERR("NULL sdk mode value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (sai_mode) {
    case SAI_STATS_MODE_READ:
        *sdk_mode = SX_ACCESS_CMD_READ;
        break;

    case SAI_STATS_MODE_READ_AND_CLEAR:
        *sdk_mode = SX_ACCESS_CMD_READ_CLEAR;
        break;

    default:
        SX_LOG_ERR("Invalid stats mode %d\n", sai_mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_object_to_type(sai_object_id_t   object_id,
                                 sai_object_type_t type,
                                 uint32_t         *data,
                                 uint8_t           extended_data[])
{
    mlnx_object_id_t *mlnx_object_id = (mlnx_object_id_t*)&object_id;

    if (NULL == data) {
        SX_LOG_ERR("NULL data value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (type != mlnx_object_id->object_type) {
        SX_LOG_ERR("Expected object %s got %s\n", SAI_TYPE_STR(type), SAI_TYPE_STR(mlnx_object_id->object_type));
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *data = mlnx_object_id->id.u32;
    if (extended_data) {
        memcpy(extended_data, mlnx_object_id->ext.bytes, EXTENDED_DATA_SIZE);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_object_id_to_sai(sai_object_type_t type, mlnx_object_id_t *mlnx_object_id,
                                   sai_object_id_t *object_id)
{
    if (object_id == NULL) {
        SX_LOG_ERR("NULL object id value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    mlnx_object_id->object_type = type;
    memcpy(object_id, mlnx_object_id, sizeof(*mlnx_object_id));

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_to_mlnx_object_id(sai_object_type_t type, sai_object_id_t object_id, mlnx_object_id_t *mlnx_object_id)
{
    mlnx_object_id_t *mlnx_sai_oid = (mlnx_object_id_t*)&object_id;

    if (mlnx_sai_oid == NULL) {
        SX_LOG_ERR("NULL object id value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (mlnx_sai_oid->object_type != type) {
        SX_LOG_ERR("Invalid object type %u expected %u\n", mlnx_sai_oid->object_type, type);
        return SAI_STATUS_INVALID_OBJECT_TYPE;
    }

    memcpy(mlnx_object_id, mlnx_sai_oid, sizeof(*mlnx_object_id));

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_object(sai_object_type_t type,
                                uint32_t          data,
                                uint8_t           extended_data[],
                                sai_object_id_t  *object_id)
{
    mlnx_object_id_t *mlnx_object_id = (mlnx_object_id_t*)object_id;

    /* guarntee same size for general object id and mellanox prvivate implementation */
    int __attribute__((unused)) dummy[(sizeof(mlnx_object_id_t) == sizeof(sai_object_id_t) ? 1 : -1)];

    UNREFERENCED_PARAMETER(dummy);

    if (NULL == object_id) {
        SX_LOG_ERR("NULL object id value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!sai_metadata_is_object_type_valid(type)) {
        SX_LOG_ERR("Unknown object type %d\n", type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memset(mlnx_object_id, 0, sizeof(*mlnx_object_id));
    mlnx_object_id->id.u32      = data;
    mlnx_object_id->object_type = type;
    if (extended_data) {
        memcpy(mlnx_object_id->ext.bytes, extended_data, EXTENDED_DATA_SIZE);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_object_to_log_port(sai_object_id_t object_id, sx_port_log_id_t *port_id)
{
    sai_object_type_t type = sai_object_type_query(object_id);

    if ((type != SAI_OBJECT_TYPE_PORT) && (type != SAI_OBJECT_TYPE_LAG)) {
        SX_LOG_ERR("Object type %s is not LAG nor Port\n", SAI_TYPE_STR(type));
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return mlnx_object_to_type(object_id, type, port_id, NULL);
}

sai_status_t mlnx_log_port_to_object(sx_port_log_id_t port_id, sai_object_id_t *object_id)
{
    sai_object_type_t type;

    if (SX_PORT_TYPE_ID_GET(port_id) == SX_PORT_TYPE_NETWORK) {
        type = SAI_OBJECT_TYPE_PORT;
    } else if (SX_PORT_TYPE_ID_GET(port_id) == SX_PORT_TYPE_LAG) {
        type = SAI_OBJECT_TYPE_LAG;
    } else {
        SX_LOG_ERR("Logical port id %x is not LAG nor Port\n", port_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return mlnx_create_object(type, port_id, NULL, object_id);
}

sai_status_t mlnx_create_queue_object(_In_ sx_port_log_id_t port_id, _In_ uint8_t index, _Out_ sai_object_id_t *id)
{
    uint8_t ext_data[EXTENDED_DATA_SIZE];

    memset(ext_data, 0, EXTENDED_DATA_SIZE);
    ext_data[0] = index;
    return mlnx_create_object(SAI_OBJECT_TYPE_QUEUE, port_id, ext_data, id);
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_queue_parse_id(_In_ sai_object_id_t id, _Out_ sx_port_log_id_t *port_id, _Out_ uint8_t *queue_index)
{
    uint8_t      ext_data[EXTENDED_DATA_SIZE];
    sai_status_t status;

    status = mlnx_object_to_type(id, SAI_OBJECT_TYPE_QUEUE, port_id, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    if (queue_index) {
        *queue_index = ext_data[0];
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_sched_group(_In_ sx_port_log_id_t  port_id,
                                     _In_ uint8_t           level,
                                     _In_ uint8_t           index,
                                     _Out_ sai_object_id_t *id)
{
    uint8_t ext_data[EXTENDED_DATA_SIZE];

    memset(ext_data, 0, EXTENDED_DATA_SIZE);
    ext_data[0] = level;
    ext_data[1] = index;
    return mlnx_create_object(SAI_OBJECT_TYPE_SCHEDULER_GROUP, port_id, ext_data, id);
}

_Success_(return == SAI_STATUS_SUCCESS)
sai_status_t mlnx_sched_group_parse_id(_In_ sai_object_id_t    id,
                                       _Out_ sx_port_log_id_t *port_id_ptr,
                                       _Out_ uint8_t          *level_ptr,
                                       _Out_ uint8_t          *index_ptr)
{
    uint8_t          ext_data[EXTENDED_DATA_SIZE];
    sx_port_log_id_t port_id;
    sai_status_t     status;

    status = mlnx_object_to_type(id, SAI_OBJECT_TYPE_SCHEDULER_GROUP, &port_id, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    if (port_id_ptr) {
        *port_id_ptr = port_id;
    }
    if (level_ptr) {
        *level_ptr = ext_data[0];
    }
    if (index_ptr) {
        *index_ptr = ext_data[1];
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_utils_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fill_genericlist(size_t element_size, const void *data, uint32_t count, void *list)
{
    /* all list objects have same field count in the beginning of the object, and then different data,
     * so can be casted to one type */
    sai_object_list_t *objlist = list;
    sai_status_t       status;

    if (NULL == data) {
        SX_LOG_ERR("NULL data value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == list) {
        SX_LOG_ERR("NULL list value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (0 == element_size) {
        SX_LOG_ERR("Zero element size\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (count > objlist->count) {
        if (0 == objlist->count) {
            status = MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST;
        } else {
            status = SAI_STATUS_BUFFER_OVERFLOW;
        }
        SX_LOG((0 == objlist->count) ? SX_LOG_INFO : SX_LOG_ERROR,
               "Insufficient list buffer size. Allocated %u needed %u\n", objlist->count, count);
        objlist->count = count;
        return status;
    }

    objlist->count = count;
    memcpy(objlist->list, data, count * element_size);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_fill_objlist(const sai_object_id_t *data, uint32_t count, sai_object_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(sai_object_id_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_u8list(const uint8_t *data, uint32_t count, sai_u8_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(uint8_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_s8list(const int8_t *data, uint32_t count, sai_s8_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(int8_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_u16list(const uint16_t *data, uint32_t count, sai_u16_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(uint16_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_s16list(const int16_t *data, uint32_t count, sai_s16_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(int16_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_u32list(const uint32_t *data, uint32_t count, sai_u32_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(uint32_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_s32list(const int32_t *data, uint32_t count, sai_s32_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(int32_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_vlanlist(const sai_vlan_id_t *data, uint32_t count, sai_vlan_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(sai_vlan_id_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_aclresourcelist(const sai_acl_resource_t *data, uint32_t count, sai_acl_resource_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(sai_acl_resource_t), (void*)data, count, (void*)list);
}

bool mlnx_route_entries_are_equal(_In_ const sai_route_entry_t *u1, _In_ const sai_route_entry_t *u2)
{
    if ((NULL == u1) && (NULL == u2)) {
        return true;
    }

    if ((NULL == u1) || (NULL == u2)) {
        return false;
    }

    if (u1->vr_id != u2->vr_id) {
        return false;
    }
    if (u1->destination.addr_family != u2->destination.addr_family) {
        return false;
    }

    if (SAI_IP_ADDR_FAMILY_IPV4 == u1->destination.addr_family) {
        if (u1->destination.addr.ip4 != u2->destination.addr.ip4) {
            return false;
        }
        if (u1->destination.mask.ip4 != u2->destination.mask.ip4) {
            return false;
        }
    } else {
        if (memcmp(u1->destination.addr.ip6, u2->destination.addr.ip6, sizeof(u1->destination.addr.ip6))) {
            return false;
        }
        if (memcmp(u1->destination.addr.ip6, u2->destination.addr.ip6, sizeof(u1->destination.addr.ip6))) {
            return false;
        }
    }

    return true;
}

sai_status_t mlnx_attribute_value_list_size_check(_Inout_ uint32_t *out_size, _In_ uint32_t in_size)
{
    sx_log_severity_t log_severity;
    sai_status_t      status = SAI_STATUS_SUCCESS;

    assert(out_size);

    if (*out_size < in_size) {
        if (0 == *out_size) {
            log_severity = SX_LOG_NOTICE;
            status       = MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST;
        } else {
            log_severity = SX_LOG_ERROR;
            status       = SAI_STATUS_BUFFER_OVERFLOW;
        }

        SX_LOG(log_severity, " Re-allocate list size as list size is not large enough - needed (%d), provided (%d)\n",
               in_size, *out_size);
    }

    *out_size = in_size;

    return status;
}

static sai_status_t mlnx_fdb_or_route_action_find(_In_ sai_object_type_t type,
                                                  _In_ const void       *entry,
                                                  _Out_ uint32_t        *index)
{
    uint32_t               ii;
    bool                   equal;
    const sai_fdb_entry_t *saved_fdb_entry, *targed_fdb_entry;

    assert((SAI_OBJECT_TYPE_FDB_ENTRY == type) || (SAI_OBJECT_TYPE_ROUTE_ENTRY == type));

    for (ii = 0; ii < g_sai_db_ptr->fdb_or_route_actions.count; ii++) {
        if (g_sai_db_ptr->fdb_or_route_actions.actions[ii].type != type) {
            continue;
        }

        if (SAI_OBJECT_TYPE_FDB_ENTRY == type) {
            saved_fdb_entry  = &g_sai_db_ptr->fdb_or_route_actions.actions[ii].fdb_entry;
            targed_fdb_entry = entry;

            equal = ((0 == memcmp(saved_fdb_entry->mac_address, targed_fdb_entry->mac_address, sizeof(sai_mac_t))) &&
                     (saved_fdb_entry->bv_id == targed_fdb_entry->bv_id));
        } else {
            equal = mlnx_route_entries_are_equal(&g_sai_db_ptr->fdb_or_route_actions.actions[ii].route_entry, entry);
        }

        if (equal) {
            *index = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_ITEM_NOT_FOUND;
}

static void mlnx_fdb_or_route_action_remove(_In_ uint32_t index)
{
    uint32_t actions_count;

    actions_count = g_sai_db_ptr->fdb_or_route_actions.count;

    assert((actions_count > 0) && (index < actions_count));

    g_sai_db_ptr->fdb_or_route_actions.actions[index] = g_sai_db_ptr->fdb_or_route_actions.actions[actions_count - 1];
    g_sai_db_ptr->fdb_or_route_actions.count--;
}

sai_status_t mlnx_fdb_route_action_save(_In_ sai_object_type_t   type,
                                        _In_ const void         *entry,
                                        _In_ sai_packet_action_t action)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii;

    assert((SAI_OBJECT_TYPE_FDB_ENTRY == type) || (SAI_OBJECT_TYPE_ROUTE_ENTRY == type));

    sai_db_write_lock();

    status = mlnx_fdb_or_route_action_find(type, entry, &ii);
    if (SAI_ERR(status)) {
        if (FDB_OR_ROUTE_SAVED_ACTIONS_NUM == g_sai_db_ptr->fdb_or_route_actions.count) {
            SX_LOG_ERR("Failed to save action - max number of saved actions reached (%d)\n",
                       FDB_OR_ROUTE_SAVED_ACTIONS_NUM);
            status = SAI_STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        ii = g_sai_db_ptr->fdb_or_route_actions.count;
        g_sai_db_ptr->fdb_or_route_actions.count++;

        if (SAI_OBJECT_TYPE_FDB_ENTRY == type) {
            g_sai_db_ptr->fdb_or_route_actions.actions[ii].fdb_entry = *(sai_fdb_entry_t*)entry;
        } else {
            g_sai_db_ptr->fdb_or_route_actions.actions[ii].route_entry = *(sai_route_entry_t*)entry;
        }

        g_sai_db_ptr->fdb_or_route_actions.actions[ii].type = type;
    }

    g_sai_db_ptr->fdb_or_route_actions.actions[ii].action = action;
    status                                                = SAI_STATUS_SUCCESS;

out:
    sai_db_unlock();
    return status;
}

void mlnx_fdb_route_action_clear(_In_ sai_object_type_t type, _In_ const void        *entry)
{
    sai_status_t status;
    uint32_t     ii;

    assert((SAI_OBJECT_TYPE_FDB_ENTRY == type) || (SAI_OBJECT_TYPE_ROUTE_ENTRY == type));

    sai_db_write_lock();

    status = mlnx_fdb_or_route_action_find(type, entry, &ii);
    if (SAI_STATUS_SUCCESS == status) {
        mlnx_fdb_or_route_action_remove(ii);
    }

    sai_db_unlock();
}

void mlnx_fdb_route_action_fetch(_In_ sai_object_type_t type,
                                 _In_ const void       *entry,
                                 _Out_ void            *entry_action)
{
    sai_status_t        status;
    sai_packet_action_t action;
    uint32_t            ii;

    assert((SAI_OBJECT_TYPE_FDB_ENTRY == type) || (SAI_OBJECT_TYPE_ROUTE_ENTRY == type));

    sai_db_write_lock();

    status = mlnx_fdb_or_route_action_find(type, entry, &ii);
    if (SAI_STATUS_SUCCESS == status) {
        action = g_sai_db_ptr->fdb_or_route_actions.actions[ii].action;
        if (SAI_OBJECT_TYPE_FDB_ENTRY == type) {
            status = mlnx_translate_sai_action_to_sdk(action, entry_action, 0);
            assert(SAI_STATUS_SUCCESS == status);
        } else {
            status = mlnx_translate_sai_router_action_to_sdk(action, entry_action, 0);
            assert(SAI_STATUS_SUCCESS == status);
        }

        mlnx_fdb_or_route_action_remove(ii);
    }

    sai_db_unlock();
}
