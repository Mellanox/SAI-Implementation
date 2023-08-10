/*
 *  Copyright (C) 2017-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "sai_windows.h"

#include "sai.h"
#include "mlnx_sai.h"

#undef  __MODULE__
#define __MODULE__ SAI_OBJECT_ETH

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t mlnx_virtual_router_availability_get(_In_ sai_object_id_t        switch_id,
                                                  _In_ uint32_t               attr_count,
                                                  _In_ const sai_attribute_t *attr_list,
                                                  _Out_ uint64_t             *count);
sai_status_t mlnx_switch_next_hop_availability_get(_In_ sai_object_id_t        switch_id,
                                                   _In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list,
                                                   _Out_ uint64_t             *count);
sai_status_t mlnx_switch_next_hop_group_availability_get(_In_ sai_object_id_t        switch_id,
                                                         _In_ uint32_t               attr_count,
                                                         _In_ const sai_attribute_t *attr_list,
                                                         _Out_ uint64_t             *count);
sai_status_t mlnx_rif_availability_get(_In_ sai_object_id_t        switch_id,
                                       _In_ uint32_t               attr_count,
                                       _In_ const sai_attribute_t *attr_list,
                                       _Out_ uint64_t             *count);
sai_status_t mlnx_switch_acl_table_availability_get(_In_ sai_object_id_t        switch_id,
                                                    _In_ uint32_t               attr_count,
                                                    _In_ const sai_attribute_t *attr_list,
                                                    _Out_ uint64_t             *count);
sai_status_t mlnx_acl_entry_availability_get(_In_ sai_object_id_t        switch_id,
                                             _In_ uint32_t               attr_count,
                                             _In_ const sai_attribute_t *attr_list,
                                             _Out_ uint64_t             *count);
sai_status_t mlnx_acl_counter_availability_get(_In_ sai_object_id_t        switch_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list,
                                               _Out_ uint64_t             *count);
sai_status_t mlnx_switch_acl_table_group_availability_get(_In_ sai_object_id_t        switch_id,
                                                          _In_ uint32_t               attr_count,
                                                          _In_ const sai_attribute_t *attr_list,
                                                          _Out_ uint64_t             *count);
sai_status_t mlnx_mirror_availability_get(_In_ sai_object_id_t        switch_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list,
                                          _Out_ uint64_t             *count);
sai_status_t mlnx_switch_stp_availability_get(_In_ sai_object_id_t        switch_id,
                                              _In_ uint32_t               attr_count,
                                              _In_ const sai_attribute_t *attr_list,
                                              _Out_ uint64_t             *count);
sai_status_t mlnx_hostif_trap_group_availability_get(_In_ sai_object_id_t        switch_id,
                                                     _In_ uint32_t               attr_count,
                                                     _In_ const sai_attribute_t *attr_list,
                                                     _Out_ uint64_t             *count);
sai_status_t mlnx_switch_fdb_entry_availability_get(_In_ sai_object_id_t        switch_id,
                                                    _In_ uint32_t               attr_count,
                                                    _In_ const sai_attribute_t *attr_list,
                                                    _Out_ uint64_t             *count);
sai_status_t mlnx_switch_neighbor_entry_availability_get(_In_ sai_object_id_t        switch_id,
                                                         _In_ uint32_t               attr_count,
                                                         _In_ const sai_attribute_t *attr_list,
                                                         _Out_ uint64_t             *count);
sai_status_t mlnx_switch_route_entry_availability_get(_In_ sai_object_id_t        switch_id,
                                                      _In_ uint32_t               attr_count,
                                                      _In_ const sai_attribute_t *attr_list,
                                                      _Out_ uint64_t             *count);
sai_status_t mlnx_tunnel_availability_get(_In_ sai_object_id_t        switch_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list,
                                          _Out_ uint64_t             *count);
sai_status_t mlnx_tunnel_term_table_entry_availability_get(_In_ sai_object_id_t        switch_id,
                                                           _In_ uint32_t               attr_count,
                                                           _In_ const sai_attribute_t *attr_list,
                                                           _Out_ uint64_t             *count);
sai_status_t mlnx_bridge_availability_get(_In_ sai_object_id_t        switch_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list,
                                          _Out_ uint64_t             *count);
sai_status_t mlnx_bridge_port_availability_get(_In_ sai_object_id_t        switch_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list,
                                               _Out_ uint64_t             *count);
sai_status_t mlnx_switch_bfd_session_availability_get(_In_ sai_object_id_t        switch_id,
                                                      _In_ uint32_t               attr_count,
                                                      _In_ const sai_attribute_t *attr_list,
                                                      _Out_ uint64_t             *count);
sai_status_t mlnx_debug_counter_availability_get(_In_ sai_object_id_t        switch_id,
                                                 _In_ uint32_t               attr_count,
                                                 _In_ const sai_attribute_t *attr_list,
                                                 _Out_ uint64_t             *count);

const mlnx_availability_get_fn mlnx_availability_get_fns[SAI_OBJECT_TYPE_MAX] = {
    [SAI_OBJECT_TYPE_VIRTUAL_ROUTER] = mlnx_virtual_router_availability_get,
    [SAI_OBJECT_TYPE_NEXT_HOP] = mlnx_switch_next_hop_availability_get,
    [SAI_OBJECT_TYPE_NEXT_HOP_GROUP] = mlnx_switch_next_hop_group_availability_get,
    [SAI_OBJECT_TYPE_ROUTER_INTERFACE] = mlnx_rif_availability_get,
    [SAI_OBJECT_TYPE_ACL_TABLE] = mlnx_switch_acl_table_availability_get,
    [SAI_OBJECT_TYPE_ACL_ENTRY] = mlnx_acl_entry_availability_get,
    [SAI_OBJECT_TYPE_ACL_COUNTER] = mlnx_acl_counter_availability_get,
    [SAI_OBJECT_TYPE_ACL_TABLE_GROUP] = mlnx_switch_acl_table_group_availability_get,
    [SAI_OBJECT_TYPE_MIRROR_SESSION] = mlnx_mirror_availability_get,
    [SAI_OBJECT_TYPE_STP] = mlnx_switch_stp_availability_get,
    [SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP] = mlnx_hostif_trap_group_availability_get,
    [SAI_OBJECT_TYPE_FDB_ENTRY] = mlnx_switch_fdb_entry_availability_get,
    [SAI_OBJECT_TYPE_NEIGHBOR_ENTRY] = mlnx_switch_neighbor_entry_availability_get,
    [SAI_OBJECT_TYPE_ROUTE_ENTRY] = mlnx_switch_route_entry_availability_get,
    [SAI_OBJECT_TYPE_TUNNEL] = mlnx_tunnel_availability_get,
    [SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY] = mlnx_tunnel_term_table_entry_availability_get,
    [SAI_OBJECT_TYPE_BRIDGE] = mlnx_bridge_availability_get,
    [SAI_OBJECT_TYPE_BRIDGE_PORT] = mlnx_bridge_port_availability_get,
    [SAI_OBJECT_TYPE_BFD_SESSION] = mlnx_switch_bfd_session_availability_get,
    [SAI_OBJECT_TYPE_DEBUG_COUNTER] = mlnx_debug_counter_availability_get,
};

sai_status_t mlnx_object_eth_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}
