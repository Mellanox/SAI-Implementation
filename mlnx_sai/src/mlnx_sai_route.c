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

#include "sai_windows.h"
#include "sai.h"
#include "mlnx_sai.h"
#include "assert.h"
#include <fx_base_api.h>
#include <flextrum_types.h>
#include <sdk/sx_api_bmtor.h>

#undef  __MODULE__
#define __MODULE__ SAI_ROUTE

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_route_packet_action_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_route_trap_id_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_route_next_hop_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_route_counter_id_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_route_packet_action_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_route_trap_id_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static sai_status_t mlnx_route_next_hop_id_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_get_route(const sai_route_entry_t* route_entry,
                                   sx_uc_route_get_entry_t *route_get_entry,
                                   sx_router_id_t          *vrid);
static sai_status_t mlnx_route_counter_id_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static const sai_vendor_attribute_entry_t route_vendor_attribs[] = {
    { SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_packet_action_get, NULL,
      mlnx_route_packet_action_set, NULL },
    { SAI_ROUTE_ENTRY_ATTR_USER_TRAP_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_trap_id_get, NULL,
      mlnx_route_trap_id_set, NULL },
    { SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_next_hop_id_get, NULL,
      mlnx_route_next_hop_id_set, NULL },
    { SAI_ROUTE_ENTRY_ATTR_COUNTER_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_route_counter_id_get, NULL,
      mlnx_route_counter_id_set, NULL },
    { SAI_ROUTE_ENTRY_ATTR_META_DATA,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        route_enum_info[] = {
    [SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION] = ATTR_ENUM_VALUES_LIST(
        SAI_PACKET_ACTION_FORWARD,
        SAI_PACKET_ACTION_TRAP,
        SAI_PACKET_ACTION_LOG,
        SAI_PACKET_ACTION_DROP)
};
static size_t route_entry_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    return sai_ipprefix_to_str(key->key.route_entry.destination, max_len, str);
}
const mlnx_obj_type_attrs_info_t mlnx_route_obj_type_info =
{ route_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(route_enum_info), OBJ_STAT_CAP_INFO_EMPTY(), route_entry_info_print};

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_translate_sai_route_entry_to_sdk(_In_ const sai_route_entry_t *route_entry,
                                                          _Out_ sx_ip_prefix_t         *ip_prefix,
                                                          _Out_ sx_router_id_t         *vrid)
{
    uint32_t     data;
    sai_status_t status;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_ip_prefix_to_sdk(&route_entry->destination, ip_prefix))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(route_entry->vr_id, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &data, NULL))) {
        return status;
    }
    *vrid = (sx_router_id_t)data;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_handle_encap_nexthop(_In_ sai_object_id_t nh,
                                                    _In_ sai_object_id_t vrf,
                                                    _Out_ sx_ecmp_id_t  *sx_ecmp_id)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t        nh_idx;

    assert(sx_ecmp_id);

    sai_db_write_lock();

    status = mlnx_encap_nexthop_oid_to_data(nh, &db_entry, &nh_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed get data from DB.\n");
        goto out;
    }

    status = mlnx_encap_nexthop_counter_update(nh_idx, vrf, 1, NH_COUNTER_TYPE_NH);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Update encap nexthop counter failed.\n");
        goto out;
    }

    status = mlnx_encap_nexthop_get_ecmp(nh, vrf, sx_ecmp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Get ecmp failed.\n");
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_fill_route_data(sx_uc_route_data_t      *route_data,
                                         sai_object_id_t          oid,
                                         uint32_t                 next_hop_param_index,
                                         const sai_route_entry_t *route_entry)
{
    sai_status_t  status;
    sx_ecmp_id_t  sdk_ecmp_id;
    sx_next_hop_t sdk_next_hop;
    uint32_t      sdk_next_hop_cnt;
    uint32_t      port_data;
    uint32_t      data;
    uint16_t      ext;

    SX_LOG_ENTER();

    if (SAI_OBJECT_TYPE_NEXT_HOP == sai_object_type_query(oid)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_NEXT_HOP, &data, (uint8_t*)&ext))) {
            return status;
        }

        if (ext) {
            status = mlnx_route_handle_encap_nexthop(oid, route_entry->vr_id, &sdk_ecmp_id);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Fill route data (Encap Nexthop) failed.\n");
                return status;
            }
        } else {
            sdk_ecmp_id = (sx_ecmp_id_t)data;
        }

        route_data->type = SX_UC_ROUTE_TYPE_NEXT_HOP;
        route_data->uc_route_param.ecmp_id = sdk_ecmp_id;

        /* ECMP container should contains exactly 1 next hop */
        sdk_next_hop_cnt = 1;
        memset(&sdk_next_hop, 0, sizeof(sdk_next_hop));
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_router_ecmp_get(get_sdk_handle(), sdk_ecmp_id, &sdk_next_hop, &sdk_next_hop_cnt))) {
            SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
        if (1 != sdk_next_hop_cnt) {
            SX_LOG_ERR("Invalid next hop object\n");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + next_hop_param_index;
        }
    } else if (SAI_OBJECT_TYPE_NEXT_HOP_GROUP == sai_object_type_query(oid)) {
        status = mlnx_nhg_get_ecmp(oid, route_entry->vr_id, 1, &sdk_ecmp_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get ECMP from NHG.\n");
            return status;
        }

        route_data->type = SX_UC_ROUTE_TYPE_NEXT_HOP;
        route_data->uc_route_param.ecmp_id = sdk_ecmp_id;
    } else if (SAI_OBJECT_TYPE_ROUTER_INTERFACE == sai_object_type_query(oid)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_rif_oid_to_sdk_rif_id(oid, &route_data->uc_route_param.local_egress_rif))) {
            SX_LOG_ERR("Fail to get sdk rif id from rif oid %" PRIx64 "\n", oid);
            SX_LOG_EXIT();
            return status;
        }
        route_data->type = SX_UC_ROUTE_TYPE_LOCAL;
    } else if (SAI_OBJECT_TYPE_PORT == sai_object_type_query(oid)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_PORT, &port_data, NULL))) {
            return status;
        }
        if (CPU_PORT != port_data) {
            SX_LOG_ERR("Invalid port passed as next hop id, only cpu port is valid - %u %u\n", port_data, CPU_PORT);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + next_hop_param_index;
        }
        route_data->type = SX_UC_ROUTE_TYPE_IP2ME;
    } else if (SAI_NULL_OBJECT_ID == oid) {
        route_data->type = SX_UC_ROUTE_TYPE_NEXT_HOP;
        if (SX_ROUTER_ACTION_TRAP != route_data->action) {
            route_data->action = SX_ROUTER_ACTION_DROP;
        }
        route_data->uc_route_param.ecmp_id = SX_ROUTER_ECMP_ID_INVALID;
    } else {
        SX_LOG_ERR("Invalid next hop object type - %s\n", SAI_TYPE_STR(sai_object_type_query(oid)));
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + next_hop_param_index;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_attr_to_sx_data(_In_ const sai_route_entry_t *route_entry,
                                               _In_ uint32_t                 attr_count,
                                               _In_ const sai_attribute_t   *attr_list,
                                               _Out_ sx_ip_prefix_t         *sx_ip_prefix,
                                               _Out_ sx_router_id_t         *sx_vrid,
                                               _Out_ sx_uc_route_data_t     *sx_route_data)
{
    sai_status_t                 status;
    const sai_attribute_value_t *action, *next_hop, *trap;
    sai_object_id_t              next_hop_oid;
    uint32_t                     action_index, next_hop_index, trap_index;
    bool                         next_hop_id_found = false;
    sx_log_severity_t            log_level = SX_LOG_NOTICE;
    int32_t                      packet_action;

    assert(sx_ip_prefix);
    assert(sx_vrid);
    assert(sx_route_data);

    if (NULL == route_entry) {
        SX_LOG_ERR("NULL route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_on_create_without_oid(attr_count, attr_list, SAI_OBJECT_TYPE_ROUTE_ENTRY);
    if (SAI_ERR(status)) {
        return status;
    }

    /* lower log level for route created often in Sonic */
#ifdef ACS_OS
    log_level = SX_LOG_INFO;
#endif
    MLNX_LOG_ATTRS_VERBOSITY(log_level, attr_count, attr_list, SAI_OBJECT_TYPE_ROUTE_ENTRY);

    status = mlnx_translate_sai_route_entry_to_sdk(route_entry, sx_ip_prefix, sx_vrid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SAI to SDK route entry.\n");
        return status;
    }

    sx_route_data->action = SX_ROUTER_ACTION_FORWARD;

    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, &action, &action_index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_translate_sai_router_action_to_sdk(action->s32, &sx_route_data->action, action_index);
        if (SAI_ERR(status)) {
            return status;
        }
        packet_action = action->s32;
    } else {
        packet_action = SAI_PACKET_ACTION_FORWARD;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, &next_hop, &next_hop_index);
    if (SAI_ERR(status)) {
        next_hop_oid = SAI_NULL_OBJECT_ID;
        next_hop_index = 0;
    } else {
        next_hop_oid = next_hop->oid;
        next_hop_id_found = true;
    }

    if (((SX_ROUTER_ACTION_FORWARD == sx_route_data->action) || (SX_ROUTER_ACTION_MIRROR == sx_route_data->action)) &&
        (!next_hop_id_found)) {
        SX_LOG_ERR(
            "Packet action forward/log without next hop / next hop group is not allowed for non directly reachable route\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ENTRY_ATTR_USER_TRAP_ID, &trap, &trap_index);
    if (SAI_ERR(status) && (status != SAI_STATUS_ITEM_NOT_FOUND)) {
        SX_LOG_ERR("Failed to find trap id attribute\n");
        return status;
    }

    if (is_action_trap(packet_action) && (SAI_ERR(status) || (trap->oid == SAI_NULL_OBJECT_ID))) {
        SX_LOG_ERR("Trap action requires a user defined trap\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if ((!is_action_trap(packet_action)) && SAI_OK(status)) {
        SX_LOG_ERR("Invalid attribute trap id for non-trap packet action\n");
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + trap_index;
    }

    sai_db_read_lock();
    if (is_action_trap((packet_action))) {
        status = mlnx_get_user_defined_trap_prio(SAI_OBJECT_TYPE_ROUTE_ENTRY, trap->oid,
                                                 &sx_route_data->trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get trap priority\n");
            sai_db_unlock();
            return status;
        }

        status = mlnx_trap_refcount_increase(trap->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to increase trap refcount\n");
            sai_db_unlock();
            return status;
        }
    }
    sai_db_unlock();

    status = mlnx_fill_route_data(sx_route_data, next_hop_oid, next_hop_index, route_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill route data.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_change_counter(sx_router_id_t  vrid,
                                              sx_ip_prefix_t *ip_prefix,
                                              sai_object_id_t counter_id)
{
    sx_flow_counter_id_t flow_counter;
    sx_status_t          sx_status;
    sai_status_t         status;

    if (SAI_NULL_OBJECT_ID != counter_id) {
        status = mlnx_get_flow_counter_id(counter_id, &flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get flow counter\n");
            return status;
        }

        sx_status = sx_api_router_uc_route_counter_bind_set(get_sdk_handle(),
                                                            SX_ACCESS_CMD_BIND,
                                                            vrid,
                                                            ip_prefix,
                                                            flow_counter);
    } else {
        sx_status = sx_api_router_uc_route_counter_bind_set(get_sdk_handle(), SX_ACCESS_CMD_UNBIND, vrid, ip_prefix,
                                                            SX_FLOW_COUNTER_ID_INVALID);
    }

    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set counter - %s.\n", SX_STATUS_MSG(sx_status));
    }

    SX_LOG_EXIT();
    return sdk_to_sai(sx_status);
}

/*
 * Routine Description:
 *    Create Route
 *
 * Arguments:
 *    [in] route_entry - route entry
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP prefix/mask expected in Network Byte Order.
 *
 */
static sai_status_t mlnx_create_route(_In_ const sai_route_entry_t* route_entry,
                                      _In_ uint32_t                 attr_count,
                                      _In_ const sai_attribute_t   *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    sx_ip_prefix_t               ip_prefix;
    sx_router_id_t               vrid = DEFAULT_VRID;
    sx_uc_route_data_t           route_data;
    sx_log_severity_t            log_level = SX_LOG_NOTICE;
    const sai_attribute_value_t *counter = NULL;
    uint32_t                     counter_index;

    SX_LOG_ENTER();

    memset(&ip_prefix, 0, sizeof(ip_prefix));
    memset(&route_data, 0, sizeof(route_data));

    status = mlnx_route_attr_to_sx_data(route_entry, attr_count, attr_list, &ip_prefix, &vrid, &route_data);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sx_status = sx_api_router_uc_route_set(get_sdk_handle(), SX_ACCESS_CMD_ADD, vrid, &ip_prefix, &route_data);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set route - %s.\n", SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTE_ENTRY_ATTR_COUNTER_ID, &counter, &counter_index);
    if (!SAI_ERR(status)) {
        status = mlnx_route_change_counter(vrid, &ip_prefix, counter->oid);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return status;
        }
    }

    /* lower log level for route created often in Sonic */
#ifdef ACS_OS
    log_level = SX_LOG_INFO;
#endif

    MLNX_LOG_KEY_CREATED(log_level, route_entry, SAI_OBJECT_TYPE_ROUTE_ENTRY);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_to_encap_nexthop_remove(_In_ sai_object_id_t nh, _In_ sai_object_id_t vrf)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t        nh_idx;

    status = mlnx_encap_nexthop_oid_to_data(nh, &db_entry, &nh_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed get data from DB.\n");
        return status;
    }

    status = mlnx_encap_nexthop_counter_update(nh_idx, vrf, -1, NH_COUNTER_TYPE_NH);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Update Encap Nexthop counter failed.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_get_encap_nh(_In_ sx_ecmp_id_t sx_ecmp_id, _Out_ sai_object_id_t *nh)
{
    sai_status_t status;
    uint32_t     data;
    uint16_t     ext;

    *nh = SAI_NULL_OBJECT_ID;

    status = mlnx_route_next_hop_id_get_ext(sx_ecmp_id,
                                            nh);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SAI_OBJECT_TYPE_NEXT_HOP != sai_object_type_query(*nh)) {
        *nh = SAI_NULL_OBJECT_ID;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_object_to_type(*nh, SAI_OBJECT_TYPE_NEXT_HOP, &data, (uint8_t*)&ext);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!ext) {
        *nh = SAI_NULL_OBJECT_ID;
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_to_nhg_remove(_In_ mlnx_shm_rm_array_idx_t nhg_idx, _In_ sai_object_id_t vrf)
{
    sai_status_t status;

    status = mlnx_nhg_counter_update(nhg_idx,
                                     vrf,
                                     -1,
                                     false);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to decrement NHG counter.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* requires sai_db write lock */
static sai_status_t mlnx_route_post_remove_unlocked(_In_ sx_uc_route_get_entry_t *route_get_entry,
                                                    _In_ sai_object_id_t          vrf)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sai_object_id_t         nh = SAI_NULL_OBJECT_ID;
    mlnx_shm_rm_array_idx_t nhg_idx = {0};

    assert(route_get_entry);

    if ((SX_UC_ROUTE_TYPE_NEXT_HOP != route_get_entry->route_data.type) ||
        (SX_ROUTER_ECMP_ID_INVALID == route_get_entry->route_data.uc_route_param.ecmp_id)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_ecmp_to_nhg_map_entry_get(route_get_entry->route_data.uc_route_param.ecmp_id,
                                            &nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to find ECMP-NHG map entry.\n");
        return status;
    }

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhg_idx)) {
        status = mlnx_route_to_nhg_remove(nhg_idx,
                                          vrf);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove route to NHG.\n");
            return status;
        }
    } else {
        status = mlnx_route_get_encap_nh(route_get_entry->route_data.uc_route_param.ecmp_id,
                                         &nh);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to find Encap NH.\n");
            return status;
        }

        if (nh != SAI_NULL_OBJECT_ID) {
            status = mlnx_route_to_encap_nexthop_remove(nh, vrf);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Remove route to Encap Nexthop failed.\n");
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_post_remove(_In_ sx_uc_route_get_entry_t *route_get_entry, _In_ sai_object_id_t vrf)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    assert(route_get_entry);

    sai_db_write_lock();

    status = mlnx_route_post_remove_unlocked(route_get_entry, vrf);

    sai_db_unlock();
    return status;
}


static sai_status_t mlnx_remove_route_trap(sx_uc_route_get_entry_t *route_get_entry)
{
    sai_packet_action_t packet_action;
    sai_status_t        status;

    SX_LOG_ENTER();

    assert(route_get_entry);

    status = mlnx_translate_sdk_router_action_to_sai(route_get_entry->route_data.action, &packet_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SDK router action to SAI\n");
        return status;
    }

    if (is_action_trap(packet_action)) {
        status = mlnx_trap_refcount_decrease_by_prio(SAI_OBJECT_TYPE_ROUTE_ENTRY,
                                                     route_get_entry->route_data.trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrease trap refcount by prio %d\n", route_get_entry->route_data.trap_attr.prio);
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove Route
 *
 * Arguments:
 *    [in] route_entry - route entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP prefix/mask expected in Network Byte Order.
 */
static sai_status_t mlnx_remove_route(_In_ const sai_route_entry_t* route_entry)
{
    sai_status_t            status;
    sx_status_t             sx_status;
    sx_router_id_t          vrid = DEFAULT_VRID;
    sx_uc_route_get_entry_t route_get_entry;

    SX_LOG_ENTER();

    if (NULL == route_entry) {
        SX_LOG_ERR("NULL route_entry param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    MLNX_LOG_KEY_REMOVE(SX_LOG_NOTICE, route_entry, SAI_OBJECT_TYPE_ROUTE_ENTRY);

    status = mlnx_get_route(route_entry, &route_get_entry, &vrid);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_router_uc_route_set(get_sdk_handle(),
                                           SX_ACCESS_CMD_DELETE,
                                           vrid,
                                           &route_get_entry.network_addr,
                                           NULL);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove route - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sai_db_write_lock();

    status = mlnx_remove_route_trap(&route_get_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unbind trap from route\n");
        goto out;
    }

    status = mlnx_route_post_remove_unlocked(&route_get_entry, route_entry->vr_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Route post remove failed.\n");
        goto out;
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Set route attribute value
 *
 * Arguments:
 *    [in] route_entry - route entry
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_route_attribute(_In_ const sai_route_entry_t* route_entry,
                                             _In_ const sai_attribute_t   *attr)
{
    sai_object_key_t key;

    if (!route_entry) {
        SX_LOG_ERR("Entry is NULL.\n");
        return SAI_STATUS_FAILURE;
    }

    memcpy(&key.key.route_entry, route_entry, sizeof(*route_entry));
    return sai_set_attribute(&key, SAI_OBJECT_TYPE_ROUTE_ENTRY, attr);
}

/*
 * Routine Description:
 *    Get route attribute value
 *
 * Arguments:
 *    [in] route_entry - route entry
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_route_attribute(_In_ const sai_route_entry_t* route_entry,
                                             _In_ uint32_t                 attr_count,
                                             _Inout_ sai_attribute_t      *attr_list)
{
    sai_object_key_t key;

    if (!route_entry) {
        SX_LOG_ERR("Entry is NULL.\n");
        return SAI_STATUS_FAILURE;
    }

    memcpy(&key.key.route_entry, route_entry, sizeof(*route_entry));
    return sai_get_attributes(&key, SAI_OBJECT_TYPE_ROUTE_ENTRY, attr_count, attr_list);
}

static sai_status_t mlnx_get_route(const sai_route_entry_t* route_entry,
                                   sx_uc_route_get_entry_t *route_get_entry,
                                   sx_router_id_t          *vrid)
{
    sx_status_t              status;
    uint32_t                 entries_count = 1;
    sx_ip_prefix_t           ip_prefix;
    sx_uc_route_key_filter_t filter;

    SX_LOG_ENTER();

    memset(&ip_prefix, 0, sizeof(ip_prefix));
    memset(&filter, 0, sizeof(filter));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_route_entry_to_sdk(route_entry, &ip_prefix, vrid))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_uc_route_get(get_sdk_handle(), SX_ACCESS_CMD_GET, *vrid, &ip_prefix, &filter,
                                        route_get_entry, &entries_count))) {
        SX_LOG_ERR("Failed to get %d route entries %s.\n", entries_count, SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet action [sai_packet_action_t] */
static sai_status_t mlnx_route_packet_action_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t             status;
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  route_get_entry;
    sx_router_id_t           vrid;
    sai_packet_action_t      packet_action;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(route_entry, &route_get_entry, &vrid))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sdk_router_action_to_sai(route_get_entry.route_data.action, &packet_action))) {
        return status;
    }

    value->s32 = packet_action;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_trap_id_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t             status;
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  route_get_entry;
    sx_router_id_t           vrid;
    sai_packet_action_t      packet_action;

    SX_LOG_ENTER();

    status = mlnx_get_route(route_entry, &route_get_entry, &vrid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get route\n");
        return status;
    }

    status = mlnx_translate_sdk_router_action_to_sai(route_get_entry.route_data.action, &packet_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SDK router %d action to SAI\n", route_get_entry.route_data.action);
        return status;
    }

    sai_db_read_lock();

    if (is_action_trap(packet_action)) {
        status = mlnx_get_user_defined_trap_by_prio(SAI_OBJECT_TYPE_ROUTE_ENTRY,
                                                    route_get_entry.route_data.trap_attr.prio, &value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup trap oid by trap prio %d\n", route_get_entry.route_data.trap_attr.prio);
            goto out;
        }
    } else {
        value->oid = SAI_NULL_OBJECT_ID;
    }

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_ecmp_get_ip(_In_ sx_ecmp_id_t sdk_ecmp_id, _Out_ sx_ip_addr_t *ip)
{
    sx_status_t   sx_status;
    sx_next_hop_t sdk_next_hop;
    uint32_t      sdk_next_hop_cnt;

    assert(ip);

    sdk_next_hop_cnt = 1;
    sx_status = sx_api_router_ecmp_get(get_sdk_handle(), sdk_ecmp_id, &sdk_next_hop, &sdk_next_hop_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (1 != sdk_next_hop_cnt) {
        SX_LOG_DBG("Next hops count != 1, (value: %u)\n", sdk_next_hop_cnt);
        return SAI_STATUS_SUCCESS;
    }

    *ip = sdk_next_hop.next_hop_key.next_hop_key_entry.ip_next_hop.address;

    return SAI_STATUS_SUCCESS;
}

static bool mlnx_is_encap_nexthop_fake_ip(_In_ sx_ip_addr_t *ip)
{
    assert(ip);

    if (ip->version == SX_IP_VERSION_IPV4) {
        return ((((ip->addr.ipv4.s_addr & 0xFF000000) >> 24) == 0) &&
                (((ip->addr.ipv4.s_addr & 0x00FFFF00) >> 8) < MAX_ENCAP_NEXTHOPS_NUMBER) &&
                (((ip->addr.ipv4.s_addr & 0x000000FF) < NUMBER_OF_LOCAL_VNETS)));
    }

    return false;
}

static sai_status_t mlnx_route_get_encap_nexthop(_In_ sx_ip_addr_t *ip, _Out_ sai_object_id_t *nh)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t db_idx;

    db_idx.type = MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP;

    if (ip->version == SX_IP_VERSION_IPV4) {
        db_idx.idx = (ip->addr.ipv4.s_addr & 0x00FFFF00) >> 8;
    } else {
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_encap_nexthop_oid_create(db_idx, nh);

    return status;
}

sai_status_t mlnx_route_next_hop_id_get_ext(_In_ sx_ecmp_id_t ecmp, _Out_ sai_object_id_t *nh)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nhg_idx;
    sx_ip_addr_t            ip = {0};

    assert(nh);

    status = mlnx_ecmp_to_nhg_map_entry_get(ecmp,
                                            &nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to find ECMP-NHG map entry.\n");
        return status;
    }

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhg_idx)) {
        status = mlnx_nhg_oid_create(nhg_idx, nh);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create NHG OID.\n");
            return status;
        }
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_ecmp_get_ip(ecmp, &ip);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Get ECMP IP failed.\n");
        return status;
    }

    if (mlnx_is_encap_nexthop_fake_ip(&ip)) {
        status = mlnx_route_get_encap_nexthop(&ip, nh);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Get Encap Next Hop OID failed.\n");
            return status;
        }
    } else {
        status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP,
                                    ecmp,
                                    NULL,
                                    nh);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Create Next Hop OID failed.\n");
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* Next hop or next hop group id for the packet or a router interface
 * in case of directly reachable route [sai_object_id_t]
 * The next hop id can be a generic next hop object, such as next hop,
 * next hop group.
 * Directly reachable routes are the IP subnets that are directly attached to the router.
 * For such routes, fill the router interface id to which the subnet is attached */
static sai_status_t mlnx_route_next_hop_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t             status;
    const sai_route_entry_t *route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  route_get_entry;
    sx_router_id_t           vrid;

    SX_LOG_ENTER();

    status = mlnx_get_route(route_entry, &route_get_entry, &vrid);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SX_UC_ROUTE_TYPE_LOCAL == route_get_entry.route_data.type) {
        status = mlnx_rif_sx_to_sai_oid(route_get_entry.route_data.uc_route_param.
                                        local_egress_rif,
                                        &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
    } else if (SX_UC_ROUTE_TYPE_NEXT_HOP == route_get_entry.route_data.type) {
        if (SX_ROUTER_ECMP_ID_INVALID != route_get_entry.route_data.uc_route_param.ecmp_id) {
            status = mlnx_route_next_hop_id_get_ext(route_get_entry.route_data.uc_route_param.ecmp_id,
                                                    &value->oid);
            if (SAI_ERR(status)) {
                return status;
            }
        } else {
            value->oid = SAI_NULL_OBJECT_ID;
        }
    } else if (SX_UC_ROUTE_TYPE_IP2ME == route_get_entry.route_data.type) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, CPU_PORT, NULL, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        SX_LOG_ERR("Unexpected sx route type %u\n", route_get_entry.route_data.type);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_modify_route(sx_router_id_t           vrid,
                                      sx_uc_route_get_entry_t *route_get_entry,
                                      sx_access_cmd_t          cmd)
{
    sx_status_t status;

    /* Delete and Add for action/priority, or Set for next hops changes */
    if (SX_ACCESS_CMD_ADD == cmd) {
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_router_uc_route_set(get_sdk_handle(), SX_ACCESS_CMD_DELETE, vrid,
                                                 &route_get_entry->network_addr, &route_get_entry->route_data))) {
            SX_LOG_ERR("Failed to delete route - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_uc_route_set(get_sdk_handle(), cmd, vrid,
                                             &route_get_entry->network_addr, &route_get_entry->route_data))) {
        SX_LOG_ERR("Failed to set route - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Packet action [sai_packet_action_t] */

/* Different packet action will be set depending on the action and whether is nexthop or trap id bound to the route
 * 1) If new action is FORWARD, but current action is DROP or TRAP, action will be changed to an action that does
 * not require nexthop e.g FORWARD-> DROP
 * 2) If new action is TRAP, but current action is DROP or FORWARD. action will be changed to an action that does
 * not require trap id e.g TRAP-> DROP
 * 3) new LOG action requires both trap and nexthop id`s so the current action could not be changed
 * current action: DROP, result action: DROP
 * current action: TRAP, result action: TRAP
 * current action: FORWARD, result action: FORWARD
 * current action: LOG, result action: LOG
 */
static sai_status_t mlnx_route_packet_action_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t             status;
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  old_route_get_entry, route_get_entry;
    sx_router_id_t           vrid;
    bool                     is_action_present;
    sai_packet_action_t      current_sai_action, action_to_configure;

    SX_LOG_ENTER();

    status = mlnx_get_route(route_entry, &route_get_entry, &vrid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get route data\n");
        return status;
    }

    old_route_get_entry = route_get_entry;

    status = mlnx_translate_sdk_router_action_to_sai(route_get_entry.route_data.action, &current_sai_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sdk action to sai\n");
        return status;
    }

    action_to_configure = value->s32;
    if ((!is_action_trap(current_sai_action)) && is_action_trap(value->s32)) {
        status = mlnx_translate_action_to_no_trap(action_to_configure, &action_to_configure, &is_action_present);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate action %d to action that does not require a trap id\n",
                       current_sai_action);
            return status;
        }
    }

    if ((!is_action_forward(current_sai_action)) && is_action_forward(action_to_configure)) {
        status = mlnx_translate_action_to_no_forward(action_to_configure, &action_to_configure);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate action %d to action that does not require a nexthop id\n",
                       current_sai_action);
            return status;
        }
    }

    if (action_to_configure == current_sai_action) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_translate_sai_router_action_to_sdk(action_to_configure, &route_get_entry.route_data.action, 0);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sai router action to SDK\n");
        return status;
    }

    status = mlnx_modify_route(vrid, &route_get_entry, SX_ACCESS_CMD_ADD);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to modify route\n");
        return status;
    }

    if (is_action_forward(current_sai_action) && (!is_action_forward(action_to_configure))) {
        status = mlnx_route_post_remove(&old_route_get_entry, route_entry->vr_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Route post remove failed.\n");
            return status;
        }
    }

    sai_db_write_lock();

    if (is_action_trap(current_sai_action) && (!is_action_trap(action_to_configure))) {
        status = mlnx_trap_refcount_decrease_by_prio(SAI_OBJECT_TYPE_ROUTE_ENTRY,
                                                     old_route_get_entry.route_data.trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrease trap prio %d\n", old_route_get_entry.route_data.trap_attr.prio);
            goto out;
        }
    }
out:
    sai_db_unlock();

    return status;
}

/*
 * Trap set may change the action that is configured in the route in following cases
 * > If current action is DROP and trap id provided is not SAI_NULL_OBJECT_ID TRAP packet action will be configured
 * > If current action is FORWARD and trap id provided is not SAI_NULL_OBJECT_ID LOG packet action will be configured
 * > If current action is LOG and trap id provided is SAI_NULL_OBJECT_ID FORWARD packet action will be configured
 * > If current action is TRAP and trap id provided is SAI_NULL_OBJECT_ID DROP packet action will be configured
 *
 * In other cases route packet action will remain the same
 */
static sai_status_t mlnx_route_trap_id_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sai_status_t             status;
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  route_get_entry;
    sx_router_id_t           vrid;
    sai_packet_action_t      current_action, action_to_configure;
    sai_object_id_t          current_trap = SAI_NULL_OBJECT_ID;
    bool                     is_action_present;

    SX_LOG_ENTER();

    status = mlnx_get_route(route_entry, &route_get_entry, &vrid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get route data\n");
        return status;
    }

    status = mlnx_translate_sdk_router_action_to_sai(route_get_entry.route_data.action, &current_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sdk action %d to sai\n", route_get_entry.route_data.action);
        return status;
    }

    sai_db_write_lock();

    if (value->oid != SAI_NULL_OBJECT_ID) {
        if (!mlnx_is_hostif_user_defined_trap_valid_for_set(SAI_OBJECT_TYPE_ROUTE_ENTRY, value->oid)) {
            status = SAI_STATUS_INVALID_PARAMETER;
            SX_LOG_ERR("Invalid trap id 0x%" PRIx64 "\n", value->oid);
            goto out;
        }
    }

    if (is_action_trap(current_action)) {
        status = mlnx_get_user_defined_trap_by_prio(SAI_OBJECT_TYPE_ROUTE_ENTRY,
                                                    route_get_entry.route_data.trap_attr.prio, &current_trap);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get current trap_id by prio %d\n", route_get_entry.route_data.trap_attr.prio);
            goto out;
        }
    }

    if (current_trap == value->oid) {
        goto out;
    }

    if ((value->oid != SAI_NULL_OBJECT_ID) && (!is_action_trap(current_action))) {
        status = mlnx_translate_action_to_trap(true, current_action, &action_to_configure);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate current action %d to trap action\n", current_action);
            goto out;
        }
    } else if ((value->oid == SAI_NULL_OBJECT_ID) && is_action_trap(current_action)) {
        status = mlnx_translate_action_to_no_trap(current_action, &action_to_configure, &is_action_present);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate current action %d to non-trap action\n", current_action);
            goto out;
        }
    } else {
        action_to_configure = current_action;
    }

    status = mlnx_translate_sai_router_action_to_sdk(action_to_configure, &route_get_entry.route_data.action, 0);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate SAI action %d to SDK\n", action_to_configure);
        goto out;
    }

    if (value->oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_get_user_defined_trap_prio(SAI_OBJECT_TYPE_ROUTE_ENTRY, value->oid,
                                                 &route_get_entry.route_data.trap_attr.prio);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get trap 0x%" PRIx64 " priority\n", value->oid);
            goto out;
        }
    }

    status = mlnx_modify_route(vrid, &route_get_entry, SX_ACCESS_CMD_ADD);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to modify route\n");
        goto out;
    }

    if (current_trap != SAI_NULL_OBJECT_ID) {
        status = mlnx_trap_refcount_decrease(current_trap);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrease previous trap refcount. Trap id - 0x%" PRIx64 "\n", current_trap);
            goto out;
        }
    }

    if (value->oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_trap_refcount_increase(value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to increase new trap refcount. Trap id - 0x%" PRIx64 "\n", value->oid);
            goto out;
        }
    }
out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/* Next hop or next hop group id for the packet or a router interface
 * in case of directly reachable route [sai_object_id_t]
 * The next hop id can be a generic next hop object, such as next hop,
 * next hop group.
 * Directly reachable routes are the IP subnets that are directly attached to the router.
 * For such routes, fill the router interface id to which the subnet is attached
 *
 * Note:
 *  Next hop set may change the action that is configured in the route in following cases
 * > If current action is DROP and nexthop id provided is not SAI_NULL_OBJECT_ID FORWARD packet action will be configured
 * > If current action is TRAP and nexthop id provided is not SAI_NULL_OBJECT_ID LOG packet action will be configured
 * > If current action is LOG and nexthop id provided is SAI_NULL_OBJECT_ID TRAP packet action will be configured
 * > If current action is FORWARD and nexthop id provided is SAI_NULL_OBJECT_ID DROP packet action will be configured
 *
 * In other cases route packet action will remain the same
 */
static sai_status_t mlnx_route_next_hop_id_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sai_status_t             status;
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  old_route_get_entry;
    sx_uc_route_get_entry_t  route_get_entry;
    sx_router_id_t           vrid;
    sai_packet_action_t      current_action, action_to_configure;
    sx_access_cmd_t          cmd = SX_ACCESS_CMD_ADD;

    SX_LOG_ENTER();

    status = mlnx_get_route(route_entry, &route_get_entry, &vrid);
    if (SAI_ERR(status)) {
        return status;
    }

    old_route_get_entry = route_get_entry;

    status = mlnx_translate_sdk_router_action_to_sai(route_get_entry.route_data.action, &current_action);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sdk action %d to sai\n", route_get_entry.route_data.action);
        return status;
    }

    if ((value->oid != SAI_NULL_OBJECT_ID) && (!is_action_forward(current_action))) {
        status = mlnx_translate_action_to_forward(current_action, &action_to_configure);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate current action %d to trap action\n", current_action);
            return status;
        }
    } else if ((value->oid == SAI_NULL_OBJECT_ID) && is_action_forward(current_action)) {
        status = mlnx_translate_action_to_no_forward(current_action, &action_to_configure);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate current action %d to non-trap action\n", current_action);
            return status;
        }
    } else {
        action_to_configure = current_action;
        cmd = SX_ACCESS_CMD_SET;
    }

    status = mlnx_translate_sai_router_action_to_sdk(action_to_configure, &route_get_entry.route_data.action, 0);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate sai action %d to sdk\n", action_to_configure);
        return status;
    }

    status = mlnx_fill_route_data(&route_get_entry.route_data, value->oid, 0, route_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill route data\n");
        return status;
    }

    status = mlnx_modify_route(vrid, &route_get_entry, cmd);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to modify route sx\n");
        return status;
    }

    status = mlnx_route_post_remove(&old_route_get_entry, route_entry->vr_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Route post remove failed.\n");
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_counter_id_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_status_t             status;
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  route_get_entry;
    sx_router_id_t           vrid;

    SX_LOG_ENTER();
    status = mlnx_get_route(route_entry, &route_get_entry, &vrid);
    if (SAI_ERR(status)) {
        return status;
    }

    return mlnx_route_change_counter(vrid, &route_get_entry.network_addr, value->oid);
}

static sai_status_t mlnx_route_counter_id_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t             status;
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    sx_uc_route_get_entry_t  route_get_entry;
    sx_router_id_t           vrid;
    sx_status_t              sx_status;
    sx_flow_counter_id_t     flow_counter;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_get_route(route_entry, &route_get_entry, &vrid))) {
        return status;
    }

    sx_status = sx_api_router_uc_route_counter_bind_get(get_sdk_handle(),
                                                        vrid,
                                                        &route_get_entry.network_addr,
                                                        &flow_counter);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get route counter - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_translate_flow_counter_to_sai_counter(flow_counter, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate flow counter to SAI  counter\n");
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_route_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_route_bulk_api_impl(_In_ sai_common_api_t         api,
                                             _In_ uint32_t                 object_count,
                                             _In_ const sai_route_entry_t *route_entry,
                                             _In_ const uint32_t          *attr_count,
                                             _In_ const sai_attribute_t  **attr_list_for_create,
                                             _In_ sai_attribute_t        **attr_list_for_get,
                                             _In_ const sai_attribute_t   *attr_list_for_set,
                                             _In_ sai_bulk_op_error_mode_t mode,
                                             _Out_ sai_status_t           *object_statuses)
{
    sai_status_t status;
    uint32_t     ii;
    bool         stop_on_error, failure = false;

    SX_LOG_ENTER();

    assert((api == SAI_COMMON_API_BULK_CREATE) || (api == SAI_COMMON_API_BULK_REMOVE) ||
           (api == SAI_COMMON_API_BULK_GET) || (api == SAI_COMMON_API_BULK_SET));

    status = mlnx_bulk_attrs_validate(object_count, attr_count, attr_list_for_create, attr_list_for_get,
                                      attr_list_for_set, mode, object_statuses, api, &stop_on_error);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!route_entry) {
        SX_LOG_ERR("route_entry is NULL");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (stop_on_error) {
        for (ii = 0; ii < object_count; ii++) {
            object_statuses[ii] = SAI_STATUS_NOT_EXECUTED;
        }
    }

    for (ii = 0; ii < object_count; ii++) {
        switch (api) {
        case SAI_COMMON_API_BULK_CREATE:
            object_statuses[ii] = mlnx_create_route(&route_entry[ii], attr_count[ii], attr_list_for_create[ii]);
            break;

        case SAI_COMMON_API_BULK_GET:
            object_statuses[ii] = mlnx_get_route_attribute(&route_entry[ii], attr_count[ii], attr_list_for_get[ii]);
            break;

        case SAI_COMMON_API_BULK_SET:
            object_statuses[ii] = mlnx_set_route_attribute(&route_entry[ii], &attr_list_for_set[ii]);
            break;

        case SAI_COMMON_API_BULK_REMOVE:
            object_statuses[ii] = mlnx_remove_route(&route_entry[ii]);
            break;

        default:
            assert(false);
        }

        if (SAI_ERR(object_statuses[ii])) {
            failure = true;
            if (stop_on_error) {
                goto out;
            } else {
                continue;
            }
        }
    }

out:
    mlnx_bulk_statuses_print("Routes", object_statuses, object_count, api);
    SX_LOG_EXIT();
    return failure ? SAI_STATUS_FAILURE : SAI_STATUS_SUCCESS;
}

/**
 * @brief Bulk create route entry
 *
 * @param[in] object_count Number of objects to create
 * @param[in] route_entry List of object to create
 * @param[in] attr_count List of attr_count. Caller passes the number
 *    of attribute for each object to create.
 * @param[in] attr_list List of attributes for every object.
 * @param[in] mode Bulk operation error handling mode.
 * @param[out] object_statuses List of status for every object. Caller needs to
 * allocate the buffer
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are created or
 * #SAI_STATUS_FAILURE when any of the objects fails to create. When there is
 * failure, Caller is expected to go through the list of returned statuses to
 * find out which fails and which succeeds.
 */
static sai_status_t mlnx_bulk_create_route_entry(_In_ uint32_t                 object_count,
                                                 _In_ const sai_route_entry_t *route_entry,
                                                 _In_ const uint32_t          *attr_count,
                                                 _In_ const sai_attribute_t  **attr_list,
                                                 _In_ sai_bulk_op_error_mode_t mode,
                                                 _Out_ sai_status_t           *object_statuses)
{
    return mlnx_route_bulk_api_impl(SAI_COMMON_API_BULK_CREATE, object_count, route_entry, attr_count,
                                    attr_list, NULL, NULL, mode, object_statuses);
}

/**
 * @brief Bulk remove route entry
 *
 * @param[in] object_count Number of objects to remove
 * @param[in] route_entry List of objects to remove
 * @param[in] mode Bulk operation error handling mode.
 * @param[out] object_statuses List of status for every object. Caller needs to
 * allocate the buffer
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or
 * #SAI_STATUS_FAILURE when any of the objects fails to remove. When there is
 * failure, Caller is expected to go through the list of returned statuses to
 * find out which fails and which succeeds.
 */
static sai_status_t mlnx_bulk_remove_route_entry(_In_ uint32_t                 object_count,
                                                 _In_ const sai_route_entry_t *route_entry,
                                                 _In_ sai_bulk_op_error_mode_t mode,
                                                 _Out_ sai_status_t           *object_statuses)
{
    return mlnx_route_bulk_api_impl(SAI_COMMON_API_BULK_REMOVE, object_count, route_entry, NULL,
                                    NULL, NULL, NULL, mode, object_statuses);
}

/**
 * @brief Bulk set attribute on route entry
 *
 * @param[in] object_count Number of objects to set attribute
 * @param[in] route_entry List of objects to set attribute
 * @param[in] attr_list List of attributes to set on objects, one attribute per object
 * @param[in] mode Bulk operation error handling mode.
 * @param[out] object_statuses List of status for every object. Caller needs to
 * allocate the buffer
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or
 * #SAI_STATUS_FAILURE when any of the objects fails to remove. When there is
 * failure, Caller is expected to go through the list of returned statuses to
 * find out which fails and which succeeds.
 */
static sai_status_t mlnx_bulk_set_route_entry_attribute(_In_ uint32_t                 object_count,
                                                        _In_ const sai_route_entry_t *route_entry,
                                                        _In_ const sai_attribute_t   *attr_list,
                                                        _In_ sai_bulk_op_error_mode_t mode,
                                                        _Out_ sai_status_t           *object_statuses)
{
    return mlnx_route_bulk_api_impl(SAI_COMMON_API_BULK_SET, object_count, route_entry, NULL, NULL, NULL,
                                    attr_list, mode, object_statuses);
}

/**
 * @brief Bulk get attribute on route entry
 *
 * @param[in] object_count Number of objects to set attribute
 * @param[in] route_entry List of objects to set attribute
 * @param[in] attr_count List of attr_count. Caller passes the number
 *    of attribute for each object to get
 * @param[inout] attr_list List of attributes to set on objects, one attribute per object
 * @param[in] mode Bulk operation error handling mode
 * @param[out] object_statuses List of status for every object. Caller needs to
 * allocate the buffer
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or
 * #SAI_STATUS_FAILURE when any of the objects fails to remove. When there is
 * failure, Caller is expected to go through the list of returned statuses to
 * find out which fails and which succeeds.
 */
static sai_status_t mlnx_bulk_get_route_entry_attribute(_In_ uint32_t                 object_count,
                                                        _In_ const sai_route_entry_t *route_entry,
                                                        _In_ const uint32_t          *attr_count,
                                                        _Inout_ sai_attribute_t     **attr_list,
                                                        _In_ sai_bulk_op_error_mode_t mode,
                                                        _Out_ sai_status_t           *object_statuses)
{
    return mlnx_route_bulk_api_impl(SAI_COMMON_API_BULK_GET, object_count, route_entry, attr_count, NULL, attr_list,
                                    NULL, mode, object_statuses);
}

static sai_status_t mlnx_bmtor_rif_event(_In_ sx_router_interface_t sx_rif, bool is_add)
{
    sx_status_t     sx_status;
    fx_handle_t    *p_fx_handle = NULL;
    sx_api_handle_t sx_handle = get_sdk_handle();

    /* Check if initialized */
    sx_status = fx_default_handle_get(&p_fx_handle, &sx_handle, 0);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failure in obtaining the default fx_handle\n");
        return SAI_STATUS_FAILURE;
    }

    if (!*p_fx_handle) {
        SX_LOG_DBG("FX handle wasn't initialized\n");
        return SAI_STATUS_SUCCESS;
    }

    SX_LOG_DBG("bmtor event: %s rif %d\n", is_add ? "adding" : "removing", sx_rif);

    sx_status = fx_pipe_binding_update(*p_fx_handle, FX_CONTROL_OUT_RIF, &sx_rif, is_add);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to update fx mapping\n");
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bmtor_rif_event_add(_In_ sx_router_interface_t sx_rif)
{
    return mlnx_bmtor_rif_event(sx_rif, true);
}

sai_status_t mlnx_bmtor_rif_event_del(_In_ sx_router_interface_t sx_rif)
{
    return mlnx_bmtor_rif_event(sx_rif, false);
}

sai_status_t sai_fx_uninitialize(void)
{
    return sdk_to_sai(fx_default_handle_free());
}

const sai_route_api_t mlnx_route_api = {
    mlnx_create_route,
    mlnx_remove_route,
    mlnx_set_route_attribute,
    mlnx_get_route_attribute,
    mlnx_bulk_create_route_entry,
    mlnx_bulk_remove_route_entry,
    mlnx_bulk_set_route_entry_attribute,
    mlnx_bulk_get_route_entry_attribute
};
