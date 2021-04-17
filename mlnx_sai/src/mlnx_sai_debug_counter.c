/*
 *  Copyright (C) 2019. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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

#include "saimetadata.h"

#undef  __MODULE__
#define __MODULE__ SAI_DEBUG_COUNTER

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t mlnx_hostif_trap_group_allocate(_Out_ sx_trap_group_t *trap_group);
sai_status_t mlnx_hostif_trap_group_free(_In_ sx_trap_group_t trap_group);
uint32_t mlnx_hostif_trap_group_db_free_entries_count(void);
sai_status_t db_init_sai_policer_data(_In_ sx_policer_attributes_t* policer_attr,
                                      _Out_ uint32_t              * db_policers_entry_index_p);
void db_reset_policer_entry(_In_ uint32_t db_policers_entry_index);
uint32_t mlnx_policer_db_free_entries_count(bool is_hostif);
sai_status_t mlnx_policer_stats_get(_In_ sx_policer_id_t sx_policer, _In_ uint64_t       *count);
sai_status_t mlnx_policer_stats_clear(_In_ sx_policer_id_t sx_policer);
sai_status_t mlnx_hostif_sx_trap_is_configured(_In_ sx_trap_id_t          sx_trap,
                                               _Out_ sai_packet_action_t *action,
                                               _Out_ bool                *is_configured);

static sai_status_t mlnx_debug_counter_attr_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_debug_counter_attr_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static const sai_vendor_attribute_entry_t debug_counter_vendor_attribs[] = {
    { SAI_DEBUG_COUNTER_ATTR_INDEX,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_debug_counter_attr_get, (void*)SAI_DEBUG_COUNTER_ATTR_INDEX,
      NULL, NULL },
    { SAI_DEBUG_COUNTER_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_debug_counter_attr_get, (void*)SAI_DEBUG_COUNTER_ATTR_TYPE,
      NULL, NULL },
    { SAI_DEBUG_COUNTER_ATTR_BIND_METHOD,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_debug_counter_attr_get, (void*)SAI_DEBUG_COUNTER_ATTR_BIND_METHOD,
      NULL, NULL },
    { SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_debug_counter_attr_get, (void*)SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST,
      mlnx_debug_counter_attr_set, (void*)SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static sai_status_t mlnx_dbg_counter_in_drop_reasons_capab_get(int32_t *attrs, uint32_t *count);
static const mlnx_attr_enum_info_t debug_counter_enum_info[] = {
    [SAI_DEBUG_COUNTER_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS),
    [SAI_DEBUG_COUNTER_ATTR_BIND_METHOD] = ATTR_ENUM_VALUES_ALL(),
    [SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST] = ATTR_ENUM_VALUES_FN(mlnx_dbg_counter_in_drop_reasons_capab_get),
};
const mlnx_obj_type_attrs_info_t   mlnx_debug_counter_obj_type_info =
{ debug_counter_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(debug_counter_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};

typedef enum mlnx_dbg_counter_drop_reason_type {
    DROP_REASON_TYPE_INVALID,
    DROP_REASON_TYPE_IN_L2,
    DROP_REASON_TYPE_IN_L3,
    DROP_REASON_TYPE_IN_TUNNEL,
    DROP_REASON_TYPE_IN_ACL,
    DROP_REASON_TYPE_OUT_L2,
    DROP_REASON_TYPE_OUT_L3,
    DROP_REASON_TYPE_MAX
} mlnx_dbg_counter_drop_reason_type_t;
typedef struct mlnx_dbg_counter_drop_reason_info {
    sai_s32_list_t                      trap_list;
    mlnx_dbg_counter_drop_reason_type_t type;
    bool                                is_group;
} mlnx_dbg_counter_drop_reason_info_t;

#define TRAP_LIST(...)                                           \
    {.list = (int32_t[ATTR_ARR_LEN(__VA_ARGS__)]) {__VA_ARGS__}, \
     .count = ATTR_ARR_LEN(__VA_ARGS__) }
#define TRAP_LIST_EMPTY() {.list = NULL, .count = 0}

#define MLNX_DBG_COUNTER_DROP_REASON_INFO_IS_VALID(info, reason) \
    (((size_t)reason < info->drop_reasons_count) && (info->drop_reasons[reason].type != DROP_REASON_TYPE_INVALID))

#define REASON_GROUP(type)  {TRAP_LIST_EMPTY(), type, true}
#define REASON(traps, type) {traps, type, false}

typedef struct mlnx_drop_counter_stage_info {
    const mlnx_dbg_counter_drop_reason_info_t *drop_reasons;
    size_t                                     drop_reasons_count;
} mlnx_drop_counter_stage_info_t;

static const mlnx_dbg_counter_drop_reason_info_t mlnx_drop_counter_in_drop_reasons_map[] = {
    /* L2 */
    [SAI_IN_DROP_REASON_L2_ANY] = REASON_GROUP(DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_SMAC_MULTICAST] = REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_ING_PACKET_SMAC_MC,
                                                           SX_TRAP_ID_DISCARD_OVERLAY_SWITCH_SMAC_MC),
                                                 DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_SMAC_EQUALS_DMAC] = REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_ING_PACKET_SMAC_DMAC,
                                                             SX_TRAP_ID_DISCARD_OVERLAY_SWITCH_SMAC_DMAC),
                                                   DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_DMAC_RESERVED] = REASON(TRAP_LIST(
                                                    SX_TRAP_ID_DISCARD_ING_PACKET_RSV_MAC),
                                                DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_VLAN_TAG_NOT_ALLOWED] = REASON(TRAP_LIST(
                                                           SX_TRAP_ID_DISCARD_ING_SWITCH_VTAG_ALLOW),
                                                       DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_INGRESS_VLAN_FILTER] = REASON(TRAP_LIST(
                                                          SX_TRAP_ID_DISCARD_ING_SWITCH_VLAN),
                                                      DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_INGRESS_STP_FILTER] = REASON(TRAP_LIST(
                                                         SX_TRAP_ID_DISCARD_ING_SWITCH_STP), DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_FDB_UC_DISCARD] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_LOOKUP_SWITCH_UC),
                                                 DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_FDB_MC_DISCARD] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_LOOKUP_SWITCH_MC_NULL),
                                                 DROP_REASON_TYPE_IN_L2),
    [SAI_IN_DROP_REASON_L2_LOOPBACK_FILTER] = REASON(TRAP_LIST(
                                                         SX_TRAP_ID_DISCARD_LOOKUP_SWITCH_LB),
                                                     DROP_REASON_TYPE_IN_L2),
    /* SAI_IN_DROP_REASON_EXCEEDS_L2_MTU, */
    /* L3 */
    [SAI_IN_DROP_REASON_L3_ANY] = REASON_GROUP(DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_EXCEEDS_L3_MTU] = REASON(TRAP_LIST(SX_TRAP_ID_ETH_L3_MTUERROR), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_TTL] = REASON(TRAP_LIST(SX_TRAP_ID_ETH_L3_TTLERROR), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_L3_LOOPBACK_FILTER] = REASON(TRAP_LIST(SX_TRAP_ID_ETH_L3_LBERROR), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_NON_ROUTABLE] =
        REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_NON_ROUTED), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_NO_L3_HEADER] = REASON(TRAP_LIST(
                                                   SX_TRAP_ID_DISCARD_ING_ROUTER_NO_HDR), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_IP_HEADER_ERROR] = REASON(TRAP_LIST(
                                                      SX_TRAP_ID_DISCARD_ING_ROUTER_IP_HDR), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_UC_DIP_MC_DMAC] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_ING_ROUTER_UC_DIP_MC_DMAC),
                                                 DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_DIP_LOOPBACK] = REASON(TRAP_LIST(
                                                   SX_TRAP_ID_DISCARD_ING_ROUTER_DIP_LB), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_SIP_LOOPBACK] = REASON(TRAP_LIST(
                                                   SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_LB), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_SIP_MC] = REASON(TRAP_LIST(
                                             SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_MC), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_SIP_CLASS_E] = REASON(TRAP_LIST(
                                                  SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_CLASS_E),
                                              DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_SIP_UNSPECIFIED] = REASON(TRAP_LIST(
                                                      SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_UNSP),
                                                  DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_MC_DMAC_MISMATCH] = REASON(TRAP_LIST(
                                                       SX_TRAP_ID_DISCARD_ING_ROUTER_MC_DMAC), DROP_REASON_TYPE_IN_L3),
#ifndef ACS_OS
    [SAI_IN_DROP_REASON_SIP_EQUALS_DIP] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_DIP), DROP_REASON_TYPE_IN_L3),
#endif
    [SAI_IN_DROP_REASON_SIP_BC] = REASON(TRAP_LIST(
                                             SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_BC), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_DIP_LOCAL] = REASON(TRAP_LIST(
                                                SX_TRAP_ID_DISCARD_ING_ROUTER_DIP_LOCAL_NET),
                                            DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_DIP_LINK_LOCAL] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_ING_ROUTER_DIP_LINK_LOCAL),
                                                 DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_SIP_LINK_LOCAL] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_ING_ROUTER_SIP_LINK_LOCAL),
                                                 DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_IPV6_MC_SCOPE0] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_MC_SCOPE_IPV6_0), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_IPV6_MC_SCOPE1] = REASON(TRAP_LIST(
                                                     SX_TRAP_ID_DISCARD_MC_SCOPE_IPV6_1), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_IRIF_DISABLED] = REASON(TRAP_LIST(
                                                    SX_TRAP_ID_DISCARD_ROUTER_IRIF_EN), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_ERIF_DISABLED] = REASON(TRAP_LIST(
                                                    SX_TRAP_ID_DISCARD_ROUTER_ERIF_EN), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_LPM4_MISS] =
        REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_ROUTER_LPM4), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_LPM6_MISS] =
        REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_ROUTER_LPM6), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_BLACKHOLE_ROUTE] = REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_ROUTER2), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_BLACKHOLE_ARP] = REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_ROUTER3), DROP_REASON_TYPE_IN_L3),
    [SAI_IN_DROP_REASON_UNRESOLVED_NEXT_HOP] = REASON(TRAP_LIST(SX_TRAP_ID_HOST_MISS_IPV4, SX_TRAP_ID_HOST_MISS_IPV6),
                                                      DROP_REASON_TYPE_IN_L3),
    /* SAI_IN_DROP_REASON_L3_EGRESS_LINK_DOWN, */
    /* Tunnel */
    [SAI_IN_DROP_REASON_DECAP_ERROR] = REASON(TRAP_LIST(SX_TRAP_ID_DISCARD_DEC_PKT, SX_TRAP_ID_DECAP_ECN1,
                                                        SX_TRAP_ID_IPIP_DECAP_ERROR, SX_TRAP_ID_FID_MISS,
                                                        SX_TRAP_ID_DISCARD_OVERLAY_SWITCH_SMAC_MC,
                                                        SX_TRAP_ID_DISCARD_OVERLAY_SWITCH_SMAC_DMAC),
                                              DROP_REASON_TYPE_IN_TUNNEL),

    /* ACL */
    [SAI_IN_DROP_REASON_ACL_ANY] = REASON(TRAP_LIST(SX_TRAP_ID_ACL_DROP, SX_TRAP_ID_SYS_ACL_DROP),
                                          DROP_REASON_TYPE_IN_ACL),
};
static const mlnx_drop_counter_stage_info_t      mlnx_drop_counter_in_drop_reasons_info =
{mlnx_drop_counter_in_drop_reasons_map, ARRAY_SIZE(mlnx_drop_counter_in_drop_reasons_map)};
static const mlnx_drop_counter_stage_info_t mlnx_drop_counter_out_drop_reasons_info = {NULL, 0};

/* Mapping is mostly 1 reason = 1 sx trap. There are 3 reasons that are mapped to 2 traps */
#define MLNX_DBG_COUNTER_TRAP_COUNT_MAX (MLNX_DEBUG_COUNTER_MAX_REASONS + 3)

static const sx_trap_id_t conflicting_traps_list[] = {
    SX_TRAP_ID_HOST_MISS_IPV4,
    SX_TRAP_ID_HOST_MISS_IPV6,
    SX_TRAP_ID_ETH_L3_MTUERROR,
    SX_TRAP_ID_ETH_L3_TTLERROR
};

sai_status_t mlnx_debug_counter_db_init(void)
{
    uint32_t ii;

    for (ii = 0; ii < ARRAY_SIZE(conflicting_traps_list); ii++) {
        g_sai_db_ptr->debug_counter_traps[ii].trap_id = conflicting_traps_list[ii];
        g_sai_db_ptr->debug_counter_traps[ii].bound_counter_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_db_find(_In_ sx_trap_id_t sx_trap, _Out_ mlnx_debug_counter_trap_t **trap_db)
{
    uint32_t ii;

    for (ii = 0; ii < ARRAY_SIZE(conflicting_traps_list); ii++) {
        if (g_sai_db_ptr->debug_counter_traps[ii].trap_id == sx_trap) {
            *trap_db = &g_sai_db_ptr->debug_counter_traps[ii];
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_FAILURE;
}

static void debug_counter_key_to_str(_In_ const sai_object_id_t debug_counter_obj_id, _Out_ char *key_str)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_oid;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_DEBUG_COUNTER, debug_counter_obj_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid sai debug counter obj ID %" PRId64 "", debug_counter_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "Debug counter obj idx %d",
                 mlnx_oid.id.debug_counter_db_idx.idx);
    }
}

sai_status_t mlnx_shm_rm_debug_counter_size_get(_Out_ size_t *size)
{
    *size = MIN(g_resource_limits.policer_host_ifc_pool_size, g_resource_limits.hw_trap_groups_num_max);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_dbg_counter_in_drop_reasons_capab_get(int32_t *attrs, uint32_t *count)
{
    const mlnx_drop_counter_stage_info_t *info;
    sai_in_drop_reason_t                  reason;
    uint32_t                              added = 0;

    assert(attrs);
    assert(*count >= mlnx_drop_counter_in_drop_reasons_info.drop_reasons_count);

    info = &mlnx_drop_counter_in_drop_reasons_info;

    for (reason = 0; reason < mlnx_drop_counter_in_drop_reasons_info.drop_reasons_count; reason++) {
        if (MLNX_DBG_COUNTER_DROP_REASON_INFO_IS_VALID(info, reason)) {
            attrs[added] = reason;
            added++;
        }
    }

    *count = added;
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_debug_counter_availability_get(_In_ sai_object_id_t        switch_id,
                                                 _In_ uint32_t               attr_count,
                                                 _In_ const sai_attribute_t *attr_list,
                                                 _Out_ uint64_t             *count)
{
    uint32_t policer_db_free, trap_group_db_free, debug_counter_db_free;

    assert(attr_list);
    assert(count);

    if (attr_count > 1) {
        SX_LOG_ERR("Unexpected attribute list (size > 1)\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (attr_list[0].id != SAI_DEBUG_COUNTER_ATTR_TYPE) {
        SX_LOG_ERR("Unexpected attribute %d, expected SAI_DEBUG_COUNTER_ATTR_TYPE\n", attr_list[0].id);
        return SAI_STATUS_INVALID_ATTRIBUTE_0;
    }

    if ((attr_list[0].value.s32 != SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) &&
        (attr_list[0].value.s32 != SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS)) {
        SX_LOG_ERR("Unsupported debug counter type - %d\n", attr_list[0].value.s32);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    policer_db_free = mlnx_policer_db_free_entries_count(true);
    trap_group_db_free = mlnx_hostif_trap_group_db_free_entries_count();
    debug_counter_db_free = mlnx_shm_rm_array_free_entries_count(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER);

    SX_LOG_DBG("policer_db_free %u, trap_group_db_free %u, debug_counter_db_free %u\n",
               policer_db_free, trap_group_db_free, debug_counter_db_free);

    *count = MIN(debug_counter_db_free, MIN(policer_db_free, trap_group_db_free));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_db_alloc(_Out_ mlnx_debug_counter_t   **dbg_counter,
                                                _Out_ mlnx_shm_rm_array_idx_t *idx)
{
    sai_status_t status;
    void        *ptr;

    assert(dbg_counter);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER, idx, &ptr);
    if (SAI_ERR(status)) {
        return status;
    }

    *dbg_counter = ptr;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_db_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx,
                                                      _Out_ mlnx_debug_counter_t **dbg_counter)
{
    sai_status_t status;
    void        *data;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    if (SAI_ERR(status)) {
        return status;
    }

    *dbg_counter = (mlnx_debug_counter_t*)data;

    if (!(*dbg_counter)->array_hdr.is_used) {
        SX_LOG_ERR("Debug counter at index %u is removed or not created yet\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_db_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t          status;
    mlnx_debug_counter_t *dbg_counter;

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_debug_counter_db_idx_to_data(idx, &dbg_counter);
    if (SAI_ERR(status)) {
        return status;
    }

    dbg_counter->type = 0;
    dbg_counter->policer_db_idx = 0;
    dbg_counter->sx_trap_group = SX_TRAP_GROUP_INVALID;
    memset(dbg_counter->drop_reasons, 0, sizeof(dbg_counter->drop_reasons));

    return mlnx_shm_rm_array_free(idx);
}

static sai_status_t mlnx_debug_counter_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t        *oid)
{
    mlnx_object_id_t *mlnx_oid = (mlnx_object_id_t*)oid;

    assert(oid);

    memset(oid, 0, sizeof(*oid));

    mlnx_oid->object_type = SAI_OBJECT_TYPE_DEBUG_COUNTER;
    mlnx_oid->id.debug_counter_db_idx = idx;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_oid_to_data(_In_ sai_object_id_t           oid,
                                                   _Out_ mlnx_debug_counter_t   **dbg_counter,
                                                   _Out_ mlnx_shm_rm_array_idx_t *idx)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_oid;

    assert(dbg_counter);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_DEBUG_COUNTER, oid, &mlnx_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_debug_counter_db_idx_to_data(mlnx_oid.id.debug_counter_db_idx, dbg_counter);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx) {
        *idx = mlnx_oid.id.debug_counter_db_idx;
    }

    return SAI_STATUS_SUCCESS;
}

/* To be used when policer is fixed
 *  static sai_status_t mlnx_debug_counter_switch_stat_to_policer(_In_ sai_switch_stat_t  stat,
 *                                                             _Out_ sx_policer_id_t  *sx_policer)
 *  {
 *   sai_status_t             status;
 *   mlnx_debug_counter_t    *dbg_counter;
 *   sai_debug_counter_type_t type;
 *   mlnx_shm_rm_array_idx_t  rm_idx;
 *   sx_policer_id_t          db_policer;
 *
 *   assert(MLNX_SWITCH_STAT_ID_RANGE_CHECK(stat));
 *   assert(sx_policer);
 *
 *   if (stat < SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_END) {
 *       type = SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS;
 *       rm_idx.idx = stat - SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_BASE;
 *   } else {
 *       type = SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS;
 *       rm_idx.idx = stat - SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_BASE;
 *   }
 *
 *   rm_idx.type = MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER;
 *
 *   status = mlnx_debug_counter_db_idx_to_data(rm_idx, &dbg_counter);
 *   if (SAI_ERR(status)) {
 *       return status;
 *   }
 *
 *   if (dbg_counter->type != type) {
 *       SX_LOG_ERR("Counter at index %u has a different type - %d\n", stat, dbg_counter->type);
 *       return SAI_STATUS_INVALID_ATTRIBUTE_0;
 *   }
 *
 *   if (dbg_counter->sx_trap_group == SX_TRAP_GROUP_INVALID) {
 *       SX_LOG_ERR("Trap group for counter idx %u is invalid\n", rm_idx.idx);
 *       return SAI_STATUS_FAILURE;
 *   }
 *
 *   if (dbg_counter->policer_db_idx >= MAX_POLICERS) {
 *       SX_LOG_ERR("Policer db index %u for counter idx %u is invalid\n", dbg_counter->policer_db_idx, rm_idx.idx);
 *       return SAI_STATUS_FAILURE;
 *   }
 *
 *   db_policer = g_sai_db_ptr->policers_db[dbg_counter->policer_db_idx].sx_policer_id_trap;
 *   if (db_policer == SX_POLICER_ID_INVALID) {
 *       SX_LOG_ERR("Policer id for counter idx %lu is invalid\n", db_policer);
 *       return SAI_STATUS_FAILURE;
 *   }
 *
 * sx_policer = db_policer;
 *
 *   return SAI_STATUS_SUCCESS;
 *  }*/

static sai_status_t mlnx_debug_counter_trap_group_stats_get(_In_ sx_trap_group_t sx_trap_group,
                                                            _In_ bool            clear,
                                                            _Out_ uint64_t      *value)
{
    sx_status_t                   sx_status;
    sx_host_ifc_counters_t       *cntrs = NULL;
    sx_host_ifc_counters_filter_t filter;
    sx_access_cmd_t               cmd;

    assert(value || clear);

    memset(&filter, 0, sizeof(filter));

    cntrs = calloc(1, sizeof(*cntrs));
    if (!cntrs) {
        SX_LOG_ERR("Failed to allocate a memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    filter.counter_type = HOST_IFC_COUNTER_TYPE_TRAP_GROUP_E;
    filter.u_counter_type.trap_group.trap_group_filter_cnt = 1;
    filter.u_counter_type.trap_group.trap_group_filter_list[0] = sx_trap_group;
    cntrs->trap_group_counters_cnt = 1;
    cmd = clear ? SX_ACCESS_CMD_READ_CLEAR : SX_ACCESS_CMD_READ;

    sx_status = sx_api_host_ifc_counters_get(gh_sdk, cmd, &filter, cntrs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("failed to sx_api_host_ifc_counters_get() - %s\n", SX_STATUS_MSG(sx_status));
        free(cntrs);
        return sdk_to_sai(sx_status);
    }

    if (value) {
        *value = cntrs->trap_group_counters[0].tocpu_packet +
                 cntrs->trap_group_counters[0].tocpu_drop_exceed_rate_packet.violation_counter;
    }

    free(cntrs);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_trap_group_stats_clear(_In_ sx_trap_group_t sx_trap_group)
{
    return mlnx_debug_counter_trap_group_stats_get(sx_trap_group, true, NULL);
}

static sai_status_t mlnx_debug_counter_stats_get(_In_ sai_switch_stat_t stat,
                                                 _In_ bool              clear,
                                                 _Out_ uint64_t        *value)
{
    sai_status_t            status;
    mlnx_debug_counter_t   *dbg_counter;
    mlnx_shm_rm_array_idx_t rm_idx;

    assert(MLNX_SWITCH_STAT_ID_RANGE_CHECK(stat));
    assert(value);


    if (stat < SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_END) {
        rm_idx.idx = stat - SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_BASE;
    } else {
        rm_idx.idx = stat - SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_BASE;
    }

    rm_idx.type = MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER;

    status = mlnx_debug_counter_db_idx_to_data(rm_idx, &dbg_counter);
    if (SAI_ERR(status)) {
        return status;
    }

    return mlnx_debug_counter_trap_group_stats_get(dbg_counter->sx_trap_group, clear, value);
}

sai_status_t mlnx_debug_counter_switch_stats_get(_In_ uint32_t             number_of_counters,
                                                 _In_ const sai_stat_id_t *counter_ids,
                                                 _In_ bool                 read,
                                                 _In_ bool                 clear,
                                                 _Out_ uint64_t           *counters)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint64_t     counter;
    uint32_t     ii;

    assert(counter_ids);
    assert(counters || !read);

    sai_db_read_lock();

    for (ii = 0; ii < number_of_counters; ii++) {
        status = mlnx_debug_counter_stats_get(counter_ids[ii], clear, &counter);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (read) {
            counters[ii] = counter;
        }
    }

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_debug_counter_drop_reason_list_expand(_In_ const mlnx_drop_counter_stage_info_t *info,
                                                               _In_ const int32_t                        *drop_reasons,
                                                               _In_ uint32_t                              drop_reasons_count,
                                                               _Out_ int32_t                             *drop_reasons_expanded,
                                                               _Inout_ uint32_t                          *drop_reasons_expanded_count)
{
    const mlnx_dbg_counter_drop_reason_info_t *reason_info;
    mlnx_dbg_counter_drop_reason_type_t        group_type;
    bool                                       group_drop_reasons[DROP_REASON_TYPE_MAX] = {false};
    uint32_t                                   drop_reason_idx, drop_reason;
    uint32_t                                   added = 0;

    assert(info);
    assert(drop_reasons);
    assert(drop_reasons_expanded);
    assert(*drop_reasons_expanded_count >= MLNX_DEBUG_COUNTER_MAX_REASONS);

    /* Check which group drop reasons are present in a list */
    for (drop_reason_idx = 0; drop_reason_idx < drop_reasons_count; drop_reason_idx++) {
        drop_reason = drop_reasons[drop_reason_idx];
        if (!MLNX_DBG_COUNTER_DROP_REASON_INFO_IS_VALID(info, drop_reason)) {
            SX_LOG_ERR("SAI drop reason %d is not defined in drop reason info map\n", drop_reason);
            return SAI_STATUS_FAILURE;
        }

        reason_info = &info->drop_reasons[drop_reason];

        if (reason_info->is_group) {
            group_drop_reasons[reason_info->type] = true;
        }
    }

    /* Adding all the reasons that belongs to found groups */
    for (group_type = DROP_REASON_TYPE_IN_L2; group_type < DROP_REASON_TYPE_MAX; group_type++) {
        if (group_drop_reasons[group_type]) {
            for (drop_reason = 0; drop_reason < info->drop_reasons_count; drop_reason++) {
                if (!MLNX_DBG_COUNTER_DROP_REASON_INFO_IS_VALID(info, drop_reason)) {
                    continue;
                }

                reason_info = &info->drop_reasons[drop_reason];
                /* not adding a group reason itself (e.g. SAI_IN_DROP_REASON_L2_ANY) */
                if ((reason_info->type == group_type) && (!reason_info->is_group)) {
                    drop_reasons_expanded[added] = drop_reason;
                    added++;
                }
            }
        }
    }

    /* process the regular non-group reasons */
    for (drop_reason_idx = 0; drop_reason_idx < drop_reasons_count; drop_reason_idx++) {
        drop_reason = drop_reasons[drop_reason_idx];
        if (!MLNX_DBG_COUNTER_DROP_REASON_INFO_IS_VALID(info, drop_reason)) {
            SX_LOG_ERR("SAI drop reason %d is not defined in drop reason info map\n", drop_reason);
            return SAI_STATUS_FAILURE;
        }

        /* skip what's already added as result of group expanding */
        reason_info = &info->drop_reasons[drop_reason];
        if (group_drop_reasons[reason_info->type]) {
            continue;
        }

        drop_reasons_expanded[added] = drop_reason;
        added++;
    }

    if (added > *drop_reasons_expanded_count) {
        SX_LOG_ERR("The drop_reasons_expanded_count %u is to small, needed %u\n", *drop_reasons_expanded_count, added);
        return SAI_STATUS_FAILURE;
    }

    *drop_reasons_expanded_count = added;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_drop_reasons_get(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                        _Out_ int32_t                   *drop_reasons,
                                                        _Inout_ uint32_t                *drop_reasons_count)
{
    uint32_t drop_reason, added = 0;

    assert(dbg_counter);
    assert(drop_reasons);
    assert(drop_reasons_count);
    assert(*drop_reasons_count >= MLNX_DEBUG_COUNTER_MAX_REASONS);

    for (drop_reason = 0; drop_reason < MLNX_DEBUG_COUNTER_MAX_REASONS; drop_reason++) {
        if (dbg_counter->drop_reasons[drop_reason]) {
            drop_reasons[added] = drop_reason;
            added++;
        }
    }

    *drop_reasons_count = added;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_drop_reasons_expanded_get(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                                 _Out_ int32_t                   *drop_reasons,
                                                                 _Inout_ uint32_t                *drop_reasons_count)
{
    sai_status_t                          status;
    const mlnx_drop_counter_stage_info_t *drop_reasons_info;
    int32_t                               drop_reasons_not_expanded[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t                              drop_reasons_not_expanded_count =
        MLNX_DEBUG_COUNTER_MAX_REASONS;

    assert(dbg_counter);
    assert(drop_reasons);
    assert(drop_reasons_count);
    assert(*drop_reasons_count >= MLNX_DEBUG_COUNTER_MAX_REASONS);

    status = mlnx_debug_counter_drop_reasons_get(dbg_counter,
                                                 drop_reasons_not_expanded,
                                                 &drop_reasons_not_expanded_count);
    if (SAI_ERR(status)) {
        return status;
    }

    if (dbg_counter->type == SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) {
        drop_reasons_info = &mlnx_drop_counter_in_drop_reasons_info;
    } else { /* SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS */
        drop_reasons_info = &mlnx_drop_counter_out_drop_reasons_info;
    }

    return mlnx_debug_counter_drop_reason_list_expand(drop_reasons_info, drop_reasons_not_expanded,
                                                      drop_reasons_not_expanded_count,
                                                      drop_reasons, drop_reasons_count);
}

static sai_status_t mlnx_debug_counter_drop_reasons_to_sdk(_In_ const mlnx_drop_counter_stage_info_t *info,
                                                           _In_ const int32_t                        *drop_reasons,
                                                           _In_ uint32_t                              drop_reasons_count,
                                                           _Out_ sx_trap_id_t                        *sx_traps,
                                                           _Inout_ uint32_t                          *sx_traps_count)
{
    const mlnx_dbg_counter_drop_reason_info_t *reason_info;
    int32_t                                    drop_reason;
    uint32_t                                   drop_reason_idx;
    uint32_t                                   traps_added = 0;

    assert(info);
    assert(drop_reasons);
    assert(sx_traps);
    assert(sx_traps_count);
    assert(*sx_traps_count >= MLNX_DBG_COUNTER_TRAP_COUNT_MAX);

    for (drop_reason_idx = 0; drop_reason_idx < drop_reasons_count; drop_reason_idx++) {
        drop_reason = drop_reasons[drop_reason_idx];
        if (!MLNX_DBG_COUNTER_DROP_REASON_INFO_IS_VALID(info, drop_reason)) {
            SX_LOG_ERR("SAI drop reason %d is not defined in drop reason info map\n", drop_reason);
            return SAI_STATUS_FAILURE;
        }

        reason_info = &info->drop_reasons[drop_reason];

        memcpy(&sx_traps[traps_added], reason_info->trap_list.list, sizeof(sx_trap_id_t) *
               reason_info->trap_list.count);
        traps_added += reason_info->trap_list.count;
    }

    if (traps_added > *sx_traps_count) {
        SX_LOG_ERR("Added more traps %u than expected %u\n", traps_added, *sx_traps_count);
        return SAI_STATUS_FAILURE;
    }

    *sx_traps_count = traps_added;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_drop_reasons_attr_get(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                             _Inout_ sai_s32_list_t          *list)
{
    sai_status_t status;
    int32_t      drop_reasons[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t     drop_reasons_count = MLNX_DEBUG_COUNTER_MAX_REASONS;

    assert(dbg_counter);
    assert(list);

    status = mlnx_debug_counter_drop_reasons_get(dbg_counter, drop_reasons, &drop_reasons_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return mlnx_fill_s32list(drop_reasons, drop_reasons_count, list);
}

static sai_status_t mlnx_debug_counter_attr_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t             status;
    sai_debug_counter_attr_t attr;
    mlnx_shm_rm_array_idx_t  db_idx;
    mlnx_debug_counter_t    *dbg_counter;

    attr = (int64_t)(arg);

    assert((SAI_DEBUG_COUNTER_ATTR_INDEX == attr) ||
           (SAI_DEBUG_COUNTER_ATTR_TYPE == attr) ||
           (SAI_DEBUG_COUNTER_ATTR_BIND_METHOD == attr) ||
           (SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST == attr) ||
           (SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST == attr));

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_debug_counter_oid_to_data(key->key.object_id, &dbg_counter, &db_idx);
    if (SAI_ERR(status)) {
        goto out;
    }

    switch (attr) {
    case SAI_DEBUG_COUNTER_ATTR_INDEX:
        value->s32 = db_idx.idx;
        break;

    case SAI_DEBUG_COUNTER_ATTR_TYPE:
        value->s32 = dbg_counter->type;
        break;

    case SAI_DEBUG_COUNTER_ATTR_BIND_METHOD:
        value->s32 = SAI_DEBUG_COUNTER_BIND_METHOD_AUTOMATIC;
        break;

    case SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST:
        if (dbg_counter->type != SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) {
            SX_LOG_ERR("Attribute IN_DROP_REASON_LIST is only valid for counter type SWITCH_IN_DROP_REASONS\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        status = mlnx_debug_counter_drop_reasons_attr_get(dbg_counter, &value->s32list);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    case SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST:
        if (dbg_counter->type != SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS) {
            SX_LOG_ERR("Attribute OUT_DROP_REASON_LIST is only valid for counter type SWITCH_OUT_DROP_REASONS\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        status = mlnx_debug_counter_drop_reasons_attr_get(dbg_counter, &value->s32list);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected attribute - %d\n", attr);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        break;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_debug_counter_drop_lists_diff(_In_ const mlnx_drop_counter_stage_info_t *info,
                                                       _In_ const int32_t                        *old_drop_reasons,
                                                       _In_ uint32_t                              old_drop_reasons_count,
                                                       _In_ const int32_t                        *new_drop_reasons,
                                                       _In_ uint32_t                              new_drop_reasons_count,
                                                       _Out_ int32_t                             *drop_reasons_to_remove,
                                                       _Inout_ uint32_t                          *drop_reasons_to_remove_count,
                                                       _Out_ int32_t                             *drop_reasons_to_add,
                                                       _Inout_ uint32_t                          *drop_reasons_to_add_count)
{
    uint32_t old_idx, new_idx;
    uint32_t to_remove_added = 0, to_add_added = 0;
    bool     old_present_in_new, new_present_in_old;

    assert(info);
    assert(old_drop_reasons);
    assert(new_drop_reasons);
    assert(drop_reasons_to_remove);
    assert(*drop_reasons_to_remove_count >= MLNX_DEBUG_COUNTER_MAX_REASONS);
    assert(drop_reasons_to_add);
    assert(*drop_reasons_to_add_count >= MLNX_DEBUG_COUNTER_MAX_REASONS);

    for (old_idx = 0; old_idx < old_drop_reasons_count; old_idx++) {
        old_present_in_new = false;
        for (new_idx = 0; new_idx < new_drop_reasons_count; new_idx++) {
            if (old_drop_reasons[old_idx] == new_drop_reasons[new_idx]) {
                old_present_in_new = true;
                break;
            }
        }

        if (!old_present_in_new) {
            drop_reasons_to_remove[to_remove_added] = old_drop_reasons[old_idx];
            to_remove_added++;
        }
    }

    for (new_idx = 0; new_idx < new_drop_reasons_count; new_idx++) {
        new_present_in_old = false;
        for (old_idx = 0; old_idx < old_drop_reasons_count; old_idx++) {
            if (new_drop_reasons[new_idx] == old_drop_reasons[old_idx]) {
                new_present_in_old = true;
                break;
            }
        }

        if (!new_present_in_old) {
            drop_reasons_to_add[to_add_added] = new_drop_reasons[new_idx];
            to_add_added++;
        }
    }

    *drop_reasons_to_remove_count = to_remove_added;
    *drop_reasons_to_add_count = to_add_added;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_update_sdk_global_acl_drop_trap_config_if_required(
    _In_ sai_debug_counter_type_t type,
    _In_ const int32_t           *drop_reasons_to_remove,
    _In_ const int32_t           *drop_reasons_to_add)
{
    sai_status_t               sai_status = SAI_STATUS_SUCCESS;
    sx_status_t                sx_status = SX_STATUS_SUCCESS;
    bool                       is_update = false;
    sx_acl_global_attributes_t acl_attrs = {0};
    int32_t                    drop_idx = SAI_IN_DROP_REASON_ACL_ANY;

    assert(drop_reasons_to_remove);
    assert(drop_reasons_to_add);

    assert(!(drop_reasons_to_remove[drop_idx] && drop_reasons_to_add[drop_idx]));

    if (type != SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) {
        goto out;
    }

    if (drop_reasons_to_remove[drop_idx]) {
        acl_attrs.disable_acl_drop_trap = 1;
        is_update = true;
    } else if (drop_reasons_to_add[drop_idx]) {
        acl_attrs.disable_acl_drop_trap = 0;
        is_update = true;
    }

    if (is_update) {
        sx_status = sx_api_acl_global_attributes_set(gh_sdk, SX_ACCESS_CMD_SET, acl_attrs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to %s global acl drop trap - %s \n",
                       acl_attrs.disable_acl_drop_trap ? "disable" : "enable",
                       SX_STATUS_MSG(sx_status));
            sai_status = sdk_to_sai(sx_status);
            goto out;
        }
    }
out:
    return sai_status;
}

static sai_status_t mlnx_debug_counter_trap_action_handle(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                          _In_ sx_trap_id_t                sx_trap,
                                                          _In_ sai_packet_action_t         old_action,
                                                          _In_ sai_packet_action_t         new_action)
{
    sx_status_t             sx_status;
    sx_host_ifc_trap_key_t  trap_key;
    sx_host_ifc_trap_attr_t trap_attr;
    sx_access_cmd_t         cmd;
    sx_trap_action_t        sx_action;
    bool                    update = false;

    assert(dbg_counter);

    if ((old_action != SAI_PACKET_ACTION_DROP) &&
        (new_action == SAI_PACKET_ACTION_DROP)) {
        cmd = SX_ACCESS_CMD_SET;
        sx_action = SX_TRAP_ACTION_EXCEPTION_TRAP;
        update = true;
    }

    if ((old_action == SAI_PACKET_ACTION_DROP) &&
        (new_action != SAI_PACKET_ACTION_DROP)) {
        cmd = SX_ACCESS_CMD_UNSET;
        sx_action = SX_TRAP_ACTION_SET_FW_DEFAULT;
        update = true;
    }

    if (!update) {
        return SAI_STATUS_SUCCESS;
    }

    memset(&trap_key, 0, sizeof(trap_key));
    memset(&trap_attr, 0, sizeof(trap_attr));

    trap_key.type = HOST_IFC_TRAP_KEY_TRAP_ID_E;
    trap_key.trap_key_attr.trap_id = sx_trap;
    trap_attr.attr.trap_id_attr.trap_group = dbg_counter->sx_trap_group;
    trap_attr.attr.trap_id_attr.trap_action = sx_action;

    sx_status = sx_api_host_ifc_trap_id_ext_set(gh_sdk, cmd, &trap_key, &trap_attr);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s trap %u from group %u- %s\n", SX_ACCESS_CMD_STR(cmd),
                   sx_trap, dbg_counter->sx_trap_group, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_debug_counter_db_trap_action_update(_In_ sx_trap_id_t sx_trap, _In_ sai_packet_action_t action)
{
    sai_status_t               status;
    mlnx_debug_counter_trap_t *trap_db;
    mlnx_debug_counter_t      *dbg_counter;

    status = mlnx_debug_counter_db_find(sx_trap, &trap_db);
    if (SAI_ERR(status)) {
        return SAI_STATUS_SUCCESS;
    }

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(trap_db->bound_counter_idx)) {
        SX_LOG_DBG("Trap %u is not used for debug counter\n", sx_trap);
        trap_db->action = action;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_debug_counter_db_idx_to_data(trap_db->bound_counter_idx, &dbg_counter);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!dbg_counter->array_hdr.is_used) {
        SX_LOG_ERR("Debug counter %u bound to trap %u but not created or removed\n",
                   trap_db->bound_counter_idx.idx,
                   sx_trap);
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_debug_counter_trap_action_handle(dbg_counter, sx_trap, trap_db->action, action);
    if (SAI_ERR(status)) {
        return status;
    }

    trap_db->action = action;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_sx_trap_db_update(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                         _In_ sx_trap_id_t                sx_trap,
                                                         _In_ bool                        is_set,
                                                         _In_ bool                       *need_to_configure)
{
    sai_status_t               status;
    mlnx_shm_rm_array_idx_t    rm_idx;
    mlnx_debug_counter_trap_t *trap_db;
    sai_packet_action_t        action = SAI_PACKET_ACTION_TRAP;
    bool                       is_configured;

    assert(dbg_counter);
    assert(need_to_configure);

    status = mlnx_hostif_sx_trap_is_configured(sx_trap, &action, &is_configured);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!is_configured) {
        *need_to_configure = true;
        return SAI_STATUS_SUCCESS;
    }

    *need_to_configure = (action == SAI_PACKET_ACTION_DROP);

    status = mlnx_debug_counter_db_find(sx_trap, &trap_db);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("SX trap %u is user-configured but not found in counter db\n", sx_trap);
        return status;
    }

    trap_db->action = action;

    status = mlnx_shm_rm_array_type_ptr_to_idx(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER, dbg_counter, &rm_idx);
    if (SAI_ERR(status)) {
        return status;
    }

    if (is_set) {
        if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(trap_db->bound_counter_idx)) {
            SX_LOG_ERR("Attempt to bind dbg counter to trap %u that already bound to different counter %u\n",
                       sx_trap, trap_db->bound_counter_idx.idx);
            return SAI_STATUS_FAILURE;
        }

        trap_db->bound_counter_idx = rm_idx;
    } else {
        if (!MLNX_SHM_RM_ARRAY_IDX_EQUAL(trap_db->bound_counter_idx, rm_idx)) {
            SX_LOG_ERR("Unbinding dbg counter %u from trap %u, while trap is bound to counter %u\n",
                       rm_idx.idx, sx_trap, trap_db->bound_counter_idx.idx);
            return SAI_STATUS_FAILURE;
        }

        trap_db->bound_counter_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_sx_trap_group_update(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                            _In_ sx_trap_group_t             sx_trap_group,
                                                            _In_ const sx_trap_id_t         *sx_traps,
                                                            _In_ uint32_t                    sx_traps_count,
                                                            _In_ bool                        set)
{
    sai_status_t            status;
    sx_status_t             sx_status;
    sx_host_ifc_trap_key_t  trap_key;
    sx_host_ifc_trap_attr_t trap_attr;
    sx_access_cmd_t         cmd;
    sx_trap_action_t        action;
    uint32_t                trap_idx;
    bool                    need_to_configure;

    assert(sx_traps);

    memset(&trap_key, 0, sizeof(trap_key));
    memset(&trap_attr, 0, sizeof(trap_attr));

    cmd = set ? SX_ACCESS_CMD_SET : SX_ACCESS_CMD_UNSET;
    action = set ? SX_TRAP_ACTION_EXCEPTION_TRAP : SX_TRAP_ACTION_SET_FW_DEFAULT;

    for (trap_idx = 0; trap_idx < sx_traps_count; trap_idx++) {
        status = mlnx_debug_counter_sx_trap_db_update(dbg_counter, sx_traps[trap_idx], set, &need_to_configure);
        if (SAI_ERR(status)) {
            return status;
        }

        if (!need_to_configure) {
            SX_LOG_DBG("Skipping a trap %u\n", sx_traps[trap_idx]);
            continue;
        }

        trap_key.type = HOST_IFC_TRAP_KEY_TRAP_ID_E;
        trap_key.trap_key_attr.trap_id = sx_traps[trap_idx];
        trap_attr.attr.trap_id_attr.trap_group = sx_trap_group;
        trap_attr.attr.trap_id_attr.trap_action = action;

        sx_status = sx_api_host_ifc_trap_id_ext_set(gh_sdk, cmd, &trap_key, &trap_attr);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to %s trap %u from group %u- %s\n", SX_ACCESS_CMD_STR(cmd),
                       sx_traps[trap_idx], sx_trap_group, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_sx_trap_group_traps_set(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                               _In_ sx_trap_group_t             sx_trap_group,
                                                               _In_ const sx_trap_id_t         *sx_traps,
                                                               _In_ uint32_t                    sx_traps_count)
{
    return mlnx_debug_counter_sx_trap_group_update(dbg_counter, sx_trap_group, sx_traps, sx_traps_count, true);
}

static sai_status_t mlnx_debug_counter_sx_trap_group_traps_unset(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                                 _In_ sx_trap_group_t             sx_trap_group,
                                                                 _In_ const sx_trap_id_t         *sx_traps,
                                                                 _In_ uint32_t                    sx_traps_count)
{
    return mlnx_debug_counter_sx_trap_group_update(dbg_counter, sx_trap_group, sx_traps, sx_traps_count, false);
}

static sai_status_t mlnx_debug_counter_drop_list_db_set(_In_ mlnx_debug_counter_t *dbg_counter,
                                                        _In_ const sai_s32_list_t *drop_reasons)
{
    uint32_t ii;

    assert(dbg_counter);
    assert(drop_reasons);

    memset(dbg_counter->drop_reasons, 0, sizeof(dbg_counter->drop_reasons));

    for (ii = 0; ii < drop_reasons->count; ii++) {
        if (drop_reasons->list[ii] >= (int32_t)MLNX_DEBUG_COUNTER_MAX_REASONS) {
            SX_LOG_ERR("SAI drop reason %d is out of range for dbg_counter->drop_reasons db array (size is %u)",
                       drop_reasons->list[ii], MLNX_DEBUG_COUNTER_MAX_REASONS);
            return SAI_STATUS_FAILURE;
        }

        dbg_counter->drop_reasons[drop_reasons->list[ii]] = true;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_attr_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sai_status_t          status;
    mlnx_debug_counter_t *dbg_counter;
    int32_t               current_drop_reasons[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t              current_drop_reasons_count =
        MLNX_DEBUG_COUNTER_MAX_REASONS;
    int32_t  new_drop_reasons[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t new_drop_reasons_count =
        MLNX_DEBUG_COUNTER_MAX_REASONS;
    int32_t  drop_reasons_to_remove[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t drop_reasons_to_remove_count =
        MLNX_DEBUG_COUNTER_MAX_REASONS;
    int32_t  drop_reasons_to_add[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t drop_reasons_to_add_count =
        MLNX_DEBUG_COUNTER_MAX_REASONS;
    sx_trap_id_t                          sx_traps[MLNX_DBG_COUNTER_TRAP_COUNT_MAX];
    uint32_t                              sx_traps_count = MLNX_DBG_COUNTER_TRAP_COUNT_MAX;
    const mlnx_drop_counter_stage_info_t *drop_reasons_info;

    sai_db_write_lock();

    status = mlnx_debug_counter_oid_to_data(key->key.object_id, &dbg_counter, NULL);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    if (dbg_counter->type == SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) {
        drop_reasons_info = &mlnx_drop_counter_in_drop_reasons_info;
    } else { /* SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS */
        drop_reasons_info = &mlnx_drop_counter_out_drop_reasons_info;
    }

    status = mlnx_debug_counter_drop_reasons_expanded_get(dbg_counter,
                                                          current_drop_reasons,
                                                          &current_drop_reasons_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_drop_reason_list_expand(drop_reasons_info, value->s32list.list, value->s32list.count,
                                                        new_drop_reasons, &new_drop_reasons_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_drop_lists_diff(drop_reasons_info,
                                                current_drop_reasons, current_drop_reasons_count,
                                                new_drop_reasons, new_drop_reasons_count,
                                                drop_reasons_to_remove, &drop_reasons_to_remove_count,
                                                drop_reasons_to_add, &drop_reasons_to_add_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_update_sdk_global_acl_drop_trap_config_if_required(dbg_counter->type,
                                                                                   drop_reasons_to_remove,
                                                                                   drop_reasons_to_add);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* unset unneeded */
    status = mlnx_debug_counter_drop_reasons_to_sdk(drop_reasons_info, drop_reasons_to_remove,
                                                    drop_reasons_to_remove_count,
                                                    sx_traps, &sx_traps_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_sx_trap_group_traps_unset(dbg_counter,
                                                          dbg_counter->sx_trap_group,
                                                          sx_traps,
                                                          sx_traps_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* set needed */
    sx_traps_count = MLNX_DBG_COUNTER_TRAP_COUNT_MAX;
    status = mlnx_debug_counter_drop_reasons_to_sdk(drop_reasons_info, drop_reasons_to_add,
                                                    drop_reasons_to_add_count,
                                                    sx_traps, &sx_traps_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_sx_trap_group_traps_set(dbg_counter,
                                                        dbg_counter->sx_trap_group,
                                                        sx_traps,
                                                        sx_traps_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_drop_list_db_set(dbg_counter, &value->s32list);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_debug_counter_sx_init(_In_ mlnx_debug_counter_t *dbg_counter,
                                               _In_ const sx_trap_id_t   *sx_traps,
                                               _In_ uint32_t              sx_traps_count,
                                               _Out_ sx_trap_group_t     *sx_trap_group,
                                               _Out_ uint32_t            *policer_db_idx)
{
    sai_status_t               status;
    sx_status_t                sx_status;
    sx_policer_attributes_t    policer_attrs;
    sx_host_ifc_trap_key_t     trap_key;
    sx_host_ifc_trap_attr_t    trap_attr;
    sx_trap_group_attributes_t trap_group_attributes;
    sx_policer_id_t           *sx_policer = NULL;
    bool                       is_policer_bound = false, is_trap_group_set = false;

    memset(&policer_attrs, 0, sizeof(policer_attrs));
    memset(&trap_key, 0, sizeof(trap_key));
    memset(&trap_attr, 0, sizeof(trap_attr));
    memset(&trap_group_attributes, 0, sizeof(trap_group_attributes));

    *sx_trap_group = SX_TRAP_GROUP_INVALID;
    *policer_db_idx = (uint32_t)-1;

    /* Policer */
    policer_attrs.is_host_ifc_policer = true;
    policer_attrs.rate_type = SX_POLICER_RATE_TYPE_SINGLE_RATE_E;
    policer_attrs.red_action = SX_POLICER_ACTION_DISCARD;
    policer_attrs.cbs = 4;
    policer_attrs.cir = 0;

    status = db_init_sai_policer_data(&policer_attrs, policer_db_idx);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_policer = &g_sai_db_ptr->policers_db[*policer_db_idx].sx_policer_id_trap;

    sx_status = sx_api_policer_set(gh_sdk, SX_ACCESS_CMD_CREATE, &policer_attrs, sx_policer);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create sx policer - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    /* Trap group */
    status = mlnx_hostif_trap_group_allocate(sx_trap_group);
    if (SAI_ERR(status)) {
        goto out;
    }

    trap_group_attributes.prio = SX_TRAP_PRIORITY_MIN;
    trap_group_attributes.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
    trap_group_attributes.truncate_size = 0;
    trap_group_attributes.control_type = SX_CONTROL_TYPE_DEFAULT;

    sx_status = sx_api_host_ifc_trap_group_ext_set(gh_sdk, SX_ACCESS_CMD_SET, DEFAULT_ETH_SWID,
                                                   *sx_trap_group, &trap_group_attributes);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set trap group %u - %s\n", *sx_trap_group, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    is_trap_group_set = true;

    sx_status = sx_api_host_ifc_policer_bind_set(gh_sdk, SX_ACCESS_CMD_BIND, DEFAULT_ETH_SWID,
                                                 *sx_trap_group, *sx_policer);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to bind sx policer %lu to trap group %u - %s\n",
                   *sx_policer, *sx_trap_group, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    is_policer_bound = true;

    status = mlnx_debug_counter_sx_trap_group_traps_set(dbg_counter, *sx_trap_group, sx_traps, sx_traps_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_trap_group_stats_clear(*sx_trap_group);
    if (SAI_ERR(status)) {
        goto out;
    }

    SX_LOG_DBG("Created sx trap group %u and policer %lu (db idx %u)\n",
               *sx_trap_group, *sx_policer, *policer_db_idx);

out:
    if (SAI_ERR(status)) {
        if (is_policer_bound) {
            sx_api_host_ifc_policer_bind_set(gh_sdk, SX_ACCESS_CMD_UNBIND, DEFAULT_ETH_SWID,
                                             *sx_trap_group, *sx_policer);
        }

        if (is_trap_group_set) {
            sx_api_host_ifc_trap_group_ext_set(gh_sdk, SX_ACCESS_CMD_UNSET, DEFAULT_ETH_SWID,
                                               *sx_trap_group, NULL);
        }

        mlnx_hostif_trap_group_free(*sx_trap_group);

        if (sx_policer && (*sx_policer != SX_POLICER_ID_INVALID)) {
            sx_status = sx_api_policer_set(gh_sdk, SX_ACCESS_CMD_DESTROY, NULL, sx_policer);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to destroy a policer %lu on cleanup\n", *sx_policer);
            }
        }

        if (*policer_db_idx != (uint32_t)-1) {
            db_reset_policer_entry(*policer_db_idx);
        }
    }

    return status;
}

static sai_status_t mlnx_debug_counter_sx_unbind_traps(_In_ const mlnx_debug_counter_t *dbg_counter)
{
    sai_status_t            status;
    sx_host_ifc_trap_key_t  trap_key;
    sx_host_ifc_trap_attr_t trap_attr;
    sx_trap_id_t            sx_traps[MLNX_DBG_COUNTER_TRAP_COUNT_MAX];
    uint32_t                sx_traps_count =
        MLNX_DBG_COUNTER_TRAP_COUNT_MAX;
    int32_t  drop_reasons[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t drop_reasons_count =
        MLNX_DEBUG_COUNTER_MAX_REASONS;
    const mlnx_drop_counter_stage_info_t *drop_reasons_info;

    assert(dbg_counter);

    memset(&trap_key, 0, sizeof(trap_key));
    memset(&trap_attr, 0, sizeof(trap_attr));

    status = mlnx_debug_counter_drop_reasons_expanded_get(dbg_counter, drop_reasons, &drop_reasons_count);
    if (SAI_ERR(status)) {
        return status;
    }

    if (dbg_counter->type == SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) {
        drop_reasons_info = &mlnx_drop_counter_in_drop_reasons_info;
    } else { /* SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS */
        drop_reasons_info = &mlnx_drop_counter_out_drop_reasons_info;
    }

    status = mlnx_debug_counter_drop_reasons_to_sdk(drop_reasons_info, drop_reasons, drop_reasons_count,
                                                    sx_traps, &sx_traps_count);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_debug_counter_sx_trap_group_traps_unset(dbg_counter,
                                                          dbg_counter->sx_trap_group,
                                                          sx_traps,
                                                          sx_traps_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_sx_uninit(_In_ const mlnx_debug_counter_t *dbg_counter)
{
    sai_status_t    status;
    sx_status_t     sx_status;
    sx_policer_id_t sx_policer;

    assert(dbg_counter);

    status = mlnx_debug_counter_sx_unbind_traps(dbg_counter);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Policer */
    sx_policer = g_sai_db_ptr->policers_db[dbg_counter->policer_db_idx].sx_policer_id_trap;
    sx_status = sx_api_host_ifc_policer_bind_set(gh_sdk, SX_ACCESS_CMD_UNBIND, DEFAULT_ETH_SWID,
                                                 dbg_counter->sx_trap_group, sx_policer);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to unbind sx policer %lu from trap group %u - %s\n",
                   sx_policer, dbg_counter->sx_trap_group, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_policer_stats_clear(sx_policer);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_policer_set(gh_sdk, SX_ACCESS_CMD_DESTROY, NULL, &sx_policer);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy sx policer - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    db_reset_policer_entry(dbg_counter->policer_db_idx);

    /* Trap group */
    sx_status = sx_api_host_ifc_trap_group_ext_set(gh_sdk, SX_ACCESS_CMD_UNSET, DEFAULT_ETH_SWID,
                                                   dbg_counter->sx_trap_group, NULL);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove trap group %u - %s\n", dbg_counter->sx_trap_group, SX_STATUS_MSG(status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_hostif_trap_group_free(dbg_counter->sx_trap_group);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_drop_reasons_validate(_In_ sai_debug_counter_type_t type,
                                                             _In_ const int32_t           *drop_reasons,
                                                             _In_ uint32_t                 drop_reasons_count,
                                                             _In_ bool                    *is_valid)
{
    sai_status_t                status;
    const mlnx_debug_counter_t *dbg_counter;
    int32_t                     existing_drop_reasons[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t                    existing_drop_reasons_count = MLNX_DEBUG_COUNTER_MAX_REASONS;
    uint32_t                    db_size, dbg_counter_idx, ii, jj;
    void                       *ptr;

    assert(drop_reasons);
    assert(is_valid);

    db_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER);

    for (dbg_counter_idx = 0; dbg_counter_idx < db_size; dbg_counter_idx++) {
        status = mlnx_shm_rm_array_type_idx_to_ptr(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER, dbg_counter_idx, &ptr);
        if (SAI_ERR(status)) {
            return status;
        }

        dbg_counter = ptr;

        if ((!dbg_counter->array_hdr.is_used) || (dbg_counter->type != type)) {
            continue;
        }

        existing_drop_reasons_count = MLNX_DEBUG_COUNTER_MAX_REASONS;
        status = mlnx_debug_counter_drop_reasons_expanded_get(dbg_counter,
                                                              existing_drop_reasons,
                                                              &existing_drop_reasons_count);
        if (SAI_ERR(status)) {
            return status;
        }

        for (ii = 0; ii < drop_reasons_count; ii++) {
            for (jj = 0; jj < existing_drop_reasons_count; jj++) {
                if (drop_reasons[ii] == existing_drop_reasons[jj]) {
                    SX_LOG_ERR("Drop reason %d is already used for debug counter index %u\n",
                               drop_reasons[ii], dbg_counter_idx);
                    *is_valid = false;
                    return SAI_STATUS_SUCCESS;
                }
            }
        }
    }

    *is_valid = true;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_debug_counter_create_impl(_In_ sai_debug_counter_type_t type,
                                                   _In_ const sai_s32_list_t    *drop_reasons,
                                                   _Out_ sai_object_id_t        *object)
{
    sai_status_t    status = SAI_STATUS_SUCCESS;
    sx_status_t     sx_status = SX_STATUS_SUCCESS;
    sx_trap_group_t sx_trap_group = SX_TRAP_GROUP_INVALID;
    sx_trap_id_t    sx_traps[MLNX_DBG_COUNTER_TRAP_COUNT_MAX];
    uint32_t        sx_trap_count = MLNX_DBG_COUNTER_TRAP_COUNT_MAX;
    uint32_t        policer_db_idx;
    int32_t         drop_reasons_expanded[MLNX_DEBUG_COUNTER_MAX_REASONS] = {0};
    uint32_t        drop_reasons_expanded_count =
        MLNX_DEBUG_COUNTER_MAX_REASONS;
    mlnx_debug_counter_t                 *dbg_counter = NULL;
    mlnx_shm_rm_array_idx_t               dbg_counter_db_idx;
    bool                                  is_valid;
    const mlnx_drop_counter_stage_info_t *drop_reasons_info;
    sx_acl_global_attributes_t            acl_attrs = {0};

    assert((type == SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) ||
           (type == SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS));
    assert(drop_reasons);
    assert(object);

    sai_db_write_lock();

    status = mlnx_debug_counter_db_alloc(&dbg_counter, &dbg_counter_db_idx);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (type == SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) {
        drop_reasons_info = &mlnx_drop_counter_in_drop_reasons_info;
    } else { /* SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS */
        drop_reasons_info = &mlnx_drop_counter_out_drop_reasons_info;
    }

    status = mlnx_debug_counter_drop_reason_list_expand(drop_reasons_info, drop_reasons->list, drop_reasons->count,
                                                        drop_reasons_expanded, &drop_reasons_expanded_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_drop_reasons_validate(type,
                                                      drop_reasons_expanded,
                                                      drop_reasons_expanded_count,
                                                      &is_valid);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!is_valid) {
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = mlnx_debug_counter_drop_reasons_to_sdk(drop_reasons_info, drop_reasons_expanded,
                                                    drop_reasons_expanded_count, sx_traps, &sx_trap_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_sx_init(dbg_counter, sx_traps, sx_trap_count, &sx_trap_group, &policer_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to initialize sdk resources for debug counter\n");
        goto out;
    }

    dbg_counter->type = type;
    dbg_counter->sx_trap_group = sx_trap_group;
    dbg_counter->policer_db_idx = policer_db_idx;

    status = mlnx_debug_counter_drop_list_db_set(dbg_counter, drop_reasons);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_oid_create(dbg_counter_db_idx, object);
    if (SAI_ERR(status)) {
        goto out;
    }

    if ((SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS == dbg_counter->type) &&
        dbg_counter->drop_reasons[SAI_IN_DROP_REASON_ACL_ANY]) {
        sx_status = sx_api_acl_global_attributes_set(gh_sdk, SX_ACCESS_CMD_SET, acl_attrs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to enable global acl drop trap - %s \n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

out:
    if (SAI_ERR(status)) {
        if (dbg_counter) {
            mlnx_debug_counter_db_free(dbg_counter_db_idx);
        }
    }
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_create_debug_counter(_Out_ sai_object_id_t      *debug_counter_id,
                                              _In_ sai_object_id_t        switch_id,
                                              _In_ uint32_t               attr_count,
                                              _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *attr_id = NULL;
    sai_debug_counter_type_t     type;
    sai_debug_counter_attr_t     drop_list_attr;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                         key_str[MAX_KEY_STR_LEN] = {0};
    uint32_t                     attr_index;

    SX_LOG_ENTER();

    if (NULL == debug_counter_id) {
        SX_LOG_ERR("NULL debug_counter_id param.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count,
                                    attr_list,
                                    SAI_OBJECT_TYPE_DEBUG_COUNTER,
                                    debug_counter_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check.\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_DEBUG_COUNTER, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create debug counter object\nAttribs %s\n", list_str);

    find_attrib_in_list(attr_count, attr_list, SAI_DEBUG_COUNTER_ATTR_TYPE, &attr_id, &attr_index);
    assert(attr_id);

    type = attr_id->s32;

    if (type == SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS) {
        drop_list_attr = SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST;
    } else { /* SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS */
        drop_list_attr = SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST;
    }

    attr_id = NULL;
    find_attrib_in_list(attr_count, attr_list, drop_list_attr, &attr_id, &attr_index);
    assert(attr_id);

    status = mlnx_debug_counter_create_impl(type, &attr_id->s32list, debug_counter_id);
    if (SAI_ERR(status)) {
        return status;
    }

    debug_counter_key_to_str(*debug_counter_id, key_str);
    SX_LOG_NTC("Created %s\n", key_str);

    return status;
}

static sai_status_t mlnx_remove_debug_counter(_In_ sai_object_id_t debug_counter_id)
{
    sai_status_t               status = SAI_STATUS_SUCCESS;
    sx_status_t                sx_status = SX_STATUS_SUCCESS;
    mlnx_debug_counter_t      *dbg_counter = NULL;
    mlnx_shm_rm_array_idx_t    idx = {0};
    char                       key_str[MAX_KEY_STR_LEN] = {0};
    sx_acl_global_attributes_t acl_attrs = {.disable_acl_drop_trap = 1};

    SX_LOG_ENTER();

    debug_counter_key_to_str(debug_counter_id, key_str);
    SX_LOG_NTC("Remove %s\n", key_str);

    sai_db_write_lock();

    status = mlnx_debug_counter_oid_to_data(debug_counter_id, &dbg_counter, &idx);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    if ((SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS == dbg_counter->type) &&
        dbg_counter->drop_reasons[SAI_IN_DROP_REASON_ACL_ANY]) {
        sx_status = sx_api_acl_global_attributes_set(gh_sdk, SX_ACCESS_CMD_SET, acl_attrs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to disable global acl drop trap - %s \n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    status = mlnx_debug_counter_sx_uninit(dbg_counter);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_debug_counter_db_free(idx);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_set_debug_counter_attribute(_In_ const sai_object_id_t  debug_counter_id,
                                                     _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = debug_counter_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    debug_counter_key_to_str(debug_counter_id, key_str);

    status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_DEBUG_COUNTER,
                               debug_counter_vendor_attribs, attr);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_get_debug_counter_attribute(_In_ const sai_object_id_t debug_counter_id,
                                                     _In_ uint32_t              attr_count,
                                                     _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .key.object_id = debug_counter_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    debug_counter_key_to_str(debug_counter_id, key_str);

    status = sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_DEBUG_COUNTER,
                                debug_counter_vendor_attribs, attr_count, attr_list);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_debug_counter_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_debug_counter_api_t mlnx_debug_counter_api = {
    mlnx_create_debug_counter,
    mlnx_remove_debug_counter,
    mlnx_set_debug_counter_attribute,
    mlnx_get_debug_counter_attribute
};
