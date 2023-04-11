/*
 *  Copyright (C) 2019-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "sai.h"
#include "sai_windows.h"
#include "mlnx_sai.h"
#include "assert.h"

#undef  __MODULE__
#define __MODULE__ SAI_COUNTER

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t mlnx_counter_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (get_sdk_handle()) {
        return sdk_to_sai(sx_api_flow_counter_log_verbosity_level_set(get_sdk_handle(), SX_LOG_VERBOSITY_BOTH, level,
                                                                      level));
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_counter_db_alloc(_Out_ mlnx_counter_t **counter, _Out_ mlnx_shm_rm_array_idx_t  *idx)
{
    sai_status_t status;
    void        *ptr;

    SX_LOG_ENTER();

    assert(counter);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_COUNTER, idx, &ptr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed alloc counter entry\n");
        return status;
    }

    *counter = ptr;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_counter_db_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ mlnx_counter_t **counter)
{
    sai_status_t status;
    void        *data;

    SX_LOG_ENTER();

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed get counter db idx\n");
        return status;
    }

    *counter = (mlnx_counter_t*)data;

    if (!(*counter)->array_hdr.is_used) {
        SX_LOG_ERR("Counter at index %u is removed or not created yet\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_counter_db_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t    status;
    sx_status_t     sx_status;
    mlnx_counter_t *counter;

    SX_LOG_ENTER();

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_counter_db_idx_to_data(idx, &counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed get counter data\n");
        return status;
    }

    if (counter->hostif_trap_ids_cnt != 0) {
        SX_LOG_ERR("Hostif traps are still attached to a counter\n");
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if (counter->sx_flow_counter != SX_FLOW_COUNTER_ID_INVALID) {
        sx_status = sx_api_flow_counter_set(get_sdk_handle(),
                                            SX_ACCESS_CMD_DESTROY,
                                            SX_FLOW_COUNTER_TYPE_PACKETS_AND_BYTES,
                                            &counter->sx_flow_counter);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Flow counter delete error\n");
            return sdk_to_sai(sx_status);
        }
    }

    return mlnx_shm_rm_array_free(idx);
}

sai_status_t mlnx_counter_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t *oid)
{
    mlnx_object_id_t *mlnx_oid = (mlnx_object_id_t*)oid;

    SX_LOG_ENTER();

    assert(oid);

    memset(oid, 0, sizeof(*oid));

    mlnx_oid->object_type = SAI_OBJECT_TYPE_COUNTER;
    mlnx_oid->id.counter_db_idx = idx;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_counter_oid_to_data(_In_ sai_object_id_t           oid,
                                      _Out_ mlnx_counter_t         **counter_db_entry,
                                      _Out_ mlnx_shm_rm_array_idx_t *idx)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_oid;

    assert(counter_db_entry);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_COUNTER, oid, &mlnx_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_counter_db_idx_to_data(mlnx_oid.id.counter_db_idx, counter_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx) {
        *idx = mlnx_oid.id.counter_db_idx;
    }

    return SAI_STATUS_SUCCESS;
}

/* DB lock must be locked before calling this function */
sai_status_t mlnx_get_sx_flow_counter_id_by_idx(_In_ mlnx_shm_rm_array_idx_t idx,
                                                _Out_ sx_flow_counter_id_t  *sx_flow_counter)
{
    sai_status_t    status;
    sx_status_t     sx_status;
    mlnx_counter_t *counter;

    status = mlnx_counter_db_idx_to_data(idx, &counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get counter data\n");
        return status;
    }

    if (counter->sx_flow_counter == SX_FLOW_COUNTER_ID_INVALID) {
        sx_status = sx_api_flow_counter_set(get_sdk_handle(),
                                            SX_ACCESS_CMD_CREATE,
                                            SX_FLOW_COUNTER_TYPE_PACKETS_AND_BYTES,
                                            &counter->sx_flow_counter);
        if (SX_ERR(sx_status)) {
            counter->sx_flow_counter = SX_FLOW_COUNTER_ID_INVALID;
            SX_LOG_ERR("Failed to create flow counter data - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    *sx_flow_counter = counter->sx_flow_counter;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_counter_type_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static const sai_vendor_attribute_entry_t counter_vendor_attribs[] = {
    { SAI_COUNTER_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_counter_type_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        counter_enum_info[] = {
    [SAI_COUNTER_ATTR_TYPE] = ATTR_ENUM_VALUES_ALL()
};
static const sai_stat_capability_t        counter_stats_capabilities[] = {
    { SAI_COUNTER_STAT_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_COUNTER_STAT_BYTES, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
};
static size_t counter_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[ID:%u]", mlnx_oid.id.counter_db_idx.idx);
}
const mlnx_obj_type_attrs_info_t mlnx_counter_obj_type_info =
{ counter_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(counter_enum_info), OBJ_STAT_CAP_INFO(counter_stats_capabilities),
  counter_info_print};
static sai_status_t mlnx_counter_type_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t            status;
    mlnx_object_id_t        mlnx_oid;
    mlnx_shm_rm_array_idx_t idx;
    mlnx_counter_t         *counter;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_COUNTER, key->key.object_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get mlnx object id\n");
        return status;
    }
    idx = mlnx_oid.id.counter_db_idx;

    sai_db_read_lock();
    status = mlnx_counter_db_idx_to_data(idx, &counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get counter data\n");
    }
    sai_db_unlock();

    value->s32 = SAI_COUNTER_TYPE_REGULAR;
    return status;
}

static bool trap_counter_cmp(_In_ const void *elem, _In_ const void *trap_id_ptr)
{
    const mlnx_counter_t *counter = (mlnx_counter_t*)elem;
    const sai_object_id_t trap_id = *((const sai_object_id_t*)trap_id_ptr);
    uint32_t              ii = 0;

    for (; ii < counter->hostif_trap_ids_cnt; ii++) {
        if (counter->hostif_trap_ids[ii] == trap_id) {
            return true;
        }
    }

    return false;
}

/*requires sai_db read lock*/
sai_status_t mlnx_update_hostif_trap_counter_unlocked(sai_object_id_t trap_id, sai_object_id_t counter_id)
{
    mlnx_shm_rm_array_idx_t       idx;
    mlnx_counter_t               *prev_counter, *new_counter;
    sai_status_t                  status = SAI_STATUS_SUCCESS;
    uint32_t                      ii = 0;
    mlnx_object_id_t              mlnx_oid;
    sx_host_ifc_counters_filter_t hostif_trap_filter;
    sx_host_ifc_counters_t       *host_ifc_counters;
    sx_trap_id_t                  trap_ids[MAX_SDK_TRAPS_PER_SAI_TRAP];
    uint8_t                       trap_id_count;
    sx_status_t                   sx_status;

    SX_LOG_ENTER();

    memset(&hostif_trap_filter, 0, sizeof(hostif_trap_filter));

    status = mlnx_shm_rm_array_find(MLNX_SHM_RM_ARRAY_TYPE_COUNTER,
                                    &trap_counter_cmp,
                                    MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED,
                                    &trap_id,
                                    &idx,
                                    (void**)&prev_counter);
    if (!SAI_ERR(status)) {
        for (; ii < prev_counter->hostif_trap_ids_cnt; ii++) {
            if (prev_counter->hostif_trap_ids[ii] == trap_id) {
                prev_counter->hostif_trap_ids[ii] =
                    prev_counter->hostif_trap_ids[prev_counter->hostif_trap_ids_cnt - 1];
                prev_counter->hostif_trap_ids_cnt--;
                break;
            }
        }
    }

    if (counter_id == SAI_NULL_OBJECT_ID) {
        SX_LOG_NTC("Counter id - SAI_NULL_OBJECT_ID - unbind the counter\n");
        status = SAI_STATUS_SUCCESS;
        return status;
    }

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_COUNTER, counter_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get mlnx object id\n");
        return status;
    }
    idx = mlnx_oid.id.counter_db_idx;

    status = mlnx_counter_db_idx_to_data(idx, &new_counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get counter data\n");
        return status;
    }

    if (new_counter->hostif_trap_ids_cnt == MLNX_COUNTER_MAX_HOSTIF_TRAPS) {
        SX_LOG_ERR("Failed to attach trap: maximum traps per counter reached\n");
        status = SAI_STATUS_FAILURE;
        return status;
    }

    hostif_trap_filter.counter_type = HOST_IFC_COUNTER_TYPE_TRAP_ID_E;
    status = mlnx_translate_sai_trap_to_sdk(trap_id, &trap_id_count, &trap_ids);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate trap");
        return status;
    }

    for (ii = 0; ii < trap_id_count; ii++) {
        hostif_trap_filter.u_counter_type.trap_id.trap_id_filter_list[ii] = trap_ids[ii];
    }
    hostif_trap_filter.u_counter_type.trap_id.trap_id_filter_cnt = trap_id_count;

    host_ifc_counters = calloc(1, sizeof(*host_ifc_counters));
    if (!host_ifc_counters) {
        return SAI_STATUS_FAILURE;
    }

    host_ifc_counters->trap_id_counters_cnt = trap_id_count;
    host_ifc_counters->trap_group_counters_cnt = 0;
    sx_status = sx_api_host_ifc_counters_get(get_sdk_handle(),
                                             SX_ACCESS_CMD_READ_CLEAR,
                                             &hostif_trap_filter,
                                             host_ifc_counters);
    free(host_ifc_counters);

    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get hostif counters\n");
        return sdk_to_sai(sx_status);
    }

    new_counter->hostif_trap_ids[new_counter->hostif_trap_ids_cnt++] = trap_id;

    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_update_hostif_trap_counter(sai_object_id_t trap_id, sai_object_id_t counter_id)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    sai_db_write_lock();

    status = mlnx_update_hostif_trap_counter_unlocked(trap_id, counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update hostif trap counter\n");
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

sai_status_t mlnx_get_flow_counter_id(sai_object_id_t counter_id, sx_flow_counter_id_t *flow_counter_id)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    mlnx_shm_rm_array_idx_t idx;
    mlnx_object_id_t        mlnx_oid;

    SX_LOG_ENTER();

    if (SAI_NULL_OBJECT_ID == counter_id) {
        *flow_counter_id = SX_FLOW_COUNTER_ID_INVALID;
        SX_LOG_NTC("SAI_NULL_OBJECT_ID counter id\n");
        return status;
    }

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_COUNTER, counter_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get mlnx oid from counter id\n");
        return status;
    }
    idx = mlnx_oid.id.counter_db_idx;

    sai_db_write_lock();
    status = mlnx_get_sx_flow_counter_id_by_idx(idx, flow_counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get sx_flow_counter.\n");
        goto out;
    }

out:
    sai_db_unlock();

    return status;
}

static bool flow_counter_cmp(_In_ const void *elem, _In_ const void *flow_counter_ptr)
{
    const mlnx_counter_t      *counter = (mlnx_counter_t*)elem;
    const sx_flow_counter_id_t flow_counter = *((const sx_flow_counter_id_t*)flow_counter_ptr);

    return counter->sx_flow_counter == flow_counter;
}

sai_status_t mlnx_translate_flow_counter_to_sai_counter(sx_flow_counter_id_t flow_counter, sai_object_id_t *counter_id)
{
    mlnx_shm_rm_array_idx_t idx;
    mlnx_counter_t         *counter;
    sai_status_t            status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    assert(counter_id);

    if (flow_counter == SX_FLOW_COUNTER_ID_INVALID) {
        *counter_id = SAI_NULL_OBJECT_ID;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_shm_rm_array_find(MLNX_SHM_RM_ARRAY_TYPE_COUNTER,
                                    &flow_counter_cmp,
                                    MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED,
                                    &flow_counter,
                                    &idx,
                                    (void**)&counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to find counter\n");
        return status;
    }

    status = mlnx_counter_oid_create(idx, counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed create counter oid\n");
        return status;
    }

    return status;
}

sai_status_t mlnx_translate_trap_id_to_sai_counter(sai_object_id_t trap_id, sai_object_id_t *counter_id)
{
    mlnx_shm_rm_array_idx_t idx;
    mlnx_counter_t         *counter;
    sai_status_t            status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    assert(counter_id);

    status = mlnx_shm_rm_array_find(MLNX_SHM_RM_ARRAY_TYPE_COUNTER,
                                    &trap_counter_cmp,
                                    MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED,
                                    &trap_id,
                                    &idx,
                                    (void**)&counter);
    if (SAI_ERR(status)) {
        SX_LOG_NTC("Failed to find counter\n");
        *counter_id = SAI_NULL_OBJECT_ID;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_counter_oid_create(idx, counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed create counter oid\n");
        return status;
    }

    return status;
}

sai_status_t mlnx_create_counter(_Out_ sai_object_id_t      *counter_id,
                                 _In_ sai_object_id_t        switch_id,
                                 _In_ uint32_t               attr_count,
                                 _In_ const sai_attribute_t *attr_list)
{
    sai_status_t            status;
    mlnx_counter_t         *counter = NULL;
    mlnx_shm_rm_array_idx_t counter_db_idx;

    SX_LOG_ENTER();

    status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_COUNTER, counter_id);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_COUNTER);

    sai_db_write_lock();
    status = mlnx_counter_db_alloc(&counter, &counter_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed alloc db\n");
        goto out;
    }

    counter->hostif_trap_ids_cnt = 0;
    counter->sx_flow_counter = SX_FLOW_COUNTER_ID_INVALID;

    status = mlnx_counter_oid_create(counter_db_idx, counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed create oid\n");
        goto out;
    }

out:
    if ((NULL != counter) && SAI_ERR(status)) {
        mlnx_counter_db_free(counter_db_idx);
    } else {
        MLNX_LOG_OID_CREATED(*counter_id);
    }

    sai_db_unlock();

    return status;
}

sai_status_t mlnx_remove_counter(_In_ sai_object_id_t counter_id)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    mlnx_object_id_t        mlnx_oid;
    mlnx_shm_rm_array_idx_t idx;

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(counter_id);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_COUNTER, counter_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get mlnx object id\n");
        return status;
    }

    idx = mlnx_oid.id.counter_db_idx;

    sai_db_write_lock();
    status = mlnx_counter_db_free(idx);
    sai_db_unlock();

    return status;
}

static sai_status_t sum_counter_stats(_In_ uint32_t             number_of_counters,
                                      _In_ const sai_stat_id_t *counter_ids,
                                      _In_ uint64_t             packets_to_add,
                                      _In_ uint64_t             bytes_to_add,
                                      _Out_ uint64_t           *counters)
{
    uint32_t ii;

    SX_LOG_ENTER();

    for (ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_COUNTER_STAT_PACKETS:
            counters[ii] += packets_to_add;
            break;

        case SAI_COUNTER_STAT_BYTES:
            counters[ii] += bytes_to_add;
            break;

        default:
            SX_LOG_ERR("Unknown stats type\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
static sai_status_t get_hostif_counter_stats(_In_ mlnx_counter_t    *counter,
                                             _In_ sx_access_cmd_t    cmd,
                                             sx_host_ifc_counters_t *host_ifc_counters)
{
    sai_status_t                  status = SAI_STATUS_SUCCESS;
    sx_status_t                   sx_status;
    sx_host_ifc_counters_filter_t hostif_trap_filter;
    sx_trap_id_t                  trap_ids[MAX_SDK_TRAPS_PER_SAI_TRAP];
    uint8_t                       trap_id_count;
    uint32_t                      ii, jj, kk = 0;

    SX_LOG_ENTER();

    memset(&hostif_trap_filter, 0, sizeof(hostif_trap_filter));

    if (counter->hostif_trap_ids_cnt == 0) {
        return status;
    }

    hostif_trap_filter.counter_type = HOST_IFC_COUNTER_TYPE_TRAP_ID_E;
    for (ii = 0; ii < counter->hostif_trap_ids_cnt; ii++) {
        status = mlnx_translate_sai_trap_to_sdk(counter->hostif_trap_ids[ii], &trap_id_count, &trap_ids);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate trap\n");
            return status;
        }

        for (jj = 0; jj < trap_id_count; jj++) {
            hostif_trap_filter.u_counter_type.trap_id.trap_id_filter_list[kk++] = trap_ids[jj];
        }
    }
    hostif_trap_filter.u_counter_type.trap_id.trap_id_filter_cnt = kk;
    host_ifc_counters->trap_id_counters_cnt = kk;
    host_ifc_counters->trap_group_counters_cnt = 0;
    sx_status = sx_api_host_ifc_counters_get(get_sdk_handle(),
                                             cmd,
                                             &hostif_trap_filter,
                                             host_ifc_counters);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get hostif counters\n");
        status = sdk_to_sai(sx_status);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/*requires sai_db read lock*/
static sai_status_t sum_hostif_counter_stats(_In_ mlnx_counter_t      *counter,
                                             _In_ uint32_t             number_of_counters,
                                             _In_ sai_stats_mode_t     mode,
                                             _In_ const sai_stat_id_t *counter_ids,
                                             _Out_ uint64_t           *counters)
{
    sai_status_t           status = SAI_STATUS_SUCCESS;
    sx_access_cmd_t        cmd;
    sx_host_ifc_counters_t host_ifc_counters;
    uint32_t               ii;

    SX_LOG_ENTER();

    memset(&host_ifc_counters, 0, sizeof(host_ifc_counters));

    switch (mode) {
    case SAI_STATS_MODE_READ:
        cmd = SX_ACCESS_CMD_READ;
        break;

    case SAI_STATS_MODE_READ_AND_CLEAR:
        cmd = SX_ACCESS_CMD_READ_CLEAR;
        break;

    default:
        SX_LOG_ERR("Invalid stats mode\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = get_hostif_counter_stats(counter, cmd, &host_ifc_counters);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get hostifc counters\n");
        return status;
    }

    for (ii = 0; ii < host_ifc_counters.trap_id_counters_cnt; ii++) {
        status = sum_counter_stats(number_of_counters, counter_ids,
                                   host_ifc_counters.trap_id_counters[ii].u_trap_type.packet.tocpu_packet,
                                   host_ifc_counters.trap_id_counters[ii].u_trap_type.packet.tocpu_byte,
                                   counters);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to sum counter stats\n");
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sum_flow_counter_stats(_In_ mlnx_counter_t      *counter,
                                           _In_ uint32_t             number_of_counters,
                                           _In_ const sai_stat_id_t *counter_ids,
                                           _In_ sai_stats_mode_t     mode,
                                           _Out_ uint64_t           *counters)
{
    sx_flow_counter_set_t sx_flow_counter_set;
    sx_status_t           sx_status;
    sx_access_cmd_t       cmd;

    SX_LOG_ENTER();

    if (counter->sx_flow_counter == SX_FLOW_COUNTER_ID_INVALID) {
        return SAI_STATUS_SUCCESS;
    }

    switch (mode) {
    case SAI_STATS_MODE_READ:
    case SAI_STATS_MODE_READ_AND_CLEAR:
        cmd = SX_ACCESS_CMD_READ;
        break;

    default:
        SX_LOG_ERR("Invalid stats mode\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sx_status = sx_api_flow_counter_get(get_sdk_handle(), cmd, counter->sx_flow_counter, &sx_flow_counter_set);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to query flow counter\n");
        return sdk_to_sai(sx_status);
    }

    if (mode == SAI_STATS_MODE_READ_AND_CLEAR) {
        sx_status = sx_api_flow_counter_clear_set(get_sdk_handle(), counter->sx_flow_counter);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to clear flow counter\n");
            return sdk_to_sai(sx_status);
        }
    }

    return sum_counter_stats(number_of_counters, counter_ids, sx_flow_counter_set.flow_counter_packets,
                             sx_flow_counter_set.flow_counter_bytes, counters);
}

sai_status_t mlnx_get_counter_stats_ext(_In_ sai_object_id_t      counter_id,
                                        _In_ uint32_t             number_of_counters,
                                        _In_ const sai_stat_id_t *counter_ids,
                                        _In_ sai_stats_mode_t     mode,
                                        _Out_ uint64_t           *counters)
{
    mlnx_shm_rm_array_idx_t idx;
    mlnx_counter_t         *counter;
    mlnx_object_id_t        mlnx_oid;
    sai_status_t            sai_status;
    char                    key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    oid_to_str(counter_id, key_str);
    SX_LOG_DBG("Get stats extended %s\n", key_str);

    if ((number_of_counters > 0) && ((counter_ids == NULL) || (counters == NULL))) {
        SX_LOG_ERR("Invalid get counter stats parameter\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_COUNTER, counter_id, &mlnx_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed get mlnx object id\n");
        return sai_status;
    }
    idx = mlnx_oid.id.counter_db_idx;

    sai_db_read_lock();
    sai_status = mlnx_counter_db_idx_to_data(idx, &counter);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get counter data\n");
        goto out;
    }

    memset(counters, 0, number_of_counters * sizeof(uint64_t));
    sai_status = sum_hostif_counter_stats(counter, number_of_counters, mode, counter_ids, counters);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed sum hostif counters\n");
        goto out;
    }

    sai_status = sum_flow_counter_stats(counter, number_of_counters, counter_ids, mode, counters);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed sum flow counter\n");
    }
out:
    sai_db_unlock();
    return sai_status;
}

static sai_status_t mlnx_set_counter_attribute(_In_ sai_object_id_t counter_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = counter_id };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_COUNTER, attr);
}

static sai_status_t mlnx_get_counter_attribute(_In_ sai_object_id_t     counter_id,
                                               _In_ uint32_t            attr_count,
                                               _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = counter_id };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_COUNTER, attr_count, attr_list);
}

/*currently only all counters at the same time could be cleared: number of counters, counter_ids unused*/
static sai_status_t mlnx_clear_counter_stats(_In_ sai_object_id_t      counter_id,
                                             _In_ uint32_t             number_of_counters,
                                             _In_ const sai_stat_id_t *counter_ids)
{
    mlnx_shm_rm_array_idx_t idx;
    mlnx_counter_t         *counter;
    mlnx_object_id_t        mlnx_oid;
    sai_status_t            sai_status;
    sx_status_t             sx_status;
    sx_host_ifc_counters_t  host_ifc_counters;
    char                    key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    memset(&host_ifc_counters, 0, sizeof(host_ifc_counters));

    oid_to_str(counter_id, key_str);
    SX_LOG_DBG("Clear stats %s\n", key_str);

    sai_status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_COUNTER, counter_id, &mlnx_oid);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed get mlnx object id\n");
        return sai_status;
    }
    idx = mlnx_oid.id.counter_db_idx;

    sai_db_read_lock();
    sai_status = mlnx_counter_db_idx_to_data(idx, &counter);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to get counter data\n");
        goto out;
    }

    if (counter->sx_flow_counter != SX_FLOW_COUNTER_ID_INVALID) {
        sx_status = sx_api_flow_counter_clear_set(get_sdk_handle(), counter->sx_flow_counter);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to clear flow counter\n");
            sai_status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (counter->hostif_trap_ids_cnt == 0) {
        goto out;
    }

    sai_status = get_hostif_counter_stats(counter, SX_ACCESS_CMD_READ_CLEAR, &host_ifc_counters);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to clear hostif trap counters\n");
        goto out;
    }

out:
    sai_db_unlock();
    return sai_status;
}

static sai_status_t mlnx_get_counter_stats(_In_ sai_object_id_t      counter_id,
                                           _In_ uint32_t             number_of_counters,
                                           _In_ const sai_stat_id_t *counter_ids,
                                           _Out_ uint64_t           *counters)
{
    return mlnx_get_counter_stats_ext(counter_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

const sai_counter_api_t mlnx_counter_api = {
    mlnx_create_counter,
    mlnx_remove_counter,
    mlnx_set_counter_attribute,
    mlnx_get_counter_attribute,
    mlnx_get_counter_stats,
    mlnx_get_counter_stats_ext,
    mlnx_clear_counter_stats,
};
