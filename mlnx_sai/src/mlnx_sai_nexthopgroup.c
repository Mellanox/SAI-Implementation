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

#undef  __MODULE__
#define __MODULE__ SAI_NEXT_HOP_GROUP

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_nhg_attr_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_nhg_attr_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static const sai_vendor_attribute_entry_t next_hop_group_vendor_attribs[] = {
    { SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_nhg_attr_get, (void *)SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_nhg_attr_get, (void *)SAI_NEXT_HOP_GROUP_ATTR_TYPE,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST,
      { false, false, false, false },
      { false, false, false, true },
      mlnx_nhg_attr_get, (void *)SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_ATTR_CONFIGURED_SIZE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_nhg_attr_get, (void *)SAI_NEXT_HOP_GROUP_ATTR_CONFIGURED_SIZE,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_nhg_attr_get, (void *)SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_nhg_attr_get, (void *)SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID,
      mlnx_nhg_attr_set, (void *)SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        nh_group_enum_info[] = {
    [SAI_NEXT_HOP_GROUP_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_NEXT_HOP_GROUP_TYPE_ECMP,
        SAI_NEXT_HOP_GROUP_TYPE_FINE_GRAIN_ECMP
        )
};
const mlnx_obj_type_attrs_info_t          mlnx_next_hop_group_obj_type_info =
{ next_hop_group_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(nh_group_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};

static sai_status_t mlnx_nhgm_attr_set(_In_ const sai_object_key_t      *key,
                                       _In_ const sai_attribute_value_t *value,
                                       void                             *arg);
static sai_status_t mlnx_nhgm_attr_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg);

static const sai_vendor_attribute_entry_t next_hop_group_member_vendor_attribs[] = {
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_nhgm_attr_get, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_nhgm_attr_get, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID,
      mlnx_nhgm_attr_set, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID },
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_nhgm_attr_get, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT,
      mlnx_nhgm_attr_set, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT },
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_INDEX,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_nhgm_attr_get, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_INDEX,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_nhgm_attr_get, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID,
      mlnx_nhgm_attr_set, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_obj_type_attrs_info_t          mlnx_nh_group_member_obj_type_info =
{ next_hop_group_member_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY()};
static void next_hop_group_member_key_to_str(_In_ sai_object_id_t group_member_id, _Out_ char *key_str);
static void next_hop_group_key_to_str(_In_ sai_object_id_t next_hop_group_id, _Out_ char *key_str)
{
    sai_status_t status;
    uint32_t     data;
    uint16_t     ext;

    status = mlnx_object_to_type(next_hop_group_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &data, (uint8_t*)&ext);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid next hop group id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "next hop group id 0x%08X", data);
    }
}

static sai_status_t update_next_hop_data_to_ecmp_id(sx_ecmp_id_t  group,
                                                    sx_next_hop_t old_nh_data,
                                                    sx_next_hop_t new_nh_data);
static sai_status_t get_next_hop_data_from_encap_nhgm(_In_ mlnx_nhgm_db_entry_t      *nhgm_db_entry,
                                                      _In_ mlnx_nhg_db_entry_t       *nhg_db_entry,
                                                      _In_ mlnx_nhg_encap_vrf_data_t *vrf_data,
                                                      _In_ bool                       create,
                                                      _Out_ sx_next_hop_t            *sx_next_hop);
static sai_status_t get_next_hop_data_from_native_nhgm(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                       _In_ mlnx_nhg_db_entry_t  *nhg_db_entry,
                                                       _Out_ sx_next_hop_t       *sx_next_hop);
static sai_status_t mlnx_nhgm_counter_update(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                             _In_ sai_object_id_t       vrf,
                                             _In_ int32_t               diff);

static sai_status_t mlnx_nhg_db_entry_alloc(_Out_ mlnx_nhg_db_entry_t    **nhg_db_entry,
                                            _Out_ mlnx_shm_rm_array_idx_t *idx)
{
    sai_status_t status;
    void        *ptr;

    assert(nhg_db_entry);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_NHG, idx, &ptr);
    if (SAI_ERR(status)) {
        return status;
    }

    *nhg_db_entry = ptr;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_ecmp_to_nhg_db_entry_alloc(_Out_ mlnx_ecmp_to_nhg_db_entry_t **db_entry,
                                                    _Out_ mlnx_shm_rm_array_idx_t      *idx)
{
    sai_status_t status;
    void        *ptr;

    assert(db_entry);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_ECMP_NHG_MAP, idx, &ptr);
    if (SAI_ERR(status)) {
        return status;
    }

    *db_entry = ptr;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_ecmp_to_nhg_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t        idx,
                                                   _Out_ mlnx_ecmp_to_nhg_db_entry_t **db_entry)
{
    sai_status_t status;
    void        *data;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    if (SAI_ERR(status)) {
        return status;
    }

    *db_entry = (mlnx_ecmp_to_nhg_db_entry_t*)data;

    if (!(*db_entry)->array_hdr.is_used) {
        SX_LOG_ERR("NHG DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhg_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ mlnx_nhg_db_entry_t  **nhg_db_entry)
{
    sai_status_t status;
    void        *data;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    if (SAI_ERR(status)) {
        return status;
    }

    *nhg_db_entry = (mlnx_nhg_db_entry_t*)data;

    if (!(*nhg_db_entry)->array_hdr.is_used) {
        SX_LOG_ERR("NHG DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhg_oid_to_data(_In_ sai_object_id_t           oid,
                                  _Out_ mlnx_nhg_db_entry_t    **nhg_db_entry,
                                  _Out_ mlnx_shm_rm_array_idx_t *idx)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_oid;

    assert(nhg_db_entry);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_NEXT_HOP_GROUP, oid, &mlnx_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_nhg_db_entry_idx_to_data(mlnx_oid.id.nhg_db_idx, nhg_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx) {
        *idx = mlnx_oid.id.nhg_db_idx;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_ecmp_to_nhg_db_entry_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t                 status;
    mlnx_ecmp_to_nhg_db_entry_t *db_entry;

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_ecmp_to_nhg_db_entry_idx_to_data(idx, &db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    db_entry->key = 0;
    db_entry->next_idx.type = MLNX_SHM_RM_ARRAY_TYPE_INVALID;
    db_entry->next_idx.idx = 0;
    db_entry->nhg_idx.type = MLNX_SHM_RM_ARRAY_TYPE_INVALID;
    db_entry->nhg_idx.idx = 0;

    return mlnx_shm_rm_array_free(idx);
}

static sai_status_t mlnx_nhg_db_entry_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t         status;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_nhg_db_entry_idx_to_data(idx, &nhg_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    memset(&nhg_db_entry->data, 0, sizeof(nhg_db_entry->data));

    return mlnx_shm_rm_array_free(idx);
}

sai_status_t mlnx_nhg_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t        *oid)
{
    sai_status_t      status;
    mlnx_object_id_t *mlnx_oid = (mlnx_object_id_t*)oid;

    assert(oid);

    status = mlnx_shm_rm_idx_validate(idx);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx.type != MLNX_SHM_RM_ARRAY_TYPE_NHG) {
        return SAI_STATUS_FAILURE;
    }

    memset(oid, 0, sizeof(*oid));

    mlnx_oid->object_type = SAI_OBJECT_TYPE_NEXT_HOP_GROUP;
    mlnx_oid->id.nhg_db_idx = idx;

    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_nhgm_db_entry_alloc(_Out_ mlnx_nhgm_db_entry_t   **nhgm_db_entry,
                                             _Out_ mlnx_shm_rm_array_idx_t *idx)
{
    sai_status_t status;
    void        *ptr;

    assert(nhgm_db_entry);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER, idx, &ptr);
    if (SAI_ERR(status)) {
        return status;
    }

    *nhgm_db_entry = ptr;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhgm_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx,
                                            _Out_ mlnx_nhgm_db_entry_t **nhgm_db_entry)
{
    sai_status_t status;
    void        *data;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    if (SAI_ERR(status)) {
        return status;
    }

    *nhgm_db_entry = (mlnx_nhgm_db_entry_t*)data;

    if (!(*nhgm_db_entry)->array_hdr.is_used) {
        SX_LOG_ERR("nhgm DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhgm_oid_to_data(_In_ sai_object_id_t           oid,
                                   _Out_ mlnx_nhgm_db_entry_t   **nhgm_db_entry,
                                   _Out_ mlnx_shm_rm_array_idx_t *idx)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_oid;

    assert(nhgm_db_entry);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, oid, &mlnx_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_nhgm_db_entry_idx_to_data(mlnx_oid.id.nhgm_db_idx, nhgm_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx) {
        *idx = mlnx_oid.id.nhgm_db_idx;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_db_entry_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t          status;
    mlnx_nhgm_db_entry_t *nhgm_db_entry;

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_nhgm_db_entry_idx_to_data(idx, &nhgm_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    memset(&nhgm_db_entry->data, 0, sizeof(nhgm_db_entry->data));

    return mlnx_shm_rm_array_free(idx);
}

sai_status_t mlnx_nhgm_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t        *oid)
{
    sai_status_t      status;
    mlnx_object_id_t *mlnx_oid = (mlnx_object_id_t*)oid;

    assert(oid);

    status = mlnx_shm_rm_idx_validate(idx);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx.type != MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER) {
        return SAI_STATUS_FAILURE;
    }

    memset(oid, 0, sizeof(*oid));

    mlnx_oid->object_type = SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER;
    mlnx_oid->id.nhgm_db_idx = idx;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sdk_nhop_by_ecmp_id_get(sx_ecmp_id_t sdk_ecmp_id, sx_next_hop_t *sx_next_hop)
{
    uint32_t    sdk_next_hop_cnt = 1;
    sx_status_t status;

    status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, sx_next_hop, &sdk_next_hop_cnt);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ecmp - %s id %u\n", SX_STATUS_MSG(status), sdk_ecmp_id);
        return sdk_to_sai(status);
    }

    if (1 != sdk_next_hop_cnt) {
        SX_LOG_ERR("Invalid next hosts count %u for ecmp id %u\n", sdk_next_hop_cnt, sdk_ecmp_id);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static int sx_nhop_equal(const sx_next_hop_t *nhop1, const sx_next_hop_t *nhop2)
{
    return !memcmp(&nhop1->next_hop_key, &nhop2->next_hop_key, sizeof(nhop2->next_hop_key));
}

static sai_status_t mlnx_sdk_nhop_find_in_list(const sx_next_hop_t *next_hops,
                                               uint32_t             count,
                                               const sx_next_hop_t *match,
                                               uint32_t            *index)
{
    uint32_t ii;

    for (ii = 0; ii < count; ii++) {
        if (sx_nhop_equal(match, &next_hops[ii])) {
            *index = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Next group member does not exist in group\n");
    return SAI_STATUS_INVALID_OBJECT_ID;
}

static sai_status_t mlnx_translate_sai_next_hop_object(_In_ uint32_t              index,
                                                       _In_ const sai_object_id_t next_hop_id,
                                                       _Out_ sx_next_hop_t       *sx_next_hop)
{
    sx_ecmp_id_t sdk_ecmp_id;
    sai_status_t status;

    status = mlnx_object_to_type(next_hop_id, SAI_OBJECT_TYPE_NEXT_HOP, &sdk_ecmp_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_sdk_nhop_by_ecmp_id_get(sdk_ecmp_id, sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get nhop ecmp at index %u\n", index);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_translate_sai_next_hop_objects(_In_ uint32_t                      count,
                                                        _In_ const sai_object_id_t        *next_hop_id,
                                                        _Out_writes_(count) sx_next_hop_t *sx_next_hop)
{
    sai_status_t status;
    uint32_t     ii;

    for (ii = 0; ii < count; ii++) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sai_next_hop_object(ii, next_hop_id[ii], &sx_next_hop[ii]))) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fg_ecmp_size_configured_to_real(_In_ uint32_t configured_size, _Inout_ uint32_t *real_size)
{
    uint32_t fg_ecmp_hw_sizes[6] = {0};
    uint32_t ii;

    if ((g_sai_db_ptr->sx_chip_type == SX_CHIP_TYPE_SPECTRUM) ||
        (g_sai_db_ptr->sx_chip_type == SX_CHIP_TYPE_SPECTRUM_A1)) {
        fg_ecmp_hw_sizes[0] = 64;
        fg_ecmp_hw_sizes[1] = 512;
        fg_ecmp_hw_sizes[2] = 1024;
        fg_ecmp_hw_sizes[3] = 2048;
        fg_ecmp_hw_sizes[4] = 4096;
    } else {
        fg_ecmp_hw_sizes[0] = 128;
        fg_ecmp_hw_sizes[1] = 256;
        fg_ecmp_hw_sizes[2] = 512;
        fg_ecmp_hw_sizes[3] = 1024;
        fg_ecmp_hw_sizes[4] = 2048;
        fg_ecmp_hw_sizes[5] = 4096;
    }

    for (ii = 0; ii < ARRAY_SIZE(fg_ecmp_hw_sizes); ++ii) {
        if (fg_ecmp_hw_sizes[ii] >= configured_size) {
            *real_size = fg_ecmp_hw_sizes[ii];
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_INSUFFICIENT_RESOURCES;
}

static sai_status_t mlnx_nhg_type_ecmp_counter_apply(mlnx_nhg_db_entry_t *db_entry, sx_flow_counter_id_t sx_counter)
{
    sx_status_t sx_status;

    assert(db_entry && db_entry->data.type == MLNX_NHG_TYPE_ECMP);

    if (db_entry->data.members_count != 0) {
        for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
            if (db_entry->data.data.encap.vrf_data[ii].refcount > 0) {
                uint32_t        offset = 0;
                sx_access_cmd_t cmd = sx_counter ==
                                      SX_FLOW_COUNTER_ID_INVALID ? SX_ACCESS_CMD_UNBIND : SX_ACCESS_CMD_BIND;

                sx_status = sx_api_router_ecmp_counter_bind_set(gh_sdk,
                                                                cmd,
                                                                db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id,
                                                                &sx_counter,
                                                                &offset,
                                                                1);
                if (SX_ERR(sx_status)) {
                    SX_LOG_ERR("Failed to bind counter - %s.\n", SX_STATUS_MSG(sx_status));
                    return sdk_to_sai(sx_status);
                }
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_type_fine_grain_counter_apply(mlnx_nhg_db_entry_t *db_entry,
                                                           sx_flow_counter_id_t sx_counter)
{
    sx_status_t sx_status;

    assert(db_entry && db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN);

    if (db_entry->data.members_count > 0) {
        uint32_t        offset = 0;
        sx_access_cmd_t cmd = sx_counter == SX_FLOW_COUNTER_ID_INVALID ? SX_ACCESS_CMD_UNBIND : SX_ACCESS_CMD_BIND;

        sx_status = sx_api_router_ecmp_counter_bind_set(gh_sdk,
                                                        cmd,
                                                        db_entry->data.data.fine_grain.sx_ecmp_id,
                                                        &sx_counter,
                                                        &offset,
                                                        1);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to %s counter - %s.\n",
                       sx_counter == SX_FLOW_COUNTER_ID_INVALID ? "unbind" : "bind",
                       SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_flow_counter_set(mlnx_nhg_db_entry_t *db_entry, sai_object_id_t counter_oid)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    assert(db_entry);

    sx_flow_counter_id_t sx_counter;

    sai_db_unlock(); /* Next call must be unlocked. Need to refactor flow counters code. */
    status = mlnx_get_flow_counter_id(counter_oid, &sx_counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get flow counter id from counters db\n");
        return status;
    }
    sai_db_write_lock();

    if (db_entry->data.type == MLNX_NHG_TYPE_ECMP) {
        status = mlnx_nhg_type_ecmp_counter_apply(db_entry, sx_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply flow counter.\n");
            return status;
        }
    } else if (db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) {
        status = mlnx_nhg_type_fine_grain_counter_apply(db_entry, sx_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply flow counter.\n");
            return status;
        }
    } else {
        SX_LOG_ERR("Unexpected NHG type: %d.\n", db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    mlnx_shm_rm_array_idx_t counter_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

    if (counter_oid != SAI_NULL_OBJECT_ID) {
        mlnx_counter_t *counter_db_entry;
        status = mlnx_counter_oid_to_data(counter_oid, &counter_db_entry, &counter_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get counter DB entry.\n");
            return status;
        }
    }

    db_entry->data.flow_counter = counter_idx;

    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Create next hop group
 *
 * Arguments:
 *    [out] next_hop_group_id - next hop group id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */

static sai_status_t mlnx_create_next_hop_group(_Out_ sai_object_id_t      *next_hop_group_id,
                                               _In_ sai_object_id_t        switch_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    /* CHECK INPUT */
    {
        if (NULL == next_hop_group_id) {
            SX_LOG_ERR("NULL next hop group id param\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        *next_hop_group_id = SAI_NULL_OBJECT_ID;

        status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                                        next_hop_group_vendor_attribs,
                                        SAI_COMMON_API_CREATE);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed attribs check\n");
            return status;
        }

        char list_str[MAX_LIST_VALUE_STR_LEN];
        sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
        SX_LOG_NTC("Create next hop group, %s\n", list_str);
    }


    mlnx_nhg_db_entry_t    *db_entry = NULL;
    mlnx_shm_rm_array_idx_t idx;

    /* HANDLE ATTRIBUTES */
    {
        mlnx_sai_attr_t type;
        mlnx_sai_attr_t counter;

        find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_TYPE, &type);
        assert(type.found);
        find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID, &counter);

        sai_db_write_lock();

        status = mlnx_nhg_db_entry_alloc(&db_entry, &idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to allocate NHG DB entry.\n");
            goto exit;
        }

        db_entry->data.type = MLNX_NHG_TYPE_ECMP;

        if (type.value->s32 == SAI_NEXT_HOP_GROUP_TYPE_FINE_GRAIN_ECMP) {
            db_entry->data.type = MLNX_NHG_TYPE_FINE_GRAIN;

            mlnx_sai_attr_t configured_size;
            find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_CONFIGURED_SIZE, &configured_size);
            assert(configured_size.found);

            uint32_t real_size;
            status = mlnx_fg_ecmp_size_configured_to_real(configured_size.value->u32, &real_size);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("The requested size %u is not available.\n", configured_size.value->u32);
                goto exit;
            }

            db_entry->data.data.fine_grain.configured_size = configured_size.value->u32;
            db_entry->data.data.fine_grain.real_size = real_size;

            sx_status_t   sx_status;
            sx_next_hop_t next_hops[1];
            uint32_t      next_hop_cnt = 0;
            sx_status = sx_api_router_ecmp_set(gh_sdk,
                                               SX_ACCESS_CMD_CREATE,
                                               &db_entry->data.data.fine_grain.sx_ecmp_id,
                                               next_hops,
                                               &next_hop_cnt);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to create fine grain sx_ecmp_id - %s.\n", SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(status);
                goto exit;
            }
        }

        if (counter.found) {
            status = mlnx_nhg_flow_counter_set(db_entry, counter.value->oid);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to set NHG counter id\n");
                goto exit;
            }
        }
    }

    /* CREATE SAI OID */
    {
        status = mlnx_nhg_oid_create(idx, next_hop_group_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create NHG OID.\n");
            goto exit;
        }

        char key_str[MAX_KEY_STR_LEN];
        next_hop_group_key_to_str(*next_hop_group_id, key_str);
        SX_LOG_NTC("Created next hop group %s\n", key_str);
    }

exit:
    if (SAI_ERR(status) && db_entry) {
        mlnx_nhg_db_entry_free(idx);
    }
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_nhg_ecmp_remove(_In_ mlnx_nhg_db_entry_t *db_entry)
{
    assert(db_entry && db_entry->data.type == MLNX_NHG_TYPE_ECMP);

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
        if (db_entry->data.data.encap.vrf_data[ii].refcount > 0) {
            SX_LOG_ERR("VRF data [%d] is not empty [refcount=%d].\n", ii,
                       db_entry->data.data.encap.vrf_data[ii].refcount);
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_fine_grain_remove(_In_ mlnx_nhg_db_entry_t *db_entry)
{
    sx_status_t sx_status;
    uint32_t    next_hop_cnt;

    assert(db_entry && db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN);

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_DESTROY,
                                       &db_entry->data.data.fine_grain.sx_ecmp_id,
                                       NULL,
                                       &next_hop_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_remove(_In_ mlnx_nhg_db_entry_t *db_entry)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    assert(db_entry);

    if (db_entry->data.members_count != 0) {
        SX_LOG_ERR("Members list is not empty [%d]. Remove HNG Members first.\n",
                   db_entry->data.members_count);
        return SAI_STATUS_FAILURE;
    }

    switch (db_entry->data.type) {
    case MLNX_NHG_TYPE_ECMP:
        status = mlnx_nhg_ecmp_remove(db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHG type ECMP.\n");
            return status;
        }
        break;

    case MLNX_NHG_TYPE_FINE_GRAIN:
        status = mlnx_nhg_fine_grain_remove(db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHG type FINE_GRAIN.\n");
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected NHG type: %u.\n", db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove next hop group
 *
 * Arguments:
 *    [in] next_hop_group_id - next hop group id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_next_hop_group(_In_ sai_object_id_t next_hop_group_id)
{
    sai_status_t status;
    char         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    SX_LOG_NTC("Remove next hop group %s\n", key_str);

    mlnx_nhg_db_entry_t    *db_entry;
    mlnx_shm_rm_array_idx_t idx;

    sai_db_write_lock();

    status = mlnx_nhg_oid_to_data(next_hop_group_id, &db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto exit;
    }

    status = mlnx_nhg_remove(db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove NHG.\n");
        goto exit;
    }

    status = mlnx_nhg_db_entry_free(idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to free NHG DB entry.\n");
        goto exit;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Set Next Hop Group attribute
 *
 * Arguments:
 *    [in] sai_next_hop_group_id_t - next_hop_group_id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_next_hop_group_attribute(_In_ sai_object_id_t        next_hop_group_id,
                                                      _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = next_hop_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, next_hop_group_vendor_attribs, attr);
}

/*
 * Routine Description:
 *    Get Next Hop Group attribute
 *
 * Arguments:
 *    [in] sai_next_hop_group_id_t - next_hop_group_id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_next_hop_group_attribute(_In_ sai_object_id_t     next_hop_group_id,
                                                      _In_ uint32_t            attr_count,
                                                      _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = next_hop_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                              next_hop_group_vendor_attribs,
                              attr_count,
                              attr_list);
}

static sai_status_t mlnx_nhg_flow_counter_get(_In_ mlnx_nhg_db_entry_t *db_entry,
                                              _Out_ sai_object_id_t    *counter_oid)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    assert(db_entry && counter_oid);

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(db_entry->data.flow_counter)) {
        status = mlnx_counter_oid_create(db_entry->data.flow_counter, counter_oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create counter oid\n");
            return status;
        }
    } else {
        *counter_oid = SAI_NULL_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_members_get(_In_ mlnx_nhg_db_entry_t *db_entry, _Inout_ sai_attribute_value_t *value)
{
    assert(db_entry && value);
    /* TODO: implement using members idx as a first member */
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t mlnx_nhg_attr_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    long         attr = (long)arg;

    SX_LOG_ENTER();

    assert((SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT == attr) ||
           (SAI_NEXT_HOP_GROUP_ATTR_TYPE == attr) ||
           (SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST == attr) ||
           (SAI_NEXT_HOP_GROUP_ATTR_CONFIGURED_SIZE == attr) ||
           (SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE == attr) ||
           (SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID == attr));

    mlnx_nhg_db_entry_t *db_entry;

    sai_db_write_lock();

    status = mlnx_nhg_oid_to_data(key->key.object_id, &db_entry, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto exit;
    }

    switch (attr) {
    case SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT:
        value->u32 = db_entry->data.members_count;
        break;

    case SAI_NEXT_HOP_GROUP_ATTR_TYPE:
        if (db_entry->data.type == MLNX_NHG_TYPE_ECMP) {
            value->s32 = SAI_NEXT_HOP_GROUP_TYPE_ECMP;
        } else if (db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) {
            value->s32 = SAI_NEXT_HOP_GROUP_TYPE_FINE_GRAIN_ECMP;
        } else {
            SX_LOG_ERR("Unexpected NHG type: %d.\n", db_entry->data.type);
            status = SAI_STATUS_FAILURE;
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST:
        status = mlnx_nhg_members_get(db_entry, value);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHG members list.\n");
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_ATTR_CONFIGURED_SIZE:
        if (db_entry->data.type != MLNX_NHG_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("[CONFIGURED_SIZE] Attribute supported only for fine grain ECMP.\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = db_entry->data.data.fine_grain.configured_size;
        break;

    case SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE:
        if (db_entry->data.type != MLNX_NHG_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("[REAL_SIZE] Attribute supported only for fine grain ECMP.\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = db_entry->data.data.fine_grain.real_size;
        break;

    case SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID:
        status = mlnx_nhg_flow_counter_get(db_entry, &value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get flow counter.\n");
            goto exit;
        }
        break;

    default:
        break;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_nhg_attr_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    long         attr = (long)arg;

    SX_LOG_ENTER();

    assert(attr == SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID);

    mlnx_nhg_db_entry_t *db_entry;

    sai_db_write_lock();

    status = mlnx_nhg_oid_to_data(key->key.object_id, &db_entry, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto exit;
    }

    switch (attr) {
    case SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID:
        status = mlnx_nhg_flow_counter_set(db_entry, value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set flow counter.\n");
            goto exit;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected attribute: %ld.\n", attr);
        status = SAI_STATUS_FAILURE;
        goto exit;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_nexthop_group_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t get_nhg_from_nhgm(_In_ mlnx_nhgm_db_entry_t  *nhgm_db_entry,
                                      _Out_ mlnx_nhg_db_entry_t **nhg_db_entry)
{
    sai_status_t status;

    status = mlnx_nhg_db_entry_idx_to_data(nhgm_db_entry->data.nhg_idx, nhg_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}


static uint32_t nhgm_get_weight(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    assert(nhgm_db_entry);

    if (nhgm_db_entry->data.weight) {
        return nhgm_db_entry->data.weight;
    }

    return 1;
}

static sai_status_t nhgm_get_flow_counter(_In_ mlnx_nhgm_db_entry_t  *nhgm_db_entry,
                                          _In_ mlnx_nhg_db_entry_t   *nhg_db_entry,
                                          _Out_ sx_flow_counter_id_t *sx_flow_counter)
{
    sai_status_t status;

    assert(nhgm_db_entry && nhg_db_entry && sx_flow_counter);

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_entry->data.flow_counter)) {
        status = mlnx_get_sx_flow_counter_id_by_idx(nhgm_db_entry->data.flow_counter,
                                                    sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter from NHGM.\n");
            return status;
        }
    } else if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhg_db_entry->data.flow_counter)) {
        status = mlnx_get_sx_flow_counter_id_by_idx(nhg_db_entry->data.flow_counter,
                                                    sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter from NHG.\n");
            return status;
        }
    } else {
        *sx_flow_counter = SX_FLOW_COUNTER_ID_INVALID;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nghm_next_hop_oid_set(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry, _In_ sai_object_id_t oid)
{
    sai_status_t         status;
    sx_next_hop_t        next_hops[FG_ECMP_MAX_PATHS];
    uint32_t             next_hop_count = FG_ECMP_MAX_PATHS;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    if (nhgm_db_entry->data.type != MLNX_NHGM_TYPE_FINE_GRAIN) {
        SX_LOG_ERR("Failed to set next hop id - supported only for FINE_GRAIN_ECMP\n");
        return SAI_STATUS_FAILURE;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG Db entry.\n");
        return status;
    }

    sx_ecmp_id_t sx_group_id = nhg_db_entry->data.data.fine_grain.sx_ecmp_id;
    uint32_t     index = nhgm_db_entry->data.entry.fg_id;

    status = sx_api_router_ecmp_get(gh_sdk, sx_group_id, next_hops, &next_hop_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    status = mlnx_translate_sai_next_hop_objects(1, &oid, &next_hops[index]);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate_sai_next_hop_objects %lu.\n", oid);
        return status;
    }

    status = nhgm_get_flow_counter(nhgm_db_entry, nhg_db_entry, &next_hops[index].next_hop_data.counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get flow counter.\n");
        return status;
    }

    status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &sx_group_id, next_hops, &next_hop_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nghm_weight_set(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry, _In_ uint32_t weight)
{
    sai_status_t               status;
    mlnx_nhg_db_entry_t       *nhg_db_entry;
    mlnx_nhg_encap_vrf_data_t *vrf_data;
    sx_next_hop_t              old_sx_next_hop;
    sx_next_hop_t              new_sx_next_hop;

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) {
        SX_LOG_NTC("Weight not supported for FG ECMP.\n");
        return SAI_STATUS_FAILURE;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG Db entry.\n");
        return status;
    }

    for (uint32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP) {
                status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                           nhg_db_entry,
                                                           vrf_data,
                                                           false,
                                                           &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data.\n");
                    return status;
                }
            } else {
                status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                            nhg_db_entry,
                                                            &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data.\n");
                    return status;
                }
            }

            new_sx_next_hop = old_sx_next_hop;
            new_sx_next_hop.next_hop_data.weight = weight;

            status = update_next_hop_data_to_ecmp_id(vrf_data->sx_ecmp_id,
                                                     old_sx_next_hop,
                                                     new_sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id. [index = %d]\n", ii);
                return status;
            }
        }
    }

    nhgm_db_entry->data.weight = weight;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_fg_counter_set(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                             _In_ mlnx_nhg_db_entry_t     *nhg_db_entry,
                                             _In_ mlnx_shm_rm_array_idx_t  counter_idx)
{
    sai_status_t         status;
    sx_status_t          sx_status;
    sx_flow_counter_id_t sx_flow_counter = SX_FLOW_COUNTER_ID_INVALID;
    sx_next_hop_t        next_hops[FG_ECMP_MAX_PATHS];
    uint32_t             next_hop_count = FG_ECMP_MAX_PATHS;

    assert(nhgm_db_entry && nhg_db_entry);
    assert(nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN);

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(counter_idx)) {
        status = mlnx_get_sx_flow_counter_id_by_idx(counter_idx,
                                                    &sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter.\n");
            return status;
        }
    }

    sx_status = sx_api_router_ecmp_get(gh_sdk,
                                       nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                       next_hops,
                                       &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    next_hops[nhgm_db_entry->data.entry.fg_id].next_hop_data.counter_id = sx_flow_counter;

    status = sx_api_router_ecmp_set(gh_sdk,
                                    SX_ACCESS_CMD_SET,
                                    &nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                    next_hops,
                                    &next_hop_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    nhgm_db_entry->data.flow_counter = counter_idx;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nghm_counter_set(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry, _In_ sai_object_id_t counter)
{
    sai_status_t               status;
    mlnx_nhg_db_entry_t       *nhg_db_entry;
    mlnx_nhg_encap_vrf_data_t *vrf_data;
    sx_next_hop_t              old_sx_next_hop;
    sx_next_hop_t              new_sx_next_hop;
    mlnx_shm_rm_array_idx_t    counter_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    sx_flow_counter_id_t       sx_flow_counter = SX_FLOW_COUNTER_ID_INVALID;

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG Db entry.\n");
        return status;
    }

    if (counter != SAI_NULL_OBJECT_ID) {
        mlnx_counter_t *counter_db_entry;
        status = mlnx_counter_oid_to_data(counter, &counter_db_entry, &counter_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get counter DB entry.\n");
            return status;
        }

        status = mlnx_get_sx_flow_counter_id_by_idx(counter_idx,
                                                    &sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter.\n");
            return status;
        }
    }

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) {
        return mlnx_nhgm_fg_counter_set(nhgm_db_entry,
                                        nhg_db_entry,
                                        counter_idx);
    }

    for (uint32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP) {
                status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                           nhg_db_entry,
                                                           vrf_data,
                                                           false,
                                                           &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data.\n");
                    return status;
                }
            } else {
                status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                            nhg_db_entry,
                                                            &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data.\n");
                    return status;
                }
            }

            new_sx_next_hop = old_sx_next_hop;
            new_sx_next_hop.next_hop_data.counter_id = sx_flow_counter;

            status = update_next_hop_data_to_ecmp_id(vrf_data->sx_ecmp_id,
                                                     old_sx_next_hop,
                                                     new_sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id. [index = %d]\n", ii);
                return status;
            }
        }
    }

    nhgm_db_entry->data.flow_counter = counter_idx;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_attr_set(_In_ const sai_object_key_t      *key,
                                       _In_ const sai_attribute_value_t *value,
                                       void                             *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    long         attr = (long)arg;

    SX_LOG_ENTER();

    assert((attr == SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID) ||
           (attr == SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT) ||
           (attr == SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID));

    mlnx_nhgm_db_entry_t *db_entry;

    sai_db_write_lock();

    status = mlnx_nhgm_oid_to_data(key->key.object_id, &db_entry, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto exit;
    }

    if (db_entry->data.type == MLNX_NHGM_TYPE_NULL) {
        SX_LOG_ERR("Unexpected NHGM type.\n");
        status = SAI_STATUS_FAILURE;
        goto exit;
    }

    switch (attr) {
    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID:
        status = mlnx_nghm_next_hop_oid_set(db_entry, value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set NH OID.\n");
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT:
        status = mlnx_nghm_weight_set(db_entry, value->u32);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set weight.\n");
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID:
        status = mlnx_nghm_counter_set(db_entry, value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set counter.\n");
            goto exit;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected attribute: %ld.\n", attr);
        status = SAI_STATUS_FAILURE;
        goto exit;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_nhgm_attr_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    long         attr = (long)arg;

    SX_LOG_ENTER();

    assert((SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID == attr) ||
           (SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID == attr) ||
           (SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT == attr) ||
           (SAI_NEXT_HOP_GROUP_MEMBER_ATTR_INDEX == attr) ||
           (SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID == attr));

    mlnx_nhgm_db_entry_t *db_entry;

    sai_db_write_lock();

    status = mlnx_nhgm_oid_to_data(key->key.object_id, &db_entry, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto exit;
    }

    if (db_entry->data.type == MLNX_NHGM_TYPE_NULL) {
        SX_LOG_ERR("Unexpected NHGM type.\n");
        status = SAI_STATUS_FAILURE;
        goto exit;
    }

    switch (attr) {
    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID:
        status = mlnx_nhg_oid_create(db_entry->data.nhg_idx, &value->oid);
        if (SAI_ERR(status)) {
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID:
        if (db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("Failed to get next hop id - not supported  for FINE_GRAIN_ECMP\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        if (db_entry->data.type == MLNX_NHGM_TYPE_NATIVE) {
            status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP, db_entry->data.entry.sx_ecmp_id, NULL, &value->oid);
            if (SAI_ERR(status)) {
                goto exit;
            }
        } else { /* ENCAP */
            status = mlnx_encap_nexthop_oid_create(db_entry->data.entry.nh_idx, &value->oid);
            if (SAI_ERR(status)) {
                goto exit;
            }
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT:
        if (db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("Failed to get weight - not supported for FINE_GRAIN_ECMP\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = db_entry->data.weight;
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_INDEX:
        if (db_entry->data.type != MLNX_NHGM_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("Failed to get group member index - supported only for FINE_GRAIN_ECMP\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = db_entry->data.entry.fg_id;
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID:
        if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(db_entry->data.flow_counter)) {
            value->oid = SAI_NULL_OBJECT_ID;
            goto exit;
        }
        status = mlnx_counter_oid_create(db_entry->data.flow_counter, &value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to flow counter.\n");
            goto exit;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected attribute: %ld.\n", attr);
        status = SAI_STATUS_FAILURE;
        goto exit;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}


static sai_status_t apply_next_hop_data_to_ecmp_id(sx_ecmp_id_t group, sx_next_hop_t nh_data)
{
    sx_status_t   sx_status;
    uint32_t      next_hop_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t ecmp_next_hops[FG_ECMP_MAX_PATHS];

    sx_status = sx_api_router_ecmp_get(gh_sdk, group, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    ecmp_next_hops[next_hop_count++] = nh_data;

    sx_status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &group, ecmp_next_hops, &next_hop_count);
    if (SAI_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t get_next_hop_data_from_encap_nhgm(_In_ mlnx_nhgm_db_entry_t      *nhgm_db_entry,
                                                      _In_ mlnx_nhg_db_entry_t       *nhg_db_entry,
                                                      _In_ mlnx_nhg_encap_vrf_data_t *vrf_data,
                                                      _In_ bool                       create,
                                                      _Out_ sx_next_hop_t            *sx_next_hop)
{
    sai_status_t status;

    status = mlnx_encap_nh_data_get(nhgm_db_entry->data.entry.nh_idx,
                                    vrf_data->associated_vrf,
                                    create ? vrf_data->refcount : 0,
                                    sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop data.\n");
        return status;
    }

    sx_next_hop->next_hop_data.weight = nhgm_get_weight(nhgm_db_entry);
    status = nhgm_get_flow_counter(nhgm_db_entry, nhg_db_entry, &sx_next_hop->next_hop_data.counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get sx_flow_counter.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t get_next_hop_data_from_native_nhgm(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                       _In_ mlnx_nhg_db_entry_t  *nhg_db_entry,
                                                       _Out_ sx_next_hop_t       *sx_next_hop)
{
    sai_status_t status;

    status = mlnx_sdk_nhop_by_ecmp_id_get(nhgm_db_entry->data.entry.sx_ecmp_id, sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop ecmp.\n");
        return status;
    }

    sx_next_hop->next_hop_data.weight = nhgm_get_weight(nhgm_db_entry);
    status = nhgm_get_flow_counter(nhgm_db_entry, nhg_db_entry, &sx_next_hop->next_hop_data.counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get sx_flow_counter.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t link_nhgm_to_nhg(_In_ mlnx_shm_rm_array_idx_t nhgm_idx,
                                     _In_ mlnx_nhgm_db_entry_t   *nhgm_db_entry,
                                     _Out_ mlnx_nhg_db_entry_t   *nhg_db_entry)
{
    sai_status_t status;

    assert(nhgm_db_entry && nhg_db_entry);

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhg_db_entry->data.members)) {
        mlnx_nhgm_db_entry_t *old_head;
        status = mlnx_nhgm_db_entry_idx_to_data(nhg_db_entry->data.members, &old_head);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get old head.\n");
            return status;
        }
        old_head->data.prev_member_idx = nhgm_idx;
    }

    memset(&nhgm_db_entry->data.prev_member_idx, 0, sizeof(nhgm_db_entry->data.prev_member_idx));
    nhgm_db_entry->data.next_member_idx = nhg_db_entry->data.members;
    nhg_db_entry->data.members = nhgm_idx;
    nhg_db_entry->data.members_count++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t unlink_nhgm_from_nhg(_In_ mlnx_shm_rm_array_idx_t nhgm_idx,
                                         _In_ mlnx_nhgm_db_entry_t   *nhgm_db_entry,
                                         _Out_ mlnx_nhg_db_entry_t   *nhg_db_entry)
{
    sai_status_t status;

    assert(nhgm_db_entry && nhg_db_entry);

    if (MLNX_SHM_RM_ARRAY_IDX_EQUAL(nhg_db_entry->data.members, nhgm_idx)) {
        nhg_db_entry->data.members = nhgm_db_entry->data.next_member_idx;
    }

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_entry->data.next_member_idx)) {
        mlnx_nhgm_db_entry_t *next;
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_db_entry->data.next_member_idx, &next);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get next NHGM.\n");
            return status;
        }
        next->data.prev_member_idx = nhgm_db_entry->data.prev_member_idx;
    }

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_entry->data.prev_member_idx)) {
        mlnx_nhgm_db_entry_t *prev;
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_db_entry->data.prev_member_idx, &prev);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get previous NHGM.\n");
            return status;
        }
        prev->data.next_member_idx = nhgm_db_entry->data.next_member_idx;
    }

    memset(&nhgm_db_entry->data.next_member_idx, 0, sizeof(nhgm_db_entry->data.next_member_idx));
    memset(&nhgm_db_entry->data.prev_member_idx, 0, sizeof(nhgm_db_entry->data.prev_member_idx));
    nhg_db_entry->data.members_count--;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_native_apply(mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                mlnx_nhg_db_entry_t  *nhg_db_entry)
{
    sx_next_hop_t              sx_next_hop;
    mlnx_nhg_encap_vrf_data_t *vrf_data;
    sai_status_t               status;

    assert(nhg_db_entry && nhgm_db_entry && nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE);

    status = get_next_hop_data_from_native_nhgm(nhgm_db_entry, nhg_db_entry, &sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop data.\n");
        return status;
    }

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->sx_ecmp_id != 0) {
            status = apply_next_hop_data_to_ecmp_id(vrf_data->sx_ecmp_id,
                                                    sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id. [index = %d]\n", ii);
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_encap_apply(mlnx_nhgm_db_entry_t *nhgm_db_entry, mlnx_nhg_db_entry_t  *nhg_db_entry)
{
    sx_next_hop_t              sx_next_hop;
    mlnx_nhg_encap_vrf_data_t *vrf_data;
    sai_status_t               status;

    assert(nhg_db_entry && nhgm_db_entry && nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP);

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry, nhg_db_entry, vrf_data, true, &sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get next hop data.\n");
                return status;
            }

            status = apply_next_hop_data_to_ecmp_id(vrf_data->sx_ecmp_id,
                                                    sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id. [index = %d]\n", ii);
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_fine_grain_apply(mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                    mlnx_nhg_db_entry_t  *nhg_db_entry,
                                                    sai_object_id_t       nh)
{
    uint32_t             next_hop_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t        ecmp_next_hops[FG_ECMP_MAX_PATHS];
    sai_status_t         status;
    sx_status_t          sx_status;
    sx_flow_counter_id_t sx_flow_counter;

    assert(nhgm_db_entry && nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN);

    sx_status = sx_api_router_ecmp_get(gh_sdk,
                                       nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                       ecmp_next_hops,
                                       &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    ecmp_next_hops[nhgm_db_entry->data.entry.fg_id].next_hop_data.weight = nhgm_get_weight(nhgm_db_entry);
    status = nhgm_get_flow_counter(nhgm_db_entry,
                                   nhg_db_entry,
                                   &sx_flow_counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get sx_flow_counter.\n");
        return status;
    }

    if (next_hop_count == 0) {
        /* when adding the first member - fill the entire group with this element */
        for (uint32_t jj = 0; jj < nhg_db_entry->data.data.fine_grain.real_size; ++jj) {
            status = mlnx_translate_sai_next_hop_objects(1, &nh, &ecmp_next_hops[jj]);
            if (SAI_ERR(status)) {
                return status;
            }
            ecmp_next_hops[jj].next_hop_data.counter_id = sx_flow_counter;
        }
        next_hop_count = nhg_db_entry->data.data.fine_grain.real_size;
    } else {
        status = mlnx_translate_sai_next_hop_objects(1, &nh, &ecmp_next_hops[nhgm_db_entry->data.entry.fg_id]);
        if (SAI_ERR(status)) {
            return status;
        }
        ecmp_next_hops[nhgm_db_entry->data.entry.fg_id].next_hop_data.counter_id = sx_flow_counter;
    }

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_SET,
                                       &nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                       ecmp_next_hops,
                                       &next_hop_count);
    if (SAI_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_apply(_In_ mlnx_nhgm_db_entry_t   *nhgm_db_entry,
                                    _In_ mlnx_shm_rm_array_idx_t nhgm_idx,
                                    _In_ sai_object_id_t         nh)
{
    sai_status_t         status;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    assert(nhgm_db_entry);

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry.\n");
        return status;
    }

    status = link_nhgm_to_nhg(nhgm_idx, nhgm_db_entry, nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to link NHGM to NHG.\n");
        return status;
    }

    switch (nhgm_db_entry->data.type) {
    case MLNX_NHGM_TYPE_NATIVE:
        status = mlnx_nhgm_type_native_apply(nhgm_db_entry, nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set NHGM type NATIVE.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_ENCAP:
        status = mlnx_nhgm_type_encap_apply(nhgm_db_entry, nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set NHGM type ENCAP.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_FINE_GRAIN:
        status = mlnx_nhgm_type_fine_grain_apply(nhgm_db_entry, nhg_db_entry, nh);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set NHGM type FINE_GRAIN.\n");
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected NHGM type.\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_sx_ecmp_get(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                         _In_ sai_object_id_t      vrf,
                                         _Out_ sx_ecmp_id_t       *sx_ecmp_id)
{
    assert(sx_ecmp_id && nhg_db_entry);

    if (nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) {
        for (uint32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
            if (nhg_db_entry->data.data.encap.vrf_data[ii].associated_vrf == vrf) {
                if (nhg_db_entry->data.data.encap.vrf_data[ii].refcount == 0) {
                    return SAI_STATUS_FAILURE;
                }
                *sx_ecmp_id = nhg_db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id;
            }
        }
    } else if (nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) {
        *sx_ecmp_id = nhg_db_entry->data.data.fine_grain.sx_ecmp_id;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_vrf_data_get(_In_ mlnx_nhg_db_entry_t         *nhg_db_entry,
                                          _In_ sai_object_id_t              vrf,
                                          _Out_ mlnx_nhg_encap_vrf_data_t **vrf_data,
                                          _In_ bool                         allocate)
{
    for (uint32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        if (nhg_db_entry->data.data.encap.vrf_data[ii].associated_vrf == vrf) {
            *vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
            return SAI_STATUS_SUCCESS;
        }
    }

    if (allocate) {
        for (uint32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
            if (nhg_db_entry->data.data.encap.vrf_data[ii].refcount == 0) {
                *vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
                (*vrf_data)->associated_vrf = vrf;
                return SAI_STATUS_SUCCESS;
            }
        }
    }

    return SAI_STATUS_FAILURE;
}

uint32_t mlnx_ecmp_id_hash(_In_ sx_ecmp_id_t sx_ecmp_id)
{
    return sx_ecmp_id;
}

sai_status_t mlnx_ecmp_to_nhg_map_entry_add(_In_ sx_ecmp_id_t key, _In_ mlnx_shm_rm_array_idx_t value)
{
    sai_status_t                 status;
    uint32_t                     index = mlnx_ecmp_id_hash(key) % MLNX_ECMP_NHG_HASHTABLE_SIZE;
    mlnx_ecmp_to_nhg_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t      idx;


    status = mlnx_ecmp_to_nhg_db_entry_alloc(&db_entry,
                                             &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to allocate ECMP-NHG db entry.\n");
        return status;
    }

    db_entry->key = key;
    db_entry->nhg_idx = value;
    db_entry->next_idx = g_sai_db_ptr->ecmp_to_nhg_map[index];

    g_sai_db_ptr->ecmp_to_nhg_map[index] = idx;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_ecmp_to_nhg_map_entry_del(_In_ sx_ecmp_id_t key)
{
    sai_status_t                 status;
    uint32_t                     index = mlnx_ecmp_id_hash(key) % MLNX_ECMP_NHG_HASHTABLE_SIZE;
    mlnx_ecmp_to_nhg_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t      idx;
    mlnx_shm_rm_array_idx_t      prev_idx = {0};
    mlnx_ecmp_to_nhg_db_entry_t *prev_db_entry = NULL;

    idx = g_sai_db_ptr->ecmp_to_nhg_map[index];

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        status = mlnx_ecmp_to_nhg_db_entry_idx_to_data(idx,
                                                       &db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get ECMP-NHG map entry.\n");
            return status;
        }

        if (db_entry->key == key) {
            break;
        }

        prev_idx = idx;
        prev_db_entry = db_entry;
        idx = db_entry->next_idx;
    }

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        SX_LOG_ERR("Missing ECMP-NHG map entry.\n");
        return SAI_STATUS_FAILURE;
    }

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(prev_idx)) {
        g_sai_db_ptr->ecmp_to_nhg_map[index] = db_entry->next_idx;
    } else {
        prev_db_entry->next_idx = db_entry->next_idx;
    }

    status = mlnx_ecmp_to_nhg_db_entry_free(idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to deallocate ECMP-NHG map entry.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_ecmp_to_nhg_map_entry_get(_In_ sx_ecmp_id_t key, _Out_ mlnx_shm_rm_array_idx_t *value)
{
    sai_status_t                 status;
    uint32_t                     index = mlnx_ecmp_id_hash(key) % MLNX_ECMP_NHG_HASHTABLE_SIZE;
    mlnx_ecmp_to_nhg_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t      idx;

    idx = g_sai_db_ptr->ecmp_to_nhg_map[index];

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        status = mlnx_ecmp_to_nhg_db_entry_idx_to_data(idx,
                                                       &db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get ECMP-NHG map entry.\n");
            return status;
        }

        if (db_entry->key == key) {
            break;
        }

        idx = db_entry->next_idx;
    }

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        value->type = MLNX_SHM_RM_ARRAY_TYPE_INVALID;
        value->idx = 0;
        return SAI_STATUS_SUCCESS;
    }

    *value = db_entry->nhg_idx;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_nh_data_get(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                          _In_ mlnx_nhg_db_entry_t  *nhg_db_entry,
                                          _In_ sai_object_id_t       vrf,
                                          _Out_ sx_next_hop_t       *next_hop)
{
    sai_status_t               status;
    mlnx_nhg_encap_vrf_data_t *vrf_data;

    status = mlnx_nhg_vrf_data_get(nhg_db_entry,
                                   vrf,
                                   &vrf_data,
                                   false);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG VRF-data.\n");
        return status;
    }

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP) {
        status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                   nhg_db_entry,
                                                   vrf_data,
                                                   0,
                                                   next_hop);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get Encap NHGM nh data.\n");
            return status;
        }
    } else if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE) {
        status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                    nhg_db_entry,
                                                    next_hop);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get Native NHGM nh data.\n");
            return status;
        }
    } else {
        SX_LOG_ERR("Unexpected NHGM type.\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_nh_data_get(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                         _In_ sai_object_id_t      vrf,
                                         _Out_ sx_next_hop_t      *next_hops,
                                         _Out_ uint32_t           *next_hops_count)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nhgm_idx = nhg_db_entry->data.members;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;

    *next_hops_count = 0;

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_idx)) {
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_idx, &nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM DB data.\n");
            return status;
        }

        status = mlnx_nhgm_nh_data_get(nhgm_db_entry,
                                       nhg_db_entry,
                                       vrf,
                                       &next_hops[*next_hops_count]);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM nh data.\n");
            return status;
        }

        *next_hops_count += 1;

        nhgm_idx = nhgm_db_entry->data.next_member_idx;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_create_ecmp(_In_ mlnx_shm_rm_array_idx_t nhg_idx,
                                         _In_ mlnx_nhg_db_entry_t    *nhg_db_entry,
                                         _In_ sai_object_id_t         vrf)
{
    sai_status_t               status;
    sx_status_t                sx_status;
    mlnx_nhg_encap_vrf_data_t *vrf_data = NULL;
    uint32_t                   next_hops_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t              next_hops[FG_ECMP_MAX_PATHS];

    assert(nhg_db_entry);

    status = mlnx_nhg_nh_data_get(nhg_db_entry,
                                  vrf,
                                  next_hops,
                                  &next_hops_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG nh_data.\n");
        return status;
    }

    status = mlnx_nhg_vrf_data_get(nhg_db_entry,
                                   vrf,
                                   &vrf_data,
                                   false);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG VRF-data.\n");
        return status;
    }

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_CREATE,
                                       &vrf_data->sx_ecmp_id,
                                       next_hops,
                                       &next_hops_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_ecmp_to_nhg_map_entry_add(vrf_data->sx_ecmp_id,
                                            nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add ECMP-NHG map entry.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_remove_ecmp(_In_ mlnx_nhg_db_entry_t *nhg_db_entry, _In_ sai_object_id_t vrf)
{
    sai_status_t               status;
    sx_status_t                sx_status;
    sx_ecmp_id_t               sx_ecmp_id = 0;
    uint32_t                   next_hops_cnt;
    mlnx_nhg_encap_vrf_data_t *vrf_data = NULL;

    assert(nhg_db_entry);

    status = mlnx_nhg_sx_ecmp_get(nhg_db_entry,
                                  vrf,
                                  &sx_ecmp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG sx_ecmp_id.\n");
        return status;
    }

    status = mlnx_ecmp_to_nhg_map_entry_del(sx_ecmp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to delete ECMP-NHG map entry.\n");
        return status;
    }

    status = mlnx_nhg_vrf_data_get(nhg_db_entry,
                                   vrf,
                                   &vrf_data,
                                   false);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG VRF-data.\n");
        return status;
    }

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_DESTROY,
                                       &vrf_data->sx_ecmp_id,
                                       NULL,
                                       &next_hops_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_counter_update(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                             _In_ sai_object_id_t       vrf,
                                             _In_ int32_t               diff)
{
    assert(nhgm_db_entry);

    if ((nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) ||
        (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE)) {
        return SAI_STATUS_SUCCESS;
    }

    if (nhgm_db_entry->data.type != MLNX_NHGM_TYPE_ENCAP) {
        return SAI_STATUS_FAILURE;
    }

    return mlnx_encap_nexthop_counter_update(nhgm_db_entry->data.entry.nh_idx,
                                             vrf,
                                             diff,
                                             NH_COUNTER_TYPE_NHGM);
}

static sai_status_t mlnx_nhg_update_nhgm_counters(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                                  _In_ sai_object_id_t      vrf,
                                                  _In_ int32_t              diff)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nhgm_idx = nhg_db_entry->data.members;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_idx)) {
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_idx, &nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM DB data.\n");
            return status;
        }

        status = mlnx_nhgm_counter_update(nhgm_db_entry,
                                          vrf,
                                          diff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update NHGM counter.\n");
            return status;
        }

        nhgm_idx = nhgm_db_entry->data.next_member_idx;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhg_counter_update(_In_ mlnx_shm_rm_array_idx_t nhg_idx, _In_ sai_object_id_t vrf, _In_ int32_t diff)
{
    sai_status_t               status;
    mlnx_nhg_encap_vrf_data_t *vrf_data = NULL;
    mlnx_nhg_db_entry_t       *nhg_db_entry;

    status = mlnx_nhg_db_entry_idx_to_data(nhg_idx,
                                           &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG db entry.\n");
        return status;
    }

    if (nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) {
        return SAI_STATUS_SUCCESS;
    }

    if (diff == 0) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_nhg_vrf_data_get(nhg_db_entry,
                                   vrf,
                                   &vrf_data,
                                   diff > 0);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG VRF-data.\n");
        return status;
    }

    if ((vrf_data->refcount + diff) < 0) {
        SX_LOG_ERR("Negative refcount.\n");
        return SAI_STATUS_FAILURE;
    }

    if (diff > 0) {
        if (vrf_data->refcount == 0) {
            status = mlnx_nhg_update_nhgm_counters(nhg_db_entry,
                                                   vrf,
                                                   diff);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to update NHGM counters.\n");
                return status;
            }

            status = mlnx_nhg_create_ecmp(nhg_idx,
                                          nhg_db_entry,
                                          vrf);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to create NHG ECMP.\n");
                return status;
            }
        }
    } else {
        if (vrf_data->refcount + diff == 0) {
            status = mlnx_nhg_remove_ecmp(nhg_db_entry,
                                          vrf);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to remove NHG ECMP.\n");
                return status;
            }

            status = mlnx_nhg_update_nhgm_counters(nhg_db_entry,
                                                   vrf,
                                                   diff);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to update NHGM counters.\n");
                return status;
            }

            vrf_data->associated_vrf = SAI_NULL_OBJECT_ID;
            vrf_data->sx_ecmp_id = 0;
        }
    }

    vrf_data->refcount += diff;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhg_get_ecmp(_In_ sai_object_id_t nhg,
                               _In_ sai_object_id_t vrf,
                               _In_ int32_t         diff,
                               _Out_ sx_ecmp_id_t  *sx_ecmp_id)
{
    sai_status_t            status;
    mlnx_nhg_db_entry_t    *nhg_db_entry;
    mlnx_shm_rm_array_idx_t nhg_idx;

    sai_db_write_lock();

    status = mlnx_nhg_oid_to_data(nhg, &nhg_db_entry, &nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto exit;
    }

    if (diff > 0) {
        status = mlnx_nhg_counter_update(nhg_idx,
                                         vrf,
                                         diff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to increment NHG counter.\n");
            goto exit;
        }
    }

    status = mlnx_nhg_sx_ecmp_get(nhg_db_entry,
                                  vrf,
                                  sx_ecmp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get SX ECMP ID.\n");
        goto exit;
    }


    if (diff < 0) {
        status = mlnx_nhg_counter_update(nhg_idx,
                                         vrf,
                                         diff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrement NHG counter.\n");
            goto exit;
        }
    }

exit:
    sai_db_unlock();
    return status;
}

/**
 * @brief Create next hop group member
 *
 * @param[out] next_hop_group_member_id - next hop group member id
 * @param[in] attr_count - number of attributes
 * @param[in] attr_list - array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_next_hop_group_member(_Out_ sai_object_id_t     * next_hop_group_member_id,
                                                      _In_ sai_object_id_t        switch_id,
                                                      _In_ uint32_t               attr_count,
                                                      _In_ const sai_attribute_t *attr_list)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    /* CHECK INPUT */
    {
        if (NULL == next_hop_group_member_id) {
            SX_LOG_ERR("NULL next hop group member id param\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        *next_hop_group_member_id = SAI_NULL_OBJECT_ID;

        status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                                        next_hop_group_member_vendor_attribs,
                                        SAI_COMMON_API_CREATE);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed attribs check\n");
            return status;
        }

        char list_str[MAX_LIST_VALUE_STR_LEN];
        sai_attr_list_to_str(attr_count,
                             attr_list,
                             SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                             MAX_LIST_VALUE_STR_LEN,
                             list_str);
        SX_LOG_NTC("Create next hop group member, %s\n", list_str);
    }

    mlnx_nhgm_db_entry_t   *nhgm_db_entry = NULL;
    mlnx_shm_rm_array_idx_t nhgm_idx;

    /* HANDLE ATTRIBUTES */
    {
        mlnx_sai_attr_t         nhg;
        mlnx_sai_attr_t         nh;
        mlnx_sai_attr_t         weight;
        mlnx_sai_attr_t         counter;
        mlnx_sai_attr_t         index;
        mlnx_nhg_db_entry_t    *nhg_db_entry = NULL;
        mlnx_shm_rm_array_idx_t nhg_idx;
        uint32_t                data;
        uint16_t                ext;

        /* READ ATTRIBUTES */
        {
            find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID, &nhg);
            assert(nhg.found);
            find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID, &nh);
            assert(nh.found);
            find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, &weight);
            find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID, &counter);
            find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_INDEX, &index);
        }

        sai_db_write_lock();

        status = mlnx_nhg_oid_to_data(nhg.value->oid, &nhg_db_entry, &nhg_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHG data from DB.\n");
            goto exit;
        }

        if ((nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) && !index.found) {
            SX_LOG_ERR("Index attribute required for fine grain ecmp nexthop group member\n");
            status = SAI_STATUS_FAILURE;
            goto exit;
        }

        status = mlnx_object_to_type(nh.value->oid, SAI_OBJECT_TYPE_NEXT_HOP, &data, (uint8_t*)&ext);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Unexpected NH OID.\n");
            goto exit;
        }

        status = mlnx_nhgm_db_entry_alloc(&nhgm_db_entry, &nhgm_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to allocate NHGM DB entry.\n");
            goto exit;
        }

        nhgm_db_entry->data.nhg_idx = nhg_idx;

        if (index.found) {
            nhgm_db_entry->data.type = MLNX_NHGM_TYPE_FINE_GRAIN;
            nhgm_db_entry->data.entry.fg_id = index.value->u32;
        } else if (ext == 1) {
            nhgm_db_entry->data.type = MLNX_NHGM_TYPE_ENCAP;
            nhgm_db_entry->data.entry.nh_idx = *(mlnx_shm_rm_array_idx_t*)&data;
        } else {
            nhgm_db_entry->data.type = MLNX_NHGM_TYPE_NATIVE;
            nhgm_db_entry->data.entry.sx_ecmp_id = (sx_ecmp_id_t)data;
        }

        if (weight.found) {
            nhgm_db_entry->data.weight = weight.value->u32;
        } else {
            nhgm_db_entry->data.weight = 1;
        }

        if (counter.found) {
            mlnx_counter_t         *counter_db_entry;
            mlnx_shm_rm_array_idx_t counter_idx;
            status = mlnx_counter_oid_to_data(counter.value->oid, &counter_db_entry, &counter_idx);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get counter DB entry.\n");
                goto exit;
            }
            nhgm_db_entry->data.flow_counter = counter_idx;
        }

        status = mlnx_nhgm_apply(nhgm_db_entry, nhgm_idx, nh.value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply NHGM.\n");
            goto exit;
        }
    }

    /* CREATE SAI OID */
    {
        status = mlnx_nhgm_oid_create(nhgm_idx, next_hop_group_member_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create NHGM OID.\n");
            goto exit;
        }

        char key_str[MAX_KEY_STR_LEN];
        next_hop_group_member_key_to_str(*next_hop_group_member_id, key_str);
        SX_LOG_NTC("Created next hop group member %s\n", key_str);
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t update_next_hop_data_to_ecmp_id(sx_ecmp_id_t  group,
                                                    sx_next_hop_t old_nh_data,
                                                    sx_next_hop_t new_nh_data)
{
    sx_status_t   sx_status;
    sai_status_t  status;
    uint32_t      next_hop_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t ecmp_next_hops[FG_ECMP_MAX_PATHS];
    uint32_t      ii;

    sx_status = sx_api_router_ecmp_get(gh_sdk, group, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_sdk_nhop_find_in_list(ecmp_next_hops, next_hop_count, &old_nh_data, &ii);
    if (SAI_ERR(status)) {
        return status;
    }

    ecmp_next_hops[ii] = new_nh_data;

    sx_status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &group, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t remove_next_hop_data_from_ecmp_id(sx_ecmp_id_t group, sx_next_hop_t nh_data)
{
    sx_status_t   sx_status;
    sai_status_t  status;
    uint32_t      next_hop_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t ecmp_next_hops[FG_ECMP_MAX_PATHS];
    uint32_t      ii;

    sx_status = sx_api_router_ecmp_get(gh_sdk, group, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_sdk_nhop_find_in_list(ecmp_next_hops, next_hop_count, &nh_data, &ii);
    if (SAI_ERR(status)) {
        return status;
    }
    ecmp_next_hops[ii] = ecmp_next_hops[--next_hop_count];

    sx_status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &group, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_native_remove(mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                 mlnx_nhg_db_entry_t  *nhg_db_entry)
{
    sx_next_hop_t              sx_next_hop;
    mlnx_nhg_encap_vrf_data_t *vrf_data;
    sai_status_t               status;

    assert(nhg_db_entry && nhgm_db_entry && nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE);

    status = get_next_hop_data_from_native_nhgm(nhgm_db_entry, nhg_db_entry, &sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop data.\n");
        return status;
    }

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            status = remove_next_hop_data_from_ecmp_id(vrf_data->sx_ecmp_id,
                                                       sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to remove nexthop_data from sx_ecmp_id. [index = %d]\n", ii);
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_encap_remove(mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                mlnx_nhg_db_entry_t  *nhg_db_entry)
{
    sx_next_hop_t              sx_next_hop;
    mlnx_nhg_encap_vrf_data_t *vrf_data;
    sai_status_t               status;

    assert(nhg_db_entry && nhgm_db_entry && nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP);

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry, nhg_db_entry, vrf_data, false, &sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get next hop data.\n");
                return status;
            }

            status = remove_next_hop_data_from_ecmp_id(vrf_data->sx_ecmp_id,
                                                       sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id. [index = %d]\n", ii);
                return status;
            }

            status = mlnx_nhgm_counter_update(nhgm_db_entry,
                                              vrf_data->associated_vrf,
                                              -vrf_data->refcount);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to decrement NHGM counter.\n");
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_fine_grain_remove(mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                     mlnx_nhg_db_entry_t  *nhg_db_entry)
{
    SX_LOG_DBG("Nothing to do for FG ECMP\n");
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_remove(mlnx_nhgm_db_entry_t *nhgm_db_entry, mlnx_shm_rm_array_idx_t nhgm_idx)
{
    sai_status_t         status = SAI_STATUS_SUCCESS;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    assert(nhgm_db_entry);

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry.\n");
        return status;
    }

    status = unlink_nhgm_from_nhg(nhgm_idx, nhgm_db_entry, nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unlink NHGM to NHG.\n");
        return status;
    }

    switch (nhgm_db_entry->data.type) {
    case MLNX_NHGM_TYPE_NATIVE:
        status = mlnx_nhgm_type_native_remove(nhgm_db_entry, nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHGM type NATIVE.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_ENCAP:
        status = mlnx_nhgm_type_encap_remove(nhgm_db_entry, nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHGM type ENCAP.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_FINE_GRAIN:
        status = mlnx_nhgm_type_fine_grain_remove(nhgm_db_entry, nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHGM type FINE_GRAIN.\n");
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected NHGM type: %u.\n", nhgm_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove next hop group member
 *
 * @param[in] next_hop_group_member_id - next hop group member id
 *
 * @return SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_next_hop_group_member(_In_ sai_object_id_t next_hop_group_member_id)
{
    sai_status_t status;
    char         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_member_key_to_str(next_hop_group_member_id, key_str);
    SX_LOG_NTC("Remove next hop group member %s\n", key_str);

    mlnx_nhgm_db_entry_t   *db_entry;
    mlnx_shm_rm_array_idx_t idx;

    sai_db_write_lock();

    status = mlnx_nhgm_oid_to_data(next_hop_group_member_id, &db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto exit;
    }

    status = mlnx_nhgm_remove(db_entry, idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove NHGM.\n");
        goto exit;
    }

    status = mlnx_nhgm_db_entry_free(idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to free NHGM DB entry.\n");
        goto exit;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}


static void next_hop_group_member_key_to_str(_In_ sai_object_id_t group_member_id, _Out_ char *key_str)
{
    sai_status_t status;
    uint32_t     data;
    uint16_t     ext;

    status = mlnx_object_to_type(group_member_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, &data, (uint8_t*)&ext);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid next hop group member id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "next hop group member id 0x%08X", data);
    }
}

/**
 * @brief Set Next Hop Group attribute
 *
 * @param[in] sai_object_id_t - next_hop_group_member_id
 * @param[in] attr - attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_next_hop_group_member_attribute(_In_ sai_object_id_t        next_hop_group_member_id,
                                                             _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = next_hop_group_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_member_key_to_str(next_hop_group_member_id, key_str);
    return sai_set_attribute(&key,
                             key_str,
                             SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                             next_hop_group_member_vendor_attribs,
                             attr);
}

/**
 * @brief Get Next Hop Group attribute
 *
 * @param[in] sai_object_id_t - next_hop_group_member_id
 * @param[in] attr_count - number of attributes
 * @param[inout] attr_list - array of attributes
 *
 * @return SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_next_hop_group_member_attribute(_In_ sai_object_id_t     next_hop_group_member_id,
                                                             _In_ uint32_t            attr_count,
                                                             _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = next_hop_group_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_member_key_to_str(next_hop_group_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                              next_hop_group_member_vendor_attribs,
                              attr_count,
                              attr_list);
}

sai_status_t mlnx_remove_next_hop_group_members(_In_ uint32_t                 object_count,
                                                _In_ const sai_object_id_t   *object_id,
                                                _In_ sai_bulk_op_error_mode_t mode,
                                                _Out_ sai_status_t           *object_statuses);

/**
 * @brief Bulk next hop group members creation.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_count Number of objects to create
 * @param[in] attr_count List of attr_count. Caller passes the number
 *    of attribute for each object to create.
 * @param[in] attr_list List of attributes for every object.
 * @param[in] mode Bulk operation error handling mode.
 *
 * @param[out] object_id List of object ids returned
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are created or #SAI_STATUS_FAILURE when
 * any of the objects fails to create. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
sai_status_t mlnx_create_next_hop_group_members(_In_ sai_object_id_t          switch_id,
                                                _In_ uint32_t                 object_count,
                                                _In_ const uint32_t          *attr_count,
                                                _In_ const sai_attribute_t  **attr_list,
                                                _In_ sai_bulk_op_error_mode_t mode,
                                                _Out_ sai_object_id_t        *object_id,
                                                _Out_ sai_status_t           *object_statuses)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
        for (uint32_t ii = 0; ii < object_count; ii++) {
            object_statuses[ii] = SAI_STATUS_NOT_EXECUTED;
        }
    }

    for (uint32_t ii = 0; ii < object_count; ii++) {
        object_statuses[ii] = mlnx_create_next_hop_group_member(&object_id[ii],
                                                                switch_id,
                                                                attr_count[ii],
                                                                attr_list[ii]);
        if (SAI_ERR(object_statuses[ii])) {
            status = object_statuses[ii];
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                return status;
            }
        }
    }

    return status;
}

/**
 * @brief Bulk next hop group members removal.
 *
 * @param[in] object_count Number of objects to create
 * @param[in] object_id List of object ids
 * @param[in] mode Bulk operation error handling mode.
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or #SAI_STATUS_FAILURE when
 * any of the objects fails to remove. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
sai_status_t mlnx_remove_next_hop_group_members(_In_ uint32_t                 object_count,
                                                _In_ const sai_object_id_t   *object_id,
                                                _In_ sai_bulk_op_error_mode_t mode,
                                                _Out_ sai_status_t           *object_statuses)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
        for (uint32_t ii = 0; ii < object_count; ii++) {
            object_statuses[ii] = SAI_STATUS_NOT_EXECUTED;
        }
    }

    for (uint32_t ii = 0; ii < object_count; ii++) {
        object_statuses[ii] = mlnx_remove_next_hop_group_member(object_id[ii]);

        if (SAI_ERR(object_statuses[ii])) {
            status = object_statuses[ii];
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                return status;
            }
        }
    }

    return status;
}

const sai_next_hop_group_api_t mlnx_next_hop_group_api = {
    mlnx_create_next_hop_group,
    mlnx_remove_next_hop_group,
    mlnx_set_next_hop_group_attribute,
    mlnx_get_next_hop_group_attribute,
    mlnx_create_next_hop_group_member,
    mlnx_remove_next_hop_group_member,
    mlnx_set_next_hop_group_member_attribute,
    mlnx_get_next_hop_group_member_attribute,
    mlnx_create_next_hop_group_members,
    mlnx_remove_next_hop_group_members,
    NULL,
    NULL,
    NULL,
    NULL,
};
