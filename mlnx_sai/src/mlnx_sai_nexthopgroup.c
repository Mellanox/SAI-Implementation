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
        SAI_NEXT_HOP_GROUP_TYPE_FINE_GRAIN_ECMP,
        SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP,
        )
};
static size_t next_hop_group_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[ID:%u]", mlnx_oid.id.nhg_db_idx.idx);
}
const mlnx_obj_type_attrs_info_t mlnx_next_hop_group_obj_type_info =
{ next_hop_group_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(nh_group_enum_info), OBJ_STAT_CAP_INFO_EMPTY(),
  next_hop_group_info_print};

static sai_status_t mlnx_nhgm_attr_set(_In_ const sai_object_key_t      *key,
                                       _In_ const sai_attribute_value_t *value,
                                       void                             *arg);
static sai_status_t mlnx_nhgm_attr_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg);
static sai_status_t mlnx_nghm_priority_set(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                           _In_ sai_object_id_t       priority);

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
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_nhgm_attr_get, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID,
      mlnx_nhgm_attr_set, (void *)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static size_t next_hop_group_member_info_print(_In_ const sai_object_key_t *key,
                                               _Out_ char                  *str,
                                               _In_ size_t                  max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[ID:%u]", mlnx_oid.id.nhgm_db_idx.idx);
}
const mlnx_obj_type_attrs_info_t mlnx_nh_group_member_obj_type_info =
{ next_hop_group_member_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY(),
  next_hop_group_member_info_print};

typedef struct mlnx_nhgm_bulk_node_t_ {
    uint32_t                       ii;
    struct mlnx_nhgm_bulk_node_t_ *next;
} mlnx_nhgm_bulk_node_t;

typedef struct mlnx_nhgm_bulk_entry_t_ {
    sai_object_id_t        nhg;
    mlnx_nhgm_bulk_node_t *list;
} mlnx_nhgm_bulk_entry_t;

static sai_status_t mlnx_ecmp_to_nhg_map_entry_add(_In_ sx_ecmp_id_t            key,
                                                   _In_ mlnx_shm_rm_array_idx_t value);
static sai_status_t mlnx_ecmp_to_nhg_map_entry_del(_In_ sx_ecmp_id_t key);
static sai_status_t replace_next_hop_data_in_ecmp_id(sx_ecmp_id_t  group,
                                                     sx_next_hop_t old_nh_data,
                                                     sx_next_hop_t new_nh_data);
static sai_status_t get_next_hop_data_from_encap_nhgm(_In_ mlnx_nhgm_db_entry_t      *nhgm_db_entry,
                                                      _In_ mlnx_nhg_encap_vrf_data_t *vrf_data,
                                                      _In_ bool                       create,
                                                      _Out_ sx_next_hop_t            *sx_next_hop);
static sai_status_t get_next_hop_data_from_native_nhgm(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                       _Out_ sx_next_hop_t       *sx_next_hop);
static sai_status_t mlnx_nhgm_counter_update(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                             _In_ sai_object_id_t       vrf,
                                             _In_ int32_t               diff,
                                             _In_ bool                  nhgm_init_stage);
static sai_status_t mlnx_nhgm_parse_attrs(mlnx_nhgm_db_entry_t   **nhgm_db_entry,
                                          mlnx_shm_rm_array_idx_t *nhgm_idx,
                                          const sai_attribute_t   *attr_list,
                                          uint32_t                 attr_count);

static sai_status_t mlnx_nhgm_get_nh_idx(_In_ mlnx_nhgm_db_entry_t     *nhgm_db_entry,
                                         _Out_ mlnx_shm_rm_array_idx_t *nh_idx)
{
    assert(nhgm_db_entry);
    assert(nh_idx);

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP) {
        *nh_idx = nhgm_db_entry->data.entry.encap.nh_idx;
    } else if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_ENCAP) {
        *nh_idx = nhgm_db_entry->data.entry.ordered.entry.encap.nh_idx;
    } else {
        SX_LOG_ERR("Unexpected NHGM type [%u]\n", nhgm_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_get_sx_ecmp(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                          _Out_ sx_ecmp_id_t        *sx_ecmp_id)
{
    assert(nhgm_db_entry);
    assert(sx_ecmp_id);

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE) {
        *sx_ecmp_id = nhgm_db_entry->data.entry.native.sx_ecmp_id;
    } else if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_NATIVE) {
        *sx_ecmp_id = nhgm_db_entry->data.entry.ordered.entry.native.sx_ecmp_id;
    } else {
        SX_LOG_ERR("Unexpected NHGM type [%u].\n", nhgm_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

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
    mlnx_ecmp_to_nhg_db_entry_t *data;
    sai_status_t                 status;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, (void**)&data);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!data->array_hdr.is_used) {
        SX_LOG_ERR("NHG DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    *db_entry = data;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhg_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ mlnx_nhg_db_entry_t  **nhg_db_entry)
{
    mlnx_nhg_db_entry_t *data;
    sai_status_t         status;

    assert(nhg_db_entry);

    status = mlnx_shm_rm_array_idx_to_ptr(idx, (void**)&data);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!data->array_hdr.is_used) {
        SX_LOG_ERR("NHG DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    *nhg_db_entry = data;

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

sai_status_t mlnx_nhg_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t       *oid)
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
    mlnx_nhgm_db_entry_t *data;
    sai_status_t          status;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, (void**)&data);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!data->array_hdr.is_used) {
        SX_LOG_ERR("NHGM DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    *nhgm_db_entry = data;

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

static bool mlnx_is_ar_nexthop(sx_next_hop_t* sx_next_hop)
{
    sx_router_id_t              vrid;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 sx_status;

    if (sx_next_hop->next_hop_key.type == SX_NEXT_HOP_TYPE_IP) {
        sx_status = sx_api_router_interface_get(gh_sdk,
                                                sx_next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.rif,
                                                &vrid,
                                                &intf_params,
                                                &intf_attribs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(sx_status));
            return false;
        }
        return (SX_L2_INTERFACE_TYPE_ADAPTIVE_ROUTING == intf_params.type);
    }
    return false;
}

sai_status_t mlnx_get_ecmp_attr(_In_ const sx_ecmp_id_t ecmp_id, _Out_ sx_ecmp_attributes_t *sx_ecmp_attr)
{
    sx_status_t sx_status;

    assert(NULL != sx_ecmp_attr);

    sx_status = sx_api_router_ecmp_attributes_get(gh_sdk, ecmp_id, sx_ecmp_attr);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set router ecmp attributes - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_ar_ecmp_attr(const sx_ecmp_id_t ecmp_id, uint32_t ecmp_group_size)
{
    sx_status_t          sx_status;
    sx_ecmp_attributes_t sx_ecmp_attr = {0};

    SX_LOG_DBG("set ar router ecmp attributes - ecmp id[%u] type[%u] size[%u].\n",
               ecmp_id,
               SX_ECMP_TYPE_ADAPTIVE_E,
               ecmp_group_size);
    sx_ecmp_attr.ecmp_type = SX_ECMP_TYPE_ADAPTIVE_E;
    sx_ecmp_attr.group_size = ecmp_group_size;
    sx_status = sx_api_router_ecmp_attributes_set(gh_sdk, ecmp_id, &sx_ecmp_attr);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set router ecmp attributes - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    return SAI_STATUS_SUCCESS;
}

/* Check if an ecmp container is ar enabled. If yes, set the ar attr. */
static sai_status_t mlnx_check_and_set_ar_ecmp(const sx_ecmp_id_t ecmp_id,
                                               sx_next_hop_t     *next_hops,
                                               uint32_t           next_hops_count)
{
    sx_status_t        sx_status;
    sai_status_t       status;
    uint32_t           sdk_next_hop_cnt = 0;
    uint32_t           ar_next_hop_cnt = 0;
    mlnx_ar_db_data_t *ar_data = &g_sai_db_ptr->ar_db;

    assert(NULL != next_hops);

    /* Skip checking for empty next hop list */
    if (0 == next_hops_count) {
        return SAI_STATUS_SUCCESS;
    }

    /* Skip checking if there are existing next hops in ecmp */
    sx_status = sx_api_router_ecmp_get(gh_sdk, ecmp_id, NULL, &sdk_next_hop_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    if (0 != sdk_next_hop_cnt) {
        return SAI_STATUS_SUCCESS;
    }

    for (uint32_t ii = 0; ii < next_hops_count; ii++) {
        if (mlnx_is_ar_nexthop(&next_hops[ii])) {
            ar_next_hop_cnt++;
        }
    }

    if (ar_next_hop_cnt == next_hops_count) {
        /* All next hops are AR enabled */
        status = mlnx_set_ar_ecmp_attr(ecmp_id, ar_data->ar_ecmp_size);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set router ecmp to adaptive routing.\n");
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_type_ecmp_counter_apply(_In_ mlnx_nhg_db_entry_t *nhg_db_entry)
{
    sai_status_t         status;
    sx_status_t          sx_status;
    sx_flow_counter_id_t sx_flow_counter = SX_FLOW_COUNTER_ID_INVALID;

    assert(nhg_db_entry &&
           (nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP ||
            nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED));

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhg_db_entry->data.flow_counter)) {
        status = mlnx_get_sx_flow_counter_id_by_idx(nhg_db_entry->data.flow_counter,
                                                    &sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter [ID:%u].\n", nhg_db_entry->data.flow_counter.idx);
            return status;
        }
    }

    if (nhg_db_entry->data.members_count != 0) {
        for (uint32_t ii = 0; ii < NUMBER_OF_VRF_DATA_SETS; ii++) {
            if (nhg_db_entry->data.data.encap.vrf_data[ii].refcount > 0) {
                uint32_t        offset = 0;
                sx_access_cmd_t cmd = sx_flow_counter ==
                                      SX_FLOW_COUNTER_ID_INVALID ? SX_ACCESS_CMD_UNBIND : SX_ACCESS_CMD_BIND;

                sx_status = sx_api_router_ecmp_counter_bind_set(gh_sdk,
                                                                cmd,
                                                                nhg_db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id,
                                                                &sx_flow_counter,
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

static sai_status_t mlnx_nhg_type_fine_grain_counter_apply(_In_ mlnx_nhg_db_entry_t *nhg_db_entry)
{
    sai_status_t         status;
    sx_status_t          sx_status;
    sx_flow_counter_id_t sx_flow_counter = SX_FLOW_COUNTER_ID_INVALID;

    assert(nhg_db_entry &&
           nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN);

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhg_db_entry->data.flow_counter)) {
        status = mlnx_get_sx_flow_counter_id_by_idx(nhg_db_entry->data.flow_counter,
                                                    &sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter [ID:%u].\n", nhg_db_entry->data.flow_counter.idx);
            return status;
        }
    }

    if (nhg_db_entry->data.members_count > 0) {
        uint32_t        offset = 0;
        sx_access_cmd_t cmd = sx_flow_counter ==
                              SX_FLOW_COUNTER_ID_INVALID ? SX_ACCESS_CMD_UNBIND : SX_ACCESS_CMD_BIND;

        sx_status = sx_api_router_ecmp_counter_bind_set(gh_sdk,
                                                        cmd,
                                                        nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                                        &sx_flow_counter,
                                                        &offset,
                                                        1);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to %s counter - %s.\n",
                       sx_flow_counter == SX_FLOW_COUNTER_ID_INVALID ? "unbind" : "bind",
                       SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_flow_counter_apply(_In_ mlnx_nhg_db_entry_t *nhg_db_entry)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    assert(nhg_db_entry);

    if ((nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) ||
        (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED)) {
        status = mlnx_nhg_type_ecmp_counter_apply(nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply flow counter for NHG type ECMP/ORDERED_ECMP.\n");
            return status;
        }
    } else if (nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) {
        status = mlnx_nhg_type_fine_grain_counter_apply(nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply flow counter for NHG type FINE_GRAIN.\n");
            return status;
        }
    } else {
        SX_LOG_ERR("Unexpected NHG type [%u].\n", nhg_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_ecmp_prepare(_Inout_ mlnx_nhg_db_entry_t *nhg_db_entry, _In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t  status;
    sx_status_t   sx_status;
    const int32_t ecmp_idx = MLNX_REGULAR_ECMP_INDEX;
    sx_next_hop_t next_hops[1] = {0};
    uint32_t      next_hop_cnt = 0;

    assert((nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) ||
           (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED));

    nhg_db_entry->data.data.encap.vrf_data[ecmp_idx].associated_vrf = SAI_NULL_OBJECT_ID;
    nhg_db_entry->data.data.encap.vrf_data[ecmp_idx].refcount = 0;

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_CREATE,
                                       &nhg_db_entry->data.data.encap.vrf_data[ecmp_idx].sx_ecmp_id,
                                       next_hops,
                                       &next_hop_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_ecmp_to_nhg_map_entry_add(nhg_db_entry->data.data.encap.vrf_data[ecmp_idx].sx_ecmp_id,
                                            idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add ECMP-NHG map entry [0x%X:%u].\n",
                   nhg_db_entry->data.data.encap.vrf_data[ecmp_idx].sx_ecmp_id,
                   idx.idx);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhg_parse_attrs(_Out_ mlnx_nhg_db_entry_t    **nhg_db_entry,
                                  _Out_ mlnx_shm_rm_array_idx_t *nhg_idx,
                                  _In_ const sai_attribute_t    *attr_list,
                                  _In_ uint32_t                  attr_count)
{
    sai_status_t status;

    *nhg_db_entry = NULL;
    *nhg_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

    status = check_attribs_metadata(attr_count,
                                    attr_list,
                                    SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                                    next_hop_group_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    mlnx_sai_attr_t type;
    mlnx_sai_attr_t counter;
    mlnx_sai_attr_t configured_size;

    /* READ ATTRIBUTES */
    {
        find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_TYPE, &type);
        assert(type.found);
        find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID, &counter);
        find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_CONFIGURED_SIZE, &configured_size);
    }

    status = mlnx_nhg_db_entry_alloc(nhg_db_entry,
                                     nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to allocate NHG DB entry.\n");
        return status;
    }

    switch (type.value->s32) {
    case SAI_NEXT_HOP_GROUP_TYPE_FINE_GRAIN_ECMP:
        (*nhg_db_entry)->data.type = MLNX_NHG_TYPE_FINE_GRAIN;
        assert(configured_size.found);
        uint32_t real_size;
        status = mlnx_fg_ecmp_size_configured_to_real(configured_size.value->u32,
                                                      &real_size);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("The requested size %u is not available.\n", configured_size.value->u32);
            goto exit;
        }

        (*nhg_db_entry)->data.data.fine_grain.sx_ecmp_id = SX_ROUTER_ECMP_ID_INVALID;
        (*nhg_db_entry)->data.data.fine_grain.configured_size = configured_size.value->u32;
        (*nhg_db_entry)->data.data.fine_grain.real_size = real_size;
        break;

    case SAI_NEXT_HOP_GROUP_TYPE_ECMP:
        (*nhg_db_entry)->data.type = MLNX_NHG_TYPE_ECMP;
        break;

    case SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP:
        (*nhg_db_entry)->data.type = MLNX_NHG_TYPE_ORDERED;
        break;

    default:
        SX_LOG_ERR("Unsupported NHG type: [%d]\n", type.value->s32);
        status = SAI_STATUS_FAILURE;
        goto exit;
    }

    if (counter.found) {
        mlnx_counter_t         *counter_db_entry;
        mlnx_shm_rm_array_idx_t counter_idx;

        status = mlnx_counter_oid_to_data(counter.value->oid,
                                          &counter_db_entry,
                                          &counter_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get counter [OID:0x%X] DB entry.\n",
                       counter.value->oid);
            goto exit;
        }
        (*nhg_db_entry)->data.flow_counter = counter_idx;
    }

exit:
    if (SAI_ERR(status)) {
        mlnx_nhg_db_entry_free(*nhg_idx);
        *nhg_db_entry = NULL;
        *nhg_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    }
    return status;
}

sai_status_t mlnx_nhg_apply(_In_ mlnx_nhg_db_entry_t *nhg_db_entry, _In_ mlnx_shm_rm_array_idx_t nhg_idx)
{
    sai_status_t status;

    assert(nhg_db_entry);

    switch (nhg_db_entry->data.type) {
    case MLNX_NHG_TYPE_FINE_GRAIN:
        /* Nothing to do here */
        break;

    case MLNX_NHG_TYPE_ECMP:
    case MLNX_NHG_TYPE_ORDERED:
        status = mlnx_nhg_ecmp_prepare(nhg_db_entry,
                                       nhg_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to prepare NHG type ECMP/ORDERED_ECMP.\n");
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected NHG type [%u].\n", nhg_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhg_db_entry->data.flow_counter)) {
        status = mlnx_nhg_flow_counter_apply(nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set NHG counter [ID:%u].\n", nhg_db_entry->data.flow_counter.idx);
            return status;
        }
    }

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
        status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, next_hop_group_id);
        if (SAI_ERR(status)) {
            return status;
        }

        MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP);
    }

    mlnx_nhg_db_entry_t    *nhg_db_entry = NULL;
    mlnx_shm_rm_array_idx_t nhg_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

    sai_db_write_lock();

    /* HANDLE ATTRIBUTES */
    {
        status = mlnx_nhg_parse_attrs(&nhg_db_entry,
                                      &nhg_idx,
                                      attr_list,
                                      attr_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to store NHG attributes.\n");
            goto exit;
        }

        status = mlnx_nhg_apply(nhg_db_entry,
                                nhg_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply NHG.\n");
            goto exit;
        }
    }

    /* CREATE SAI OID */
    {
        status = mlnx_nhg_oid_create(nhg_idx, next_hop_group_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create NHG OID.\n");
            goto exit;
        }

        MLNX_LOG_OID_CREATED(*next_hop_group_id);
    }

exit:
    if (SAI_ERR(status) && nhg_db_entry) {
        mlnx_nhg_db_entry_free(nhg_idx);
    }
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_nhg_ecmp_remove(_In_ mlnx_nhg_db_entry_t *nhg_db_entry)
{
    sx_status_t  sx_status;
    sai_status_t status;
    uint32_t     next_hop_cnt = 0;

    assert(nhg_db_entry &&
           ((nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) ||
            (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED)));

    for (uint32_t ii = 0; ii < NUMBER_OF_VRF_DATA_SETS; ii++) {
        if (nhg_db_entry->data.data.encap.vrf_data[ii].refcount > 0) {
            SX_LOG_ERR("VRF data [%d] is not empty [refcount=%d].\n", ii,
                       nhg_db_entry->data.data.encap.vrf_data[ii].refcount);
            return SAI_STATUS_FAILURE;
        }
    }

    status =
        mlnx_ecmp_to_nhg_map_entry_del(nhg_db_entry->data.data.encap.vrf_data[MLNX_REGULAR_ECMP_INDEX].sx_ecmp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to delete ECMP-NHG map entry [0x%X].\n",
                   nhg_db_entry->data.data.encap.vrf_data[MLNX_REGULAR_ECMP_INDEX].sx_ecmp_id);
        return status;
    }

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_DESTROY,
                                       &nhg_db_entry->data.data.encap.vrf_data[MLNX_REGULAR_ECMP_INDEX].sx_ecmp_id,
                                       NULL,
                                       &next_hop_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_fine_grain_remove(_In_ mlnx_nhg_db_entry_t *db_entry)
{
    sx_status_t sx_status;
    uint32_t    next_hop_cnt;

    assert(db_entry && db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN);

    if (SX_ROUTER_ECMP_ID_INVALID == db_entry->data.data.fine_grain.sx_ecmp_id) {
        /*do nothing */
        return SAI_STATUS_SUCCESS;
    }

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
    case MLNX_NHG_TYPE_ORDERED:
        status = mlnx_nhg_ecmp_remove(db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHG type ECMP/ORDERED.\n");
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

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(next_hop_group_id);

    mlnx_nhg_db_entry_t    *db_entry;
    mlnx_shm_rm_array_idx_t idx;

    sai_db_write_lock();

    status = mlnx_nhg_oid_to_data(next_hop_group_id, &db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG data [OID:0x%X] from DB.\n",
                   next_hop_group_id);
        goto exit;
    }

    status = mlnx_nhg_remove(db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove NHG [ID:%u].\n", idx.idx);
        goto exit;
    }

    status = mlnx_nhg_db_entry_free(idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to free NHG DB entry [ID:%u].\n", idx.idx);
        goto exit;
    }

exit:
    sai_db_unlock();
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

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, attr);
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

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, attr_count, attr_list);
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
        SX_LOG_ERR("Failed to get NHG data [OID:0x%X] from DB.\n", key->key.object_id);
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
        } else if (db_entry->data.type == MLNX_NHG_TYPE_ORDERED) {
            value->s32 = SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP;
        } else {
            SX_LOG_ERR("Unexpected NHG type [%u].\n", db_entry->data.type);
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
            SX_LOG_ERR("[CONFIGURED_SIZE] Attribute supported only for FINE_GRAIN ECMP.\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = db_entry->data.data.fine_grain.configured_size;
        break;

    case SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE:
        if (db_entry->data.type != MLNX_NHG_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("[REAL_SIZE] Attribute supported only for FINE_GRAIN ECMP.\n");
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

static sai_status_t mlnx_nhg_flow_counter_set(_In_ mlnx_nhg_db_entry_t *nhg_db_entry, _In_ sai_object_id_t counter)
{
    sai_status_t            status;
    mlnx_counter_t         *counter_db_entry;
    mlnx_shm_rm_array_idx_t counter_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

    if (counter != SAI_NULL_OBJECT_ID) {
        status = mlnx_counter_oid_to_data(counter,
                                          &counter_db_entry,
                                          &counter_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get counter DB entry [OID:0x%X].\n", counter);
            return status;
        }
    }

    nhg_db_entry->data.flow_counter = counter_idx;

    status = mlnx_nhg_flow_counter_apply(nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set flow counter.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_attr_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    long         attr = (long)arg;

    SX_LOG_ENTER();

    assert(attr == SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID);

    mlnx_nhg_db_entry_t *nhg_db_entry = NULL;

    sai_db_write_lock();

    status = mlnx_nhg_oid_to_data(key->key.object_id, &nhg_db_entry, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG data [OID:0x%X] from DB.\n", key->key.object_id);
        goto exit;
    }

    switch (attr) {
    case SAI_NEXT_HOP_GROUP_ATTR_COUNTER_ID:
        status = mlnx_nhg_flow_counter_set(nhg_db_entry,
                                           value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set flow counter [OID:0x%lX] to the NHG [OID:0x%lX]\n",
                       value->oid, key->key.object_id);
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
                                          _Out_ sx_flow_counter_id_t *sx_flow_counter)
{
    sai_status_t         status;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    assert(nhgm_db_entry && sx_flow_counter);

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [ID:%u] DB entry.\n", nhgm_db_entry->data.nhg_idx.idx);
        return status;
    }

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
    sai_status_t           status;
    sx_status_t            sx_status;
    mlnx_nhg_db_entry_t   *nhg_db_entry;
    sx_ecmp_update_entry_t edited_nhgm;

    if (nhgm_db_entry->data.type != MLNX_NHGM_TYPE_FINE_GRAIN) {
        SX_LOG_ERR("Failed to set next hop id - supported only for FINE_GRAIN_ECMP\n");
        return SAI_STATUS_FAILURE;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry,
                               &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry.\n");
        return status;
    }

    sx_ecmp_id_t sx_group_id = nhg_db_entry->data.data.fine_grain.sx_ecmp_id;
    uint32_t     index = nhgm_db_entry->data.entry.fg.id;

    memset(&edited_nhgm, 0, sizeof(edited_nhgm));

    status = mlnx_translate_sai_next_hop_objects(1,
                                                 &oid,
                                                 &edited_nhgm.next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate_sai_next_hop_objects %lu.\n", oid);
        return status;
    }

    status = nhgm_get_flow_counter(nhgm_db_entry,
                                   &edited_nhgm.next_hop.next_hop_data.counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get flow counter.\n");
        return status;
    }

    edited_nhgm.next_hop_index = index;

    sx_status = sx_api_router_ecmp_update_set(gh_sdk,
                                              SX_ACCESS_CMD_SET,
                                              sx_group_id,
                                              &edited_nhgm,
                                              1);
    if (SAI_ERR(sx_status)) {
        SX_LOG_ERR("Failed to update ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
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
        SX_LOG_NTC("Weight is not supported for FINE_GRAIN ECMP.\n");
        return SAI_STATUS_FAILURE;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry.\n");
        return status;
    }

    for (uint32_t ii = 0; ii < NUMBER_OF_VRF_DATA_SETS; ++ii) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP) {
                status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                           vrf_data,
                                                           false,
                                                           &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data.\n");
                    return status;
                }
            } else {
                status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                            &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data.\n");
                    return status;
                }
            }

            new_sx_next_hop = old_sx_next_hop;
            new_sx_next_hop.next_hop_data.weight = weight;

            status = replace_next_hop_data_in_ecmp_id(vrf_data->sx_ecmp_id,
                                                      old_sx_next_hop,
                                                      new_sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id [0x%X] [ii:%u]\n", vrf_data->sx_ecmp_id, ii);
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
            SX_LOG_ERR("Failed to get sx_flow_counter [ID:%u].\n", counter_idx.idx);
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

    next_hops[nhgm_db_entry->data.entry.fg.id].next_hop_data.counter_id = sx_flow_counter;

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

static sai_status_t mlnx_nhgm_counter_set(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry, _In_ sai_object_id_t counter)
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
        SX_LOG_ERR("Failed to get NHG DB entry.\n");
        return status;
    }

    if (counter != SAI_NULL_OBJECT_ID) {
        mlnx_counter_t *counter_db_entry;
        status = mlnx_counter_oid_to_data(counter, &counter_db_entry, &counter_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get counter DB entry [OID:0x%X].\n", counter);
            return status;
        }

        status = mlnx_get_sx_flow_counter_id_by_idx(counter_idx,
                                                    &sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter [ID:%u].\n", counter_idx.idx);
            return status;
        }
    }

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) {
        return mlnx_nhgm_fg_counter_set(nhgm_db_entry,
                                        nhg_db_entry,
                                        counter_idx);
    }

    for (uint32_t ii = 0; ii < NUMBER_OF_VRF_DATA_SETS; ++ii) {
        vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            if ((nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP) ||
                (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_ENCAP)) {
                status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                           vrf_data,
                                                           false,
                                                           &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data. [ii=%u]\n", ii);
                    return status;
                }
            } else if ((nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE) ||
                       (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_NATIVE)) {
                status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                            &old_sx_next_hop);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get next hop data. [ii=%u]\n", ii);
                    return status;
                }
            } else {
                SX_LOG_ERR("Unexpected NHGM type [%u].", nhgm_db_entry->data.type);
                return SAI_STATUS_FAILURE;
            }

            new_sx_next_hop = old_sx_next_hop;
            new_sx_next_hop.next_hop_data.counter_id = sx_flow_counter;

            status = replace_next_hop_data_in_ecmp_id(vrf_data->sx_ecmp_id,
                                                      old_sx_next_hop,
                                                      new_sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id [0x%X] [ii=%u]\n", vrf_data->sx_ecmp_id, ii);
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
           (attr == SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID) ||
           (attr == SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID));

    mlnx_nhgm_db_entry_t *db_entry;

    sai_db_write_lock();

    status = mlnx_nhgm_oid_to_data(key->key.object_id, &db_entry, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHGM data [OID:0x%X] from DB.\n", key->key.object_id);
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
        status = mlnx_nhgm_counter_set(db_entry, value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set counter.\n");
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID:
        status = mlnx_nghm_priority_set(db_entry, value->u32);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set priority.\n");
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

static sai_status_t mlnx_nhgm_get_next_hop(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry, _Out_ sai_object_id_t     *nh)
{
    sai_status_t status;

    assert(nhgm_db_entry);
    assert(nh);

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) {
        SX_LOG_ERR("Failed to get next hop id - not supported for FINE_GRAIN_ECMP\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    if ((nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE) ||
        (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_NATIVE)) {
        sx_ecmp_id_t sx_ecmp_id;

        status = mlnx_nhgm_get_sx_ecmp(nhgm_db_entry, &sx_ecmp_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_ecmp from NHGM.\n");
            return status;
        }

        status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP,
                                    sx_ecmp_id,
                                    NULL,
                                    nh);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create NH OID.\n");
            return status;
        }
    } else if ((nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP) ||
               (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_ENCAP)) {
        mlnx_shm_rm_array_idx_t nh_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

        status = mlnx_nhgm_get_nh_idx(nhgm_db_entry, &nh_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NH idx from NHGM.\n");
            return status;
        }
        status = mlnx_encap_nexthop_oid_create(nh_idx, nh);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create Encap NH OID.\n");
            return status;
        }
    } else {
        SX_LOG_ERR("Unexpected NHGM type [%u].\n", nhgm_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
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
           (SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID == attr) ||
           (SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID == attr));

    mlnx_nhgm_db_entry_t *nhgm_db_entry;

    sai_db_write_lock();

    status = mlnx_nhgm_oid_to_data(key->key.object_id, &nhgm_db_entry, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHGM data [OID:0x%X] from DB.\n", key->key.object_id);
        goto exit;
    }

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NULL) {
        SX_LOG_ERR("Unexpected NHGM type.\n");
        status = SAI_STATUS_FAILURE;
        goto exit;
    }

    switch (attr) {
    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID:
        status = mlnx_nhg_oid_create(nhgm_db_entry->data.nhg_idx, &value->oid);
        if (SAI_ERR(status)) {
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID:
        status = mlnx_nhgm_get_next_hop(nhgm_db_entry, &value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NH.\n");
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT:
        if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("Failed to get weight - not supported for FINE_GRAIN_ECMP\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = nhgm_db_entry->data.weight;
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_INDEX:
        if (nhgm_db_entry->data.type != MLNX_NHGM_TYPE_FINE_GRAIN) {
            SX_LOG_ERR("Failed to get group member index - supported only for FINE_GRAIN_ECMP\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = nhgm_db_entry->data.entry.fg.id;
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_COUNTER_ID:
        if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_entry->data.flow_counter)) {
            value->oid = SAI_NULL_OBJECT_ID;
            goto exit;
        }
        status = mlnx_counter_oid_create(nhgm_db_entry->data.flow_counter, &value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create flow counter OID [ID:%u].\n",
                       nhgm_db_entry->data.flow_counter.idx);
            goto exit;
        }
        break;

    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID:
        if ((nhgm_db_entry->data.type != MLNX_NHGM_TYPE_ORDERED_NATIVE) &&
            (nhgm_db_entry->data.type != MLNX_NHGM_TYPE_ORDERED_ENCAP)) {
            SX_LOG_ERR("Failed to get SEQUENCE_ID - supported only for ORDERED_ECMP\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto exit;
        }
        value->u32 = nhgm_db_entry->data.entry.ordered.prio;
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

sai_status_t mlnx_get_index_of_priority(_In_ uint32_t   prio,
                                        _In_ uint32_t  *priorities,
                                        _In_ uint32_t   priorities_count,
                                        _Out_ uint32_t *index)
{
    uint32_t ii = 0;

    assert(priorities && index);

    while (ii < priorities_count && priorities[ii] < prio) {
        ii++;
    }

    if ((ii == priorities_count) || (priorities[ii] != prio)) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    *index = ii;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_insert_priority(_In_ uint32_t prio, _Inout_ uint32_t *priorities, _Inout_ uint32_t *priorities_count)
{
    uint32_t ii = 0;
    uint32_t index_for_prio = 0;

    while (ii < *priorities_count && priorities[ii] < prio) {
        ii++;
    }

    index_for_prio = ii;

    ii = *priorities_count;
    while (ii > index_for_prio) {
        priorities[ii] = priorities[ii - 1];
        ii--;
    }

    priorities[index_for_prio] = prio;
    *priorities_count += 1;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_get_nhg_priorities(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                     _In_ uint32_t             nhgm_types_mask,
                                     _Out_ uint32_t           *priorities,
                                     _Out_ uint32_t           *priorities_count)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nhgm_db_idx;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;

    if (nhg_db_entry->data.type != MLNX_NHG_TYPE_ORDERED) {
        SX_LOG_ERR("Getting member priorities is only supported for NHG type ORDERED.\n");
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_DBG("Include priorities for NHGM types:\n");
    if (nhgm_types_mask & MLNX_NHGM_TYPE_ORDERED_NATIVE) {
        SX_LOG_DBG("\tORDERED_NATIVE\n");
    }
    if (nhgm_types_mask & MLNX_NHGM_TYPE_ORDERED_ENCAP) {
        SX_LOG_DBG("\tORDERED_ENCAP\n");
    }

    uint32_t priorities_size = *priorities_count;

    *priorities_count = 0;
    nhgm_db_idx = nhg_db_entry->data.members;

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_idx)) {
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_db_idx, &nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM DB data [ID:%u].\n", nhgm_db_idx.idx);
            return status;
        }

        if ((nhgm_types_mask & nhgm_db_entry->data.type) && (nhgm_db_entry->data.state != MLNX_NHGM_STATE_TO_REMOVE)) {
            if (*priorities_count >= priorities_size) {
                return SAI_STATUS_BUFFER_OVERFLOW;
            }
            status = mlnx_insert_priority(nhgm_db_entry->data.entry.ordered.prio,
                                          priorities,
                                          priorities_count);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to insert priority [prio=%u, ID:%u]",
                           nhgm_db_entry->data.entry.ordered.prio,
                           nhgm_db_idx.idx);
                return status;
            }
        }

        nhgm_db_idx = nhgm_db_entry->data.next_member_idx;
    }

    SX_LOG_DBG("Priorities of the NHG:\n");
    for (uint32_t ii = 0; ii < *priorities_count; ii++) {
        SX_LOG_DBG("\tpriorities[%u] = %u\n", ii, priorities[ii]);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_insert_nh_data(_In_ sx_next_hop_t   nh_data,
                                 _In_ uint32_t        index,
                                 _Out_ sx_next_hop_t *ecmp_next_hops,
                                 _In_ uint32_t        next_hop_count)
{
    uint32_t ii = next_hop_count - 1;

    assert(ecmp_next_hops && index < next_hop_count);

    while (ii > index) {
        ecmp_next_hops[ii] = ecmp_next_hops[ii - 1];
        ii--;
    }

    ecmp_next_hops[index] = nh_data;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t apply_next_hop_data_to_ecmp_id(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                                   _In_ sx_ecmp_id_t         group,
                                                   _In_ sx_next_hop_t        nh_data,
                                                   _In_ int64_t              prio)
{
    sai_status_t  status;
    sx_status_t   sx_status;
    uint32_t      next_hop_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t ecmp_next_hops[FG_ECMP_MAX_PATHS];
    uint32_t      index_to_put_new_nh_data = -1;

    sx_status = sx_api_router_ecmp_get(gh_sdk,
                                       group,
                                       ecmp_next_hops,
                                       &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (prio == -1) {
        index_to_put_new_nh_data = next_hop_count;
    } else {
        uint32_t priorities[FG_ECMP_MAX_PATHS] = {0};
        uint32_t priorities_count = FG_ECMP_MAX_PATHS;
        uint32_t nhgms_mask = MLNX_NHGM_TYPE_ORDERED_NATIVE;
        if (group != nhg_db_entry->data.data.encap.vrf_data[MLNX_REGULAR_ECMP_INDEX].sx_ecmp_id) {
            nhgms_mask |= MLNX_NHGM_TYPE_ORDERED_ENCAP;
        }

        status = mlnx_get_nhg_priorities(nhg_db_entry,
                                         nhgms_mask,
                                         priorities,
                                         &priorities_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get a list of NHG priorities\n");
            return status;
        }

        if (priorities_count >= FG_ECMP_MAX_PATHS) {
            SX_LOG_ERR("No more space left for members.\n");
            return SAI_STATUS_TABLE_FULL;
        }

        if (priorities_count != next_hop_count + 1) {
            SX_LOG_ERR("Unexpected number of priorities [%u], expected [%u].\n", priorities_count, next_hop_count + 1);
            return SAI_STATUS_FAILURE;
        }

        status = mlnx_get_index_of_priority(prio,
                                            priorities,
                                            priorities_count,
                                            &index_to_put_new_nh_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to find an index of the new priority [%u]\n", prio);
            return status;
        }
    }

    next_hop_count++;

    status = mlnx_insert_nh_data(nh_data,
                                 index_to_put_new_nh_data,
                                 ecmp_next_hops,
                                 next_hop_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to insert nh_data [index=%u]\n", index_to_put_new_nh_data);
        return status;
    }

    SX_LOG_DBG("Insert NH data with prio [%u] at index [%u] for sx_ecmp_id [0x%X].\n",
               prio,
               index_to_put_new_nh_data,
               group);

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_SET,
                                       &group,
                                       ecmp_next_hops,
                                       &next_hop_count);
    if (SAI_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t get_next_hop_data_from_encap_nhgm(_In_ mlnx_nhgm_db_entry_t      *nhgm_db_entry,
                                                      _In_ mlnx_nhg_encap_vrf_data_t *vrf_data,
                                                      _In_ bool                       create,
                                                      _Out_ sx_next_hop_t            *sx_next_hop)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nh_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

    status = mlnx_nhgm_get_nh_idx(nhgm_db_entry, &nh_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NH idx from NHGM.\n");
        return status;
    }

    status = mlnx_encap_nh_data_get(nh_idx,
                                    vrf_data->associated_vrf,
                                    create ? vrf_data->refcount : 0,
                                    sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop data [NH_idx=%u, VRF=0x%lX, create=%d, refcount=%d]\n",
                   nhgm_db_entry->data.entry.encap.nh_idx.idx,
                   vrf_data->associated_vrf,
                   create,
                   create ? vrf_data->refcount : 0);
        return status;
    }

    sx_next_hop->next_hop_data.weight = nhgm_get_weight(nhgm_db_entry);
    status = nhgm_get_flow_counter(nhgm_db_entry,
                                   &sx_next_hop->next_hop_data.counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get sx_flow_counter.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t get_next_hop_data_from_native_nhgm(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                                       _Out_ sx_next_hop_t       *sx_next_hop)
{
    sai_status_t status;
    sx_ecmp_id_t sx_ecmp_id;

    status = mlnx_nhgm_get_sx_ecmp(nhgm_db_entry, &sx_ecmp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get sx_ecmp from NHGM.\n");
        return status;
    }

    status = mlnx_sdk_nhop_by_ecmp_id_get(sx_ecmp_id,
                                          sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop ecmp.\n");
        return status;
    }

    sx_next_hop->next_hop_data.weight = nhgm_get_weight(nhgm_db_entry);
    status = nhgm_get_flow_counter(nhgm_db_entry,
                                   &sx_next_hop->next_hop_data.counter_id);
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
            SX_LOG_ERR("Failed to get next NHGM [ID:%u].\n", nhgm_db_entry->data.next_member_idx.idx);
            return status;
        }
        next->data.prev_member_idx = nhgm_db_entry->data.prev_member_idx;
    }

    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_entry->data.prev_member_idx)) {
        mlnx_nhgm_db_entry_t *prev;
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_db_entry->data.prev_member_idx, &prev);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get previous NHGM [ID:%u].\n", nhgm_db_entry->data.prev_member_idx.idx);
            return status;
        }
        prev->data.next_member_idx = nhgm_db_entry->data.next_member_idx;
    }

    memset(&nhgm_db_entry->data.next_member_idx, 0, sizeof(nhgm_db_entry->data.next_member_idx));
    memset(&nhgm_db_entry->data.prev_member_idx, 0, sizeof(nhgm_db_entry->data.prev_member_idx));
    nhg_db_entry->data.members_count--;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_native_apply(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    sai_status_t         status;
    sx_next_hop_t        sx_next_hop;
    int64_t              prio = -1;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    assert(nhgm_db_entry &&
           (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE ||
            nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_NATIVE));

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [ID:%u] DB entry.\n", nhgm_db_entry->data.nhg_idx.idx);
        return status;
    }

    status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                &sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop data.\n");
        return status;
    }

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_NATIVE) {
        prio = nhgm_db_entry->data.entry.ordered.prio;
    }

    for (uint32_t ii = 0; ii < NUMBER_OF_VRF_DATA_SETS; ii++) {
        sx_ecmp_id_t sx_ecmp_id = nhg_db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id;
        if (sx_ecmp_id != 0) {
            if (prio == -1) {
                status = mlnx_check_and_set_ar_ecmp(sx_ecmp_id, &sx_next_hop, 1);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to check ar for sx_ecmp_id. [index = %d]\n", ii);
                    return status;
                }
            }

            status = apply_next_hop_data_to_ecmp_id(nhg_db_entry,
                                                    sx_ecmp_id,
                                                    sx_next_hop,
                                                    prio);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id. [ii=%d, prio=%u]\n",
                           ii, prio);
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_encap_apply(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    sai_status_t         status;
    sx_next_hop_t        sx_next_hop;
    mlnx_nhg_db_entry_t *nhg_db_entry;
    int64_t              prio = -1;

    assert(nhgm_db_entry &&
           (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP ||
            nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_ENCAP));

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [ID:%u] DB entry.\n", nhgm_db_entry->data.nhg_idx.idx);
        return status;
    }

    if (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_ENCAP) {
        prio = nhgm_db_entry->data.entry.ordered.prio;
    }

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
        mlnx_nhg_encap_vrf_data_t *vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->refcount > 0) {
            status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                       vrf_data,
                                                       true,
                                                       &sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get next hop data. [ii:%u]\n", ii);
                return status;
            }

            status = apply_next_hop_data_to_ecmp_id(nhg_db_entry,
                                                    vrf_data->sx_ecmp_id,
                                                    sx_next_hop,
                                                    prio);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id. [ii=%d, prio=%u]\n", ii, prio);
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fg_group_init(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry,
                                       _Out_ uint32_t            *next_hop_count,
                                       _Out_ sx_next_hop_t       *next_hops)
{
    sai_status_t         status;
    mlnx_nhg_db_entry_t *nhg_db_entry;
    sx_flow_counter_id_t sx_flow_counter;
    sx_next_hop_weight_t sx_weight;

    assert(nhgm_db_entry && nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN);

    status = get_nhg_from_nhgm(nhgm_db_entry,
                               &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [ID:%u] DB entry.\n", nhgm_db_entry->data.nhg_idx.idx);
        return status;
    }

    sx_weight = nhgm_get_weight(nhgm_db_entry);
    status = nhgm_get_flow_counter(nhgm_db_entry,
                                   &sx_flow_counter);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHGM counter.\n");
        return status;
    }

    for (uint32_t jj = 0; jj < nhg_db_entry->data.data.fine_grain.real_size; ++jj) {
        status = mlnx_translate_sai_next_hop_objects(1,
                                                     &nhgm_db_entry->data.entry.fg.nh,
                                                     &next_hops[jj]);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate NH.\n");
            return status;
        }
        next_hops[jj].next_hop_data.counter_id = sx_flow_counter;
        next_hops[jj].next_hop_data.weight = sx_weight;
    }

    *next_hop_count = nhg_db_entry->data.data.fine_grain.real_size;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_fine_grain_apply(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    sai_status_t         status;
    sx_status_t          sx_status;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    assert(nhgm_db_entry && nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN);

    status = get_nhg_from_nhgm(nhgm_db_entry,
                               &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [ID:%u] DB entry.\n", nhgm_db_entry->data.nhg_idx.idx);
        return status;
    }

    if (SX_ROUTER_ECMP_ID_INVALID == nhg_db_entry->data.data.fine_grain.sx_ecmp_id) {
        sx_next_hop_t next_hops[FG_ECMP_MAX_PATHS];
        uint32_t      next_hop_count = 0;

        status = mlnx_fg_group_init(nhgm_db_entry,
                                    &next_hop_count,
                                    next_hops);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to init FG group.\n");
            return status;
        }

        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_CREATE,
                                           &nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                           next_hops,
                                           &next_hop_count);
        if (SAI_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    } else {
        sx_ecmp_update_entry_t edited_nhgm = {0};
        sx_flow_counter_id_t   sx_flow_counter;

        status = nhgm_get_flow_counter(nhgm_db_entry,
                                       &sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter.\n");
            return status;
        }

        status = mlnx_translate_sai_next_hop_objects(1,
                                                     &nhgm_db_entry->data.entry.fg.nh,
                                                     &edited_nhgm.next_hop);
        if (SAI_ERR(status)) {
            return status;
        }
        edited_nhgm.next_hop_index = nhgm_db_entry->data.entry.fg.id;
        edited_nhgm.next_hop.next_hop_data.weight = nhgm_get_weight(nhgm_db_entry);
        edited_nhgm.next_hop.next_hop_data.counter_id = sx_flow_counter;

        sx_status = sx_api_router_ecmp_update_set(gh_sdk,
                                                  SX_ACCESS_CMD_SET,
                                                  nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                                  &edited_nhgm,
                                                  1);
        if (SAI_ERR(sx_status)) {
            SX_LOG_ERR("Failed to update set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_fine_grain_bulk_apply(mlnx_nhg_db_entry_t *nhg_db_entry)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    mlnx_nhgm_db_entry_t *nhgm_db_entry;
    sx_next_hop_t         next_hops[FG_ECMP_MAX_PATHS];
    uint32_t              next_hop_count = FG_ECMP_MAX_PATHS;

    assert(nhg_db_entry && nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN);
    assert(nhg_db_entry->data.members_count > 0);

    status = mlnx_nhgm_db_entry_idx_to_data(nhg_db_entry->data.members, &nhgm_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get the first member [ID:%u].\n", nhg_db_entry->data.members.idx);
        return status;
    }

    if (SX_ROUTER_ECMP_ID_INVALID == nhg_db_entry->data.data.fine_grain.sx_ecmp_id) {
        status = mlnx_fg_group_init(nhgm_db_entry,
                                    &next_hop_count,
                                    next_hops);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to init FG group.\n");
            return status;
        }
    } else {
        sx_status = sx_api_router_ecmp_get(gh_sdk,
                                           nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                           next_hops,
                                           &next_hop_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    while (true) {
        if (nhgm_db_entry->data.state == MLNX_NHGM_STATE_TO_REMOVE) {
            SX_LOG_DBG("Nothing to do for FG ECMP.\n");
            if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_entry->data.next_member_idx)) {
                break;
            }
            status = mlnx_nhgm_db_entry_idx_to_data(nhgm_db_entry->data.next_member_idx,
                                                    &nhgm_db_entry);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get the next member.\n");
                return status;
            }
            continue;
        }

        sx_flow_counter_id_t sx_flow_counter;
        sx_next_hop_weight_t sx_weight = nhgm_get_weight(nhgm_db_entry);
        status = nhgm_get_flow_counter(nhgm_db_entry,
                                       &sx_flow_counter);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get sx_flow_counter.\n");
            return status;
        }

        status = mlnx_translate_sai_next_hop_objects(1,
                                                     &nhgm_db_entry->data.entry.fg.nh,
                                                     &next_hops[nhgm_db_entry->data.entry.fg.id]);
        if (SAI_ERR(status)) {
            return status;
        }
        next_hops[nhgm_db_entry->data.entry.fg.id].next_hop_data.counter_id = sx_flow_counter;
        next_hops[nhgm_db_entry->data.entry.fg.id].next_hop_data.weight = sx_weight;

        if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_db_entry->data.next_member_idx)) {
            break;
        }
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_db_entry->data.next_member_idx,
                                                &nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get the next member [ID:%u].\n", nhgm_db_entry->data.next_member_idx.idx);
            return status;
        }
    }

    sx_access_cmd_t cmd = nhg_db_entry->data.data.fine_grain.sx_ecmp_id == SX_ROUTER_ECMP_ID_INVALID ?
                          SX_ACCESS_CMD_CREATE : SX_ACCESS_CMD_SET;

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       cmd,
                                       &nhg_db_entry->data.data.fine_grain.sx_ecmp_id,
                                       next_hops,
                                       &next_hop_count);
    if (SAI_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_apply(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    sai_status_t status;

    assert(nhgm_db_entry);

    switch (nhgm_db_entry->data.type) {
    case MLNX_NHGM_TYPE_NATIVE:
    case MLNX_NHGM_TYPE_ORDERED_NATIVE:
        status = mlnx_nhgm_type_native_apply(nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply NHGM type NATIVE/ORDERED_NATIVE.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_ENCAP:
    case MLNX_NHGM_TYPE_ORDERED_ENCAP:
        status = mlnx_nhgm_type_encap_apply(nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply NHGM type ENCAP/ORDERED_ENCAP.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_FINE_GRAIN:
        status = mlnx_nhgm_type_fine_grain_apply(nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to apply NHGM type FINE_GRAIN.\n");
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected NHGM type [%u]\n", nhgm_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    nhgm_db_entry->data.state = MLNX_NHGM_STATE_INITIALIZED;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_sx_ecmp_get(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                         _In_ sai_object_id_t      vrf,
                                         _Out_ sx_ecmp_id_t       *sx_ecmp_id)
{
    assert(sx_ecmp_id && nhg_db_entry);

    if ((nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) ||
        (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED)) {
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
    } else {
        SX_LOG_ERR("Unexpected NHG type [%u]\n", nhg_db_entry->data.type);
        return SAI_STATUS_FAILURE;
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

static sai_status_t mlnx_ecmp_to_nhg_map_entry_add(_In_ sx_ecmp_id_t key, _In_ mlnx_shm_rm_array_idx_t value)
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

static sai_status_t mlnx_ecmp_to_nhg_map_entry_del(_In_ sx_ecmp_id_t key)
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
            SX_LOG_ERR("Failed to get ECMP-NHG map entry [ID:%u]\n", idx.idx);
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
            SX_LOG_ERR("Failed to get ECMP-NHG map entry [ID:%u]\n", idx.idx);
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

    switch (nhgm_db_entry->data.type) {
    case MLNX_NHGM_TYPE_ENCAP:
    case MLNX_NHGM_TYPE_ORDERED_ENCAP:
        status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                   vrf_data,
                                                   0,
                                                   next_hop);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM ENCAP/ORDERED_ENCAP nh data.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_NATIVE:
    case MLNX_NHGM_TYPE_ORDERED_NATIVE:
        status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                    next_hop);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM NATIVE/ORDERED_NATIVE nh data.\n");
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected NHGM type.\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_nh_data_get(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                         _In_ sai_object_id_t      vrf,
                                         _Out_ sx_next_hop_t      *next_hops,
                                         _Out_ uint32_t           *next_hops_count,
                                         _In_ bool                 native_only)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nhgm_idx = nhg_db_entry->data.members;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;
    /* coverity[stack_use_local_overflow] */
    uint32_t priorities[FG_ECMP_MAX_PATHS];
    uint32_t priorities_count = 0;

    *next_hops_count = 0;

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_idx)) {
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_idx, &nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM DB data [ID:%u].\n", nhgm_idx.idx);
            return status;
        }

        SX_LOG_DBG("Checking NHGM [ID:%u] with type [%u] and state [%u]\n", nhgm_idx.idx, nhgm_db_entry->data.type,
                   nhgm_db_entry->data.state);

        if (native_only &&
            ((nhgm_db_entry->data.type != MLNX_NHGM_TYPE_NATIVE) &&
             (nhgm_db_entry->data.type != MLNX_NHGM_TYPE_ORDERED_NATIVE))) {
            nhgm_idx = nhgm_db_entry->data.next_member_idx;
            continue;
        }

        if (nhgm_db_entry->data.state != MLNX_NHGM_STATE_TO_REMOVE) {
            sx_next_hop_t nh_data;

            status = mlnx_nhgm_nh_data_get(nhgm_db_entry,
                                           nhg_db_entry,
                                           vrf,
                                           &nh_data);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get NHGM nh data [NHGM_idx=%u, VRF=0x%lX]\n",
                           nhgm_idx.idx,
                           vrf);
                return status;
            }

            SX_LOG_DBG("Read next_hop data from NHGM [ID:%u] for VRF [0x%X]\n", nhgm_idx.idx, vrf);

            if (nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) {
                next_hops[*next_hops_count] = nh_data;
                *next_hops_count += 1;
            } else if (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED) {
                uint32_t prio = nhgm_db_entry->data.entry.ordered.prio;
                uint32_t index_of_prio = -1;

                status = mlnx_insert_priority(prio,
                                              priorities,
                                              &priorities_count);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to insert priority [prio=%u, ID:%u]",
                               nhgm_db_entry->data.entry.ordered.prio,
                               nhgm_idx.idx);
                    return status;
                }

                if (priorities_count >= FG_ECMP_MAX_PATHS) {
                    return SAI_STATUS_BUFFER_OVERFLOW;
                }

                status = mlnx_get_index_of_priority(prio,
                                                    priorities,
                                                    priorities_count,
                                                    &index_of_prio);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Priority [%u] is not found.\n", prio);
                    return status;
                }

                status = mlnx_insert_nh_data(nh_data,
                                             index_of_prio,
                                             next_hops,
                                             priorities_count);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to insert nh_data [index=%u]\n", index_of_prio);
                    return status;
                }

                SX_LOG_DBG("Insert NH data of NHGM [ID:%u] with prio [%u] at index [%u] for VRF [0x%X].\n",
                           nhgm_idx.idx,
                           prio,
                           index_of_prio,
                           vrf);
            } else {
                SX_LOG_ERR("Unexpected NHG type [%u]\n", nhg_db_entry->data.type);
                return SAI_STATUS_FAILURE;
            }
        }

        nhgm_idx = nhgm_db_entry->data.next_member_idx;
    }

    if (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED) {
        *next_hops_count = priorities_count;
    }

    SX_LOG_DBG("Got array of [%u] nh_data for VRF [0x%X] [NHG members:%u]\n",
               *next_hops_count,
               vrf,
               nhg_db_entry->data.members_count);

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
    uint32_t                   ar_next_hop_cnt = 0;
    sx_next_hop_t              empty_next_hops[1] = {0};
    uint32_t                   zero_next_hop_cnt = 0;

    assert(nhg_db_entry);

    SX_LOG_DBG("Creating NHG [ID:%u] sx_ecmp_id for VRF [0x%X]\n",
               nhg_idx, vrf);

    status = mlnx_nhg_nh_data_get(nhg_db_entry,
                                  vrf,
                                  next_hops,
                                  &next_hops_count,
                                  false);
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

    for (uint32_t ii = 0; ii < next_hops_count; ii++) {
        if (mlnx_is_ar_nexthop(&next_hops[ii])) {
            ar_next_hop_cnt++;
        }
    }

    if (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED) {
        uint32_t dummy_number_of_nh = 0;

        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_CREATE,
                                           &vrf_data->sx_ecmp_id,
                                           NULL,
                                           &dummy_number_of_nh);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_ecmp_attributes_t sx_ecmp_attr;
        sx_ecmp_attr.ecmp_type = SX_ECMP_TYPE_PRESERVED_ORDER_E;
        sx_status = sx_api_router_ecmp_attributes_set(gh_sdk,
                                                      vrf_data->sx_ecmp_id,
                                                      &sx_ecmp_attr);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp attribute - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_SET,
                                           &vrf_data->sx_ecmp_id,
                                           next_hops,
                                           &next_hops_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    } else if ((0 != ar_next_hop_cnt) && (ar_next_hop_cnt == next_hops_count)) {
        /* AR ecmp cannot be created together with next hops */
        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_CREATE,
                                           &vrf_data->sx_ecmp_id,
                                           empty_next_hops,
                                           &zero_next_hop_cnt);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        status = mlnx_set_ar_ecmp_attr(vrf_data->sx_ecmp_id, g_sai_db_ptr->ar_db.ar_ecmp_size);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set router ecmp to adaptive routing.\n");
            return status;
        }

        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_SET,
                                           &vrf_data->sx_ecmp_id,
                                           next_hops,
                                           &next_hops_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    } else {
        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_CREATE,
                                           &vrf_data->sx_ecmp_id,
                                           next_hops,
                                           &next_hops_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    SX_LOG_DBG("Created sx_ecmp_id [0x%X] with [%u] next_hops for VRF [0x%X].\n",
               vrf_data->sx_ecmp_id, next_hops_count, vrf);

    status = mlnx_ecmp_to_nhg_map_entry_add(vrf_data->sx_ecmp_id,
                                            nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add ECMP-NHG map entry [0x%X:%u]\n", vrf_data->sx_ecmp_id, nhg_idx.idx);
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
        SX_LOG_ERR("Failed to delete ECMP-NHG map entry [0x%X]\n", sx_ecmp_id);
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
                                             _In_ int32_t               diff,
                                             _In_ bool                  bulk_operation)
{
    sai_status_t status;

    assert(nhgm_db_entry);

    if ((nhgm_db_entry->data.type == MLNX_NHGM_TYPE_FINE_GRAIN) ||
        (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE) ||
        (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_NATIVE)) {
        return SAI_STATUS_SUCCESS;
    }

    if (bulk_operation) {
        if ((diff < 0) && (nhgm_db_entry->data.state != MLNX_NHGM_STATE_TO_REMOVE)) {
            return SAI_STATUS_SUCCESS;
        } else if ((diff > 0) && (nhgm_db_entry->data.state != MLNX_NHGM_STATE_ALLOCATED)) {
            return SAI_STATUS_SUCCESS;
        }
    }

    mlnx_shm_rm_array_idx_t nh_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

    status = mlnx_nhgm_get_nh_idx(nhgm_db_entry, &nh_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NH idx from NHGM.\n");
        return status;
    }

    status = mlnx_encap_nexthop_counter_update(nh_idx,
                                               vrf,
                                               diff,
                                               NH_COUNTER_TYPE_NHGM);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update NH counter for ENCAP/ORDERED_ENCAP NHGM\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_update_nhgm_counters(_In_ mlnx_nhg_db_entry_t *nhg_db_entry,
                                                  _In_ sai_object_id_t      vrf,
                                                  _In_ int32_t              diff,
                                                  _In_ bool                 bulk_operation)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nhgm_idx = nhg_db_entry->data.members;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_idx)) {
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_idx, &nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM DB data [ID:%u].\n", nhgm_idx.idx);
            return status;
        }

        if (bulk_operation && (nhgm_db_entry->data.state == MLNX_NHGM_STATE_TO_REMOVE)) {
            diff = -diff;
        }

        status = mlnx_nhgm_counter_update(nhgm_db_entry,
                                          vrf,
                                          diff,
                                          bulk_operation);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update NHGM counter [ID=%u, VRF=0x%lX, diff=%d, is_bulk=%d].\n",
                       nhgm_idx.idx,
                       vrf,
                       diff,
                       bulk_operation);
            return status;
        }

        nhgm_idx = nhgm_db_entry->data.next_member_idx;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nhg_counter_update(_In_ mlnx_shm_rm_array_idx_t nhg_idx,
                                     _In_ sai_object_id_t         vrf,
                                     _In_ int32_t                 diff,
                                     _In_ bool                    bulk_operation)
{
    sai_status_t               status;
    mlnx_nhg_encap_vrf_data_t *vrf_data = NULL;
    mlnx_nhg_db_entry_t       *nhg_db_entry;

    status = mlnx_nhg_db_entry_idx_to_data(nhg_idx,
                                           &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry [ID:%u]\n", nhg_idx.idx);
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
        SX_LOG_ERR("Unexpected negative refcount.\n");
        return SAI_STATUS_FAILURE;
    }

    if (diff < 0) {
        if (vrf_data->refcount + diff == 0) {
            status = mlnx_nhg_remove_ecmp(nhg_db_entry,
                                          vrf);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to remove NHG ECMP.\n");
                return status;
            }

            vrf_data->associated_vrf = SAI_NULL_OBJECT_ID;
            vrf_data->sx_ecmp_id = 0;
        }
    }

    status = mlnx_nhg_update_nhgm_counters(nhg_db_entry,
                                           vrf,
                                           diff,
                                           bulk_operation);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update NHGM counters.\n");
        return status;
    }

    if (diff > 0) {
        if (vrf_data->refcount == 0) {
            status = mlnx_nhg_create_ecmp(nhg_idx,
                                          nhg_db_entry,
                                          vrf);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to create NHG [ID:%u] ECMP.\n", nhg_idx.idx);
                return status;
            }
        }
    }

    vrf_data->refcount += diff;

    return SAI_STATUS_SUCCESS;
}

/* Must be guarded with a lock */
sai_status_t mlnx_nhg_get_regular_ecmp(_In_ sai_object_id_t nhg, _Out_ sx_ecmp_id_t  *sx_ecmp_id)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    mlnx_nhg_db_entry_t    *nhg_db_entry;
    mlnx_shm_rm_array_idx_t nhg_idx;

    status = mlnx_nhg_oid_to_data(nhg,
                                  &nhg_db_entry,
                                  &nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [OID:0x%X] data from DB.\n", nhg);
        goto exit;
    }

    if ((nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) ||
        (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED)) {
        *sx_ecmp_id = nhg_db_entry->data.data.encap.vrf_data[MLNX_REGULAR_ECMP_INDEX].sx_ecmp_id;
    } else if (nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) {
        *sx_ecmp_id = nhg_db_entry->data.data.fine_grain.sx_ecmp_id;
    } else {
        *sx_ecmp_id = 0;
        status = SAI_STATUS_FAILURE;
        SX_LOG_ERR("Unexpected NHG type [%u]\n", nhg_db_entry->data.type);
        goto exit;
    }

exit:
    return status;
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
        SX_LOG_ERR("Failed to get NHG [OID:0x%X] data from DB.\n", nhg);
        goto exit;
    }

    SX_LOG_DBG("Getting NHG [ID:%u] sx_ecmp_id for VRF [0x%X] [diff:%d]\n",
               nhg_idx.idx, vrf, diff);

    if (diff > 0) {
        status = mlnx_nhg_counter_update(nhg_idx,
                                         vrf,
                                         diff,
                                         false);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to increment NHG [ID:%u] counter [diff=%d, vrf=0x%X].\n", nhg_idx.idx, diff, vrf);
            goto exit;
        }
    }

    status = mlnx_nhg_sx_ecmp_get(nhg_db_entry,
                                  vrf,
                                  sx_ecmp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get sx_ecmp_id.\n");
        goto exit;
    }


    if (diff < 0) {
        status = mlnx_nhg_counter_update(nhg_idx,
                                         vrf,
                                         diff,
                                         false);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrement NHG [ID:%u] counter [diff=%d, vrf=0x%X].\n", nhg_idx.idx, diff, vrf);
            goto exit;
        }
    }

exit:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_clean_up_nhgm_on_create_failed(mlnx_nhgm_db_entry_t   *nhgm_db_entry,
                                                        mlnx_shm_rm_array_idx_t nhgm_idx)
{
    sai_status_t         status = SAI_STATUS_SUCCESS;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    if (NULL == nhgm_db_entry) {
        goto exit;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry.\n");
        goto exit;
    }

    status = unlink_nhgm_from_nhg(nhgm_idx, nhgm_db_entry, nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unlink NHGM from NHG.\n");
        goto exit;
    }

exit:
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
        status = check_attribs_on_create(attr_count,
                                         attr_list,
                                         SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                                         next_hop_group_member_id);
        if (SAI_ERR(status)) {
            return status;
        }

        *next_hop_group_member_id = SAI_NULL_OBJECT_ID;
        MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER);
    }

    mlnx_nhgm_db_entry_t   *nhgm_db_entry = NULL;
    mlnx_shm_rm_array_idx_t nhgm_idx;

    sai_db_write_lock();
    /* HANDLE ATTRIBUTES */
    {
        status = mlnx_nhgm_parse_attrs(&nhgm_db_entry,
                                       &nhgm_idx,
                                       attr_list,
                                       attr_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to store NHGM attributes.\n");
            goto exit;
        }


        status = mlnx_nhgm_apply(nhgm_db_entry);
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

        MLNX_LOG_OID_CREATED(*next_hop_group_member_id);
    }

exit:
    if (SAI_ERR(status)) {
        mlnx_clean_up_nhgm_on_create_failed(nhgm_db_entry, nhgm_idx);
    }
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t replace_next_hop_data_in_ecmp_id(_In_ sx_ecmp_id_t  group,
                                                     _In_ sx_next_hop_t old_nh_data,
                                                     _In_ sx_next_hop_t new_nh_data)
{
    sx_status_t  sx_status;
    sai_status_t status;
    uint32_t     next_hop_count = FG_ECMP_MAX_PATHS;
    /* coverity[stack_use_overflow] */
    /* coverity[stack_use_local_overflow] */
    sx_next_hop_t ecmp_next_hops[FG_ECMP_MAX_PATHS];
    uint32_t      ii = 0;

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

static sai_status_t remove_next_hop_data_from_ecmp_id(_In_ sx_ecmp_id_t group, _In_ sx_next_hop_t nh_data)
{
    sx_status_t   sx_status;
    sai_status_t  status;
    uint32_t      next_hop_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t ecmp_next_hops[FG_ECMP_MAX_PATHS];
    uint32_t      ii = 0;

    sx_status = sx_api_router_ecmp_get(gh_sdk, group, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_sdk_nhop_find_in_list(ecmp_next_hops, next_hop_count, &nh_data, &ii);
    if (SAI_ERR(status)) {
        return status;
    }

    for (uint32_t jj = ii; jj < next_hop_count - 1; jj++) {
        ecmp_next_hops[jj] = ecmp_next_hops[jj + 1];
    }
    next_hop_count--;

    sx_status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &group, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_native_remove(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    sai_status_t         status;
    mlnx_nhg_db_entry_t *nhg_db_entry;
    sx_next_hop_t        sx_next_hop;

    assert(nhgm_db_entry &&
           (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_NATIVE ||
            nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_NATIVE));

    status = get_next_hop_data_from_native_nhgm(nhgm_db_entry,
                                                &sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get next hop data.\n");
        return status;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [ID:%u] DB entry.\n", nhgm_db_entry->data.nhg_idx.idx);
        return status;
    }

    for (uint32_t ii = 0; ii < NUMBER_OF_VRF_DATA_SETS; ii++) {
        sx_ecmp_id_t sx_ecmp_id = nhg_db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id;
        if (sx_ecmp_id != 0) {
            status = remove_next_hop_data_from_ecmp_id(sx_ecmp_id,
                                                       sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to remove nexthop_data from sx_ecmp_id. [ii=%d]\n", ii);
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_encap_remove(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    sai_status_t         status;
    mlnx_nhg_db_entry_t *nhg_db_entry;

    assert(nhgm_db_entry &&
           (nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ENCAP ||
            nhgm_db_entry->data.type == MLNX_NHGM_TYPE_ORDERED_ENCAP));

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [ID:%u] DB entry.\n", nhgm_db_entry->data.nhg_idx.idx);
        return status;
    }

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
        mlnx_nhg_encap_vrf_data_t *vrf_data = &nhg_db_entry->data.data.encap.vrf_data[ii];
        if (vrf_data->sx_ecmp_id != 0) {
            sx_next_hop_t sx_next_hop;
            status = get_next_hop_data_from_encap_nhgm(nhgm_db_entry,
                                                       vrf_data,
                                                       false,
                                                       &sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get next hop data [ii=%u]\n", ii);
                return status;
            }

            status = remove_next_hop_data_from_ecmp_id(vrf_data->sx_ecmp_id,
                                                       sx_next_hop);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add nexthop_data to sx_ecmp_id [ii=%u]\n", ii);
                return status;
            }

            status = mlnx_nhgm_counter_update(nhgm_db_entry,
                                              vrf_data->associated_vrf,
                                              -vrf_data->refcount,
                                              false);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to decrement NHGM counter.\n");
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_type_fine_grain_remove(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    SX_LOG_DBG("Nothing to do for FG ECMP\n");
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgm_remove(_Inout_ mlnx_nhgm_db_entry_t *nhgm_db_entry)
{
    sai_status_t status;

    assert(nhgm_db_entry);

    switch (nhgm_db_entry->data.type) {
    case MLNX_NHGM_TYPE_NATIVE:
    case MLNX_NHGM_TYPE_ORDERED_NATIVE:
        status = mlnx_nhgm_type_native_remove(nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHGM type NATIVE/ORDERED_NATIVE.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_ENCAP:
    case MLNX_NHGM_TYPE_ORDERED_ENCAP:
        status = mlnx_nhgm_type_encap_remove(nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHGM type ENCAP/ORDERED_ENCAP.\n");
            return status;
        }
        break;

    case MLNX_NHGM_TYPE_FINE_GRAIN:
        status = mlnx_nhgm_type_fine_grain_remove(nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove NHGM type FINE_GRAIN.\n");
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected NHGM type [%u]\n", nhgm_db_entry->data.type);
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

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(next_hop_group_member_id);

    mlnx_nhgm_db_entry_t   *nhgm_db_entry;
    mlnx_nhg_db_entry_t    *nhg_db_entry;
    mlnx_shm_rm_array_idx_t nhgm_idx;

    sai_db_write_lock();

    status = mlnx_nhgm_oid_to_data(next_hop_group_member_id, &nhgm_db_entry, &nhgm_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHGM [OID:0x%X] data from DB.\n", next_hop_group_member_id);
        goto exit;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry [ID:%u].\n", nhgm_idx.idx);
        goto exit;
    }

    status = unlink_nhgm_from_nhg(nhgm_idx, nhgm_db_entry, nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unlink NHGM [ID:%u] from NHG.\n", nhgm_idx.idx);
        goto exit;
    }

    status = mlnx_nhgm_remove(nhgm_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove NHGM [ID:%u].\n", nhgm_idx.idx);
        goto exit;
    }

    status = mlnx_nhgm_db_entry_free(nhgm_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to free NHGM DB entry [ID:%u].\n", nhgm_idx.idx);
        goto exit;
    }

exit:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
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

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, attr);
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

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, attr_count, attr_list);
}

sai_status_t mlnx_remove_next_hop_group_members(_In_ uint32_t                 object_count,
                                                _In_ const sai_object_id_t   *object_id,
                                                _In_ sai_bulk_op_error_mode_t mode,
                                                _Out_ sai_status_t           *object_statuses);

static sai_status_t mlnx_nhgm_parse_attrs(_Out_ mlnx_nhgm_db_entry_t   **nhgm_db_entry,
                                          _Out_ mlnx_shm_rm_array_idx_t *nhgm_idx,
                                          _In_ const sai_attribute_t    *attr_list,
                                          _In_ uint32_t                  attr_count)
{
    sai_status_t status;

    *nhgm_db_entry = NULL;
    *nhgm_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

    status = check_attribs_on_create_without_oid(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER);
    if (SAI_ERR(status)) {
        return status;
    }

    mlnx_sai_attr_t         nhg;
    mlnx_sai_attr_t         nh;
    mlnx_sai_attr_t         weight;
    mlnx_sai_attr_t         counter;
    mlnx_sai_attr_t         index;
    mlnx_sai_attr_t         sequence_id;
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
        find_attrib(attr_count, attr_list, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID, &sequence_id);
    }

    status = mlnx_nhg_oid_to_data(nhg.value->oid, &nhg_db_entry, &nhg_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG [OID:0x%X] data from DB.\n", nhg.value->oid);
        return status;
    }

    if ((nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) && !index.found) {
        SX_LOG_ERR("Index attribute required for fine grain ecmp nexthop group member\n");
        return SAI_STATUS_FAILURE;
    }

    if ((nhg_db_entry->data.type != MLNX_NHG_TYPE_ORDERED) && sequence_id.found) {
        SX_LOG_ERR("Sequence ID attribute is not allowed when group type is not ORDERED\n");
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_object_to_type(nh.value->oid, SAI_OBJECT_TYPE_NEXT_HOP, &data, (uint8_t*)&ext);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Unexpected NH [OID:0x%X].\n", nh.value->oid);
        return status;
    }

    status = mlnx_nhgm_db_entry_alloc(nhgm_db_entry,
                                      nhgm_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to allocate NHGM DB entry.\n");
        return status;
    }

    (*nhgm_db_entry)->data.state = MLNX_NHGM_STATE_ALLOCATED;

    (*nhgm_db_entry)->data.nhg_idx = nhg_idx;

    if (weight.found) {
        (*nhgm_db_entry)->data.weight = weight.value->u32;
    } else {
        (*nhgm_db_entry)->data.weight = 1;
    }

    if (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED) {
        /* Arch Spec:
         * SAI shall ignore the "weight" parameter passed via SAI API when
         * setting members of the ECMP container of the Dynamic Ordered Type
         * and always use "1" calling the corresponding SDK API.
         */
        (*nhgm_db_entry)->data.weight = 1;
        (*nhgm_db_entry)->data.entry.ordered.prio = sequence_id.found ? sequence_id.value->u32 : 0;
        if (ext == 1) {
            (*nhgm_db_entry)->data.type = MLNX_NHGM_TYPE_ORDERED_ENCAP;
            (*nhgm_db_entry)->data.entry.ordered.entry.encap.nh_idx = *(mlnx_shm_rm_array_idx_t*)&data;
        } else {
            (*nhgm_db_entry)->data.type = MLNX_NHGM_TYPE_ORDERED_NATIVE;
            (*nhgm_db_entry)->data.entry.ordered.entry.native.sx_ecmp_id = (sx_ecmp_id_t)data;
        }
    } else if (index.found) {
        (*nhgm_db_entry)->data.type = MLNX_NHGM_TYPE_FINE_GRAIN;
        (*nhgm_db_entry)->data.entry.fg.id = index.value->u32;
        (*nhgm_db_entry)->data.entry.fg.nh = nh.value->oid;
    } else if (ext == 1) {
        (*nhgm_db_entry)->data.type = MLNX_NHGM_TYPE_ENCAP;
        (*nhgm_db_entry)->data.entry.encap.nh_idx = *(mlnx_shm_rm_array_idx_t*)&data;
    } else {
        (*nhgm_db_entry)->data.type = MLNX_NHGM_TYPE_NATIVE;
        (*nhgm_db_entry)->data.entry.native.sx_ecmp_id = (sx_ecmp_id_t)data;
    }

    if (counter.found) {
        mlnx_counter_t         *counter_db_entry;
        mlnx_shm_rm_array_idx_t counter_idx;
        status = mlnx_counter_oid_to_data(counter.value->oid,
                                          &counter_db_entry,
                                          &counter_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get counter DB entry [OID:0x%X].\n", counter.value->oid);
            goto exit;
        }
        (*nhgm_db_entry)->data.flow_counter = counter_idx;
    }

    status = link_nhgm_to_nhg(*nhgm_idx, *nhgm_db_entry, nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to link NHGM [ID:%u] to NHG [ID:%u].\n", nhgm_idx->idx, (*nhgm_db_entry)->data.nhg_idx.idx);
        goto exit;
    }

exit:
    if (SAI_ERR(status)) {
        mlnx_nhgm_db_entry_free(*nhgm_idx);
    }
    return status;
}

static sai_status_t mlnx_nghm_priority_set(_In_ mlnx_nhgm_db_entry_t *nhgm_db_entry, _In_ sai_object_id_t priority)
{
    sai_status_t         status;
    mlnx_nhg_db_entry_t *nhg_db_entry;
    /* coverity[stack_use_local_overflow] */
    uint32_t priorities[FG_ECMP_MAX_PATHS] = {0};
    uint32_t priorities_count = FG_ECMP_MAX_PATHS;

    if ((nhgm_db_entry->data.type != MLNX_NHGM_TYPE_ORDERED_NATIVE) &&
        (nhgm_db_entry->data.type != MLNX_NHGM_TYPE_ORDERED_ENCAP)) {
        SX_LOG_ERR("Set SEQUENCE_ID is only supported for members of DYNAMIC_ORDERED_ECMP.\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    status = get_nhg_from_nhgm(nhgm_db_entry, &nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry.\n");
        return status;
    }

    status = mlnx_get_nhg_priorities(nhg_db_entry,
                                     MLNX_NHGM_TYPE_ORDERED_ENCAP | MLNX_NHGM_TYPE_ORDERED_NATIVE,
                                     priorities,
                                     &priorities_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get a list of NHG priorities.\n");
        return status;
    }

    status = mlnx_nhgm_remove(nhgm_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove NHGM with prio [%u].\n", nhgm_db_entry->data.entry.ordered.prio);
        return status;
    }

    nhgm_db_entry->data.entry.ordered.prio = priority;

    status = mlnx_nhgm_apply(nhgm_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to apply NHGM with prio [%u].\n", priority);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhgms_fill_db(_In_ uint32_t                 object_count,
                                       _In_ const uint32_t          *attr_count,
                                       _In_ const sai_attribute_t  **attr_list,
                                       _In_ sai_bulk_op_error_mode_t mode,
                                       _Out_ sai_object_id_t        *object_id,
                                       _Out_ sai_status_t           *object_statuses)
{
    sai_status_t            return_status = SAI_STATUS_SUCCESS;
    sai_status_t            status = SAI_STATUS_SUCCESS;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;
    mlnx_shm_rm_array_idx_t idx;

    for (uint32_t ii = 0; ii < object_count; ii++) {
        status = mlnx_nhgm_parse_attrs(&nhgm_db_entry,
                                       &idx,
                                       attr_list[ii],
                                       attr_count[ii]);
        if (SAI_ERR(status)) {
            return_status = status;
            SX_LOG_ERR("Failed to parse NHGM attrs [ii=%u].\n", ii);
            object_statuses[ii] = status;
            object_id[ii] = SAI_NULL_OBJECT_ID;
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }

        status = mlnx_nhgm_oid_create(idx, &object_id[ii]);
        if (SAI_ERR(status)) {
            return_status = status;
            SX_LOG_ERR("Failed to create NHGM OID. [ii=%u].\n", ii);
            mlnx_nhgm_db_entry_free(idx);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }
    }

exit:
    return return_status;
}

static sai_status_t mlnx_nhgms_mark_initialized(_In_ mlnx_nhg_db_entry_t *nhg_db_entry)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t nhgm_idx = nhg_db_entry->data.members;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;

    while (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(nhgm_idx)) {
        status = mlnx_nhgm_db_entry_idx_to_data(nhgm_idx, &nhgm_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get NHGM [ID:%u] DB data.\n", nhgm_idx.idx);
            return status;
        }

        if (nhgm_db_entry->data.state == MLNX_NHGM_STATE_ALLOCATED) {
            nhgm_db_entry->data.state = MLNX_NHGM_STATE_INITIALIZED;
        }

        nhgm_idx = nhgm_db_entry->data.next_member_idx;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_nhg_apply_bulk_members(_In_ sai_object_id_t nhg_oid)
{
    mlnx_nhg_db_entry_t    *nhg_db_entry;
    mlnx_shm_rm_array_idx_t idx;
    sai_status_t            status;
    sx_status_t             sx_status;
    uint32_t                next_hops_count = FG_ECMP_MAX_PATHS;
    sx_next_hop_t           next_hops[FG_ECMP_MAX_PATHS];

    status = mlnx_nhg_oid_to_data(nhg_oid, &nhg_db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NHG DB entry [OID:0x%X].\n", nhg_oid);
        return status;
    }

    if ((nhg_db_entry->data.type == MLNX_NHG_TYPE_ECMP) ||
        (nhg_db_entry->data.type == MLNX_NHG_TYPE_ORDERED)) {
        for (uint32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ii++) {
            if (nhg_db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id != 0) {
                status = mlnx_nhg_update_nhgm_counters(nhg_db_entry,
                                                       nhg_db_entry->data.data.encap.vrf_data[ii].associated_vrf,
                                                       nhg_db_entry->data.data.encap.vrf_data[ii].refcount,
                                                       true);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to update NHGM counters [ii=%u, VRF=0x%lX, refcount=%u].\n",
                               ii,
                               nhg_db_entry->data.data.encap.vrf_data[ii].associated_vrf,
                               nhg_db_entry->data.data.encap.vrf_data[ii].refcount);
                    return status;
                }

                status = mlnx_nhg_nh_data_get(nhg_db_entry,
                                              nhg_db_entry->data.data.encap.vrf_data[ii].associated_vrf,
                                              next_hops,
                                              &next_hops_count,
                                              false);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get NHG nh_data [ii=%u, VRF=0x%lX]\n",
                               ii,
                               nhg_db_entry->data.data.encap.vrf_data[ii].associated_vrf);
                    return status;
                }

                status = mlnx_check_and_set_ar_ecmp(nhg_db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id,
                                                    next_hops,
                                                    next_hops_count);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to check ar for sx_ecmp_id. [index = %d]\n", ii);
                    return status;
                }

                sx_status = sx_api_router_ecmp_set(gh_sdk,
                                                   SX_ACCESS_CMD_SET,
                                                   &nhg_db_entry->data.data.encap.vrf_data[ii].sx_ecmp_id,
                                                   next_hops,
                                                   &next_hops_count);
                if (SX_ERR(sx_status)) {
                    SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
                    return sdk_to_sai(sx_status);
                }
            }
        }

        status = mlnx_nhg_nh_data_get(nhg_db_entry,
                                      SAI_NULL_OBJECT_ID,
                                      next_hops,
                                      &next_hops_count,
                                      true);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get Regular NHG nh_data.\n");
            return status;
        }

        status = mlnx_check_and_set_ar_ecmp(nhg_db_entry->data.data.encap.vrf_data[MLNX_REGULAR_ECMP_INDEX].sx_ecmp_id,
                                            next_hops,
                                            next_hops_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to check ar for sx_ecmp_id. [index = %d]\n", MLNX_REGULAR_ECMP_INDEX);
            return status;
        }

        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_SET,
                                           &nhg_db_entry->data.data.encap.vrf_data[MLNX_REGULAR_ECMP_INDEX].sx_ecmp_id,
                                           next_hops,
                                           &next_hops_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    } else if (nhg_db_entry->data.type == MLNX_NHG_TYPE_FINE_GRAIN) {
        status = mlnx_nhgm_type_fine_grain_bulk_apply(nhg_db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed NHG type FG apply.\n");
            return status;
        }
    } else {
        SX_LOG_ERR("Unexpected NHG type [%u]\n", nhg_db_entry->data.type);
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_nhgms_mark_initialized(nhg_db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed marking NHGMs initialized.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static void mlnx_nhgm_bulk_list_free(_Inout_ mlnx_nhgm_bulk_node_t *list)
{
    while (list) {
        mlnx_nhgm_bulk_node_t *node = list;
        list = list->next;
        free(node);
    }
}

static sai_status_t mlnx_nhgs_apply_counter_to_new_members(_In_ mlnx_nhgm_bulk_entry_t  *nhgs,
                                                           _In_ uint32_t                 nhgs_count,
                                                           _In_ sai_bulk_op_error_mode_t mode,
                                                           _Out_ sai_object_id_t        *object_id,
                                                           _Out_ sai_status_t           *object_statuses)
{
    sai_status_t return_status = SAI_STATUS_SUCCESS;
    sai_status_t status = SAI_STATUS_SUCCESS;

    for (uint32_t ii = 0; ii < nhgs_count; ii++) {
        status = mlnx_nhg_apply_bulk_members(nhgs[ii].nhg);

        mlnx_nhgm_bulk_node_t *list = nhgs[ii].list;
        while (list) {
            SX_LOG_DBG("NHG_ii[%u] - NHGM[%u] (OID=0x%lX) status is %d.\n",
                       ii, list->ii, object_id[list->ii], status);
            object_statuses[list->ii] = status;
            if (SAI_ERR(status)) {
                object_id[list->ii] = SAI_NULL_OBJECT_ID;
            }
            list = list->next;
        }

        if (SAI_ERR(status)) {
            return_status = status;
            SX_LOG_ERR("Failed to apply NHG counter [ii=%u].\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }
    }

exit:
    for (uint32_t ii = 0; ii < nhgs_count; ii++) {
        mlnx_nhgm_bulk_list_free(nhgs[ii].list);
    }
    return return_status;
}

static sai_status_t mlnx_bulk_read_nhg_set(_In_ uint32_t                 object_count,
                                           _In_ sai_bulk_op_error_mode_t mode,
                                           _In_ const uint32_t          *attr_count,
                                           _In_ const sai_attribute_t  **attr_list,
                                           _Out_ mlnx_nhgm_bulk_entry_t *nhgs,
                                           _Out_ uint64_t               *nhgs_count,
                                           _Out_ sai_object_id_t        *object_id,
                                           _Out_ sai_status_t           *object_statuses)
{
    sai_status_t return_status = SAI_STATUS_SUCCESS;
    uint32_t     jj = 0, ii = 0;

    *nhgs_count = 0;

    for (ii = 0; ii < object_count; ii++) {
        if (SAI_ERR(object_statuses[ii]) && (object_statuses[ii] != SAI_STATUS_NOT_EXECUTED)) {
            continue;
        }

        mlnx_sai_attr_t nhg_attr;
        find_attrib(attr_count[ii], attr_list[ii], SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID, &nhg_attr);
        if (!nhg_attr.found) {
            return_status = SAI_STATUS_FAILURE;
            SX_LOG_ERR("NHG attribute not found [ii=%u].\n", ii);
            object_statuses[ii] = SAI_STATUS_FAILURE;
            object_id[ii] = SAI_NULL_OBJECT_ID;
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }

        for (jj = 0; jj < *nhgs_count; jj++) {
            if (nhgs[jj].nhg == nhg_attr.value->oid) {
                break;
            }
        }

        if (jj == *nhgs_count) {
            nhgs[(*nhgs_count)++].nhg = nhg_attr.value->oid;
        }

        mlnx_nhgm_bulk_node_t *new_nhgm_id = (mlnx_nhgm_bulk_node_t *)malloc(sizeof(mlnx_nhgm_bulk_node_t));
        new_nhgm_id->ii = ii;
        new_nhgm_id->next = nhgs[jj].list;
        nhgs[jj].list = new_nhgm_id;
    }

exit:
    return return_status;
}

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
    sai_status_t            return_status = SAI_STATUS_SUCCESS;
    sai_status_t            status = SAI_STATUS_SUCCESS;
    mlnx_nhgm_bulk_entry_t *nhgs = NULL;
    uint64_t                nhgs_count = 0;

    SX_LOG_ENTER();

    for (uint32_t ii = 0; ii < object_count; ii++) {
        object_statuses[ii] = SAI_STATUS_NOT_EXECUTED;
        object_id[ii] = SAI_NULL_OBJECT_ID;
    }

    sai_db_write_lock();

    status = mlnx_nhgms_fill_db(object_count,
                                attr_count,
                                attr_list,
                                mode,
                                object_id,
                                object_statuses);
    if (SAI_ERR(status)) {
        return_status = status;
        SX_LOG_ERR("Failed to fill NHGMs DB.\n");
        if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
            goto exit;
        }
    }

    nhgs = (mlnx_nhgm_bulk_entry_t*)calloc(sizeof(*nhgs), object_count);
    status = mlnx_bulk_read_nhg_set(object_count,
                                    mode,
                                    attr_count,
                                    attr_list,
                                    nhgs,
                                    &nhgs_count,
                                    object_id,
                                    object_statuses);
    if (SAI_ERR(status)) {
        return_status = status;
        SX_LOG_ERR("Failed to create a set of NHGs.\n");
        if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
            goto exit;
        }
    }

    status = mlnx_nhgs_apply_counter_to_new_members(nhgs,
                                                    (uint32_t)nhgs_count,
                                                    mode,
                                                    object_id,
                                                    object_statuses);
    if (SAI_ERR(status)) {
        return_status = status;
        SX_LOG_ERR("Failed to apply NHGs counter.\n");
        if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
            goto exit;
        }
    }

exit:
    if (nhgs) {
        free(nhgs);
    }
    sai_db_unlock();
    SX_LOG_EXIT();
    return return_status;
}

static sai_status_t mlnx_nhgms_mark_to_delete(_In_ uint32_t                 object_count,
                                              _In_ const sai_object_id_t   *object_id,
                                              _In_ sai_bulk_op_error_mode_t mode,
                                              _Out_ sai_status_t           *object_statuses)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sai_status_t            return_status = status;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;
    mlnx_shm_rm_array_idx_t idx;

    assert(object_count && object_statuses);

    sai_db_write_lock();
    for (uint32_t ii = 0; ii < object_count; ii++) {
        status = mlnx_nhgm_oid_to_data(object_id[ii], &nhgm_db_entry, &idx);
        if (SAI_ERR(status)) {
            return_status = status;
            object_statuses[ii] = status;
            SX_LOG_ERR("Failed getting NHGM DB entry [ii=%u]\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        } else {
            nhgm_db_entry->data.state = MLNX_NHGM_STATE_TO_REMOVE;
            SX_LOG_DBG("Mark NHGM [ID:%u] 'TO_DELETE'\n", idx.idx);
        }
    }

exit:
    sai_db_unlock();
    return return_status;
}

static sai_status_t mlnx_nhgms_get_nhgs_set(_In_ uint32_t                 object_count,
                                            _In_ const sai_object_id_t   *object_id,
                                            _In_ sai_bulk_op_error_mode_t mode,
                                            _Inout_ sai_status_t         *object_statuses,
                                            _Out_ mlnx_nhgm_bulk_entry_t *nhgs,
                                            _Out_ uint64_t               *nhgs_count)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sai_status_t            return_status = status;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;
    mlnx_shm_rm_array_idx_t idx;
    uint32_t                jj = 0;

    assert(object_count && object_statuses);

    sai_db_write_lock();
    for (uint32_t ii = 0; ii < object_count; ii++) {
        if (SAI_ERR(object_statuses[ii]) && (object_statuses[ii] != SAI_STATUS_NOT_EXECUTED)) {
            continue;
        }

        status = mlnx_nhgm_oid_to_data(object_id[ii], &nhgm_db_entry, &idx);
        if (SAI_ERR(status)) {
            return_status = status;
            object_statuses[ii] = status;
            SX_LOG_ERR("Failed getting NHGM DB entry [ii=%u]\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }

        sai_object_id_t nhg_oid = SAI_NULL_OBJECT_ID;
        status = mlnx_nhg_oid_create(nhgm_db_entry->data.nhg_idx, &nhg_oid);
        if (SAI_ERR(status)) {
            return_status = status;
            object_statuses[ii] = status;
            SX_LOG_ERR("Failed getting NHG [ID:%u] from NHGM [ii=%u]\n", nhgm_db_entry->data.nhg_idx.idx, ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }

        for (jj = 0; jj < *nhgs_count; jj++) {
            if (nhgs[jj].nhg == nhg_oid) {
                break;
            }
        }

        if (jj == *nhgs_count) {
            nhgs[(*nhgs_count)++].nhg = nhg_oid;
        }

        mlnx_nhgm_bulk_node_t *new_nhgm_id = (mlnx_nhgm_bulk_node_t *)malloc(sizeof(mlnx_nhgm_bulk_node_t));
        new_nhgm_id->ii = ii;
        new_nhgm_id->next = nhgs[jj].list;
        nhgs[jj].list = new_nhgm_id;
    }

exit:
    sai_db_unlock();
    return return_status;
}

static sai_status_t mlnx_nhgms_remove_bulk(_In_ mlnx_nhgm_bulk_entry_t  *nhgs,
                                           _In_ uint32_t                 nhgs_count,
                                           _In_ sai_bulk_op_error_mode_t mode,
                                           _In_ uint32_t                 object_count,
                                           _Inout_ sai_status_t         *object_statuses)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_status_t return_status = status;

    sai_db_write_lock();
    for (uint32_t ii = 0; ii < nhgs_count; ii++) {
        status = mlnx_nhg_apply_bulk_members(nhgs[ii].nhg);

        mlnx_nhgm_bulk_node_t *list = nhgs[ii].list;
        while (list) {
            SX_LOG_DBG("NHG_ii[%u] - NHGM[%u] status is %d.\n",
                       ii, list->ii, status);
            object_statuses[list->ii] = status;
            list = list->next;
        }

        if (SAI_ERR(status)) {
            return_status = status;
            SX_LOG_ERR("Failed to remove bulk NHG members [ii=%u].\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }
    }

exit:
    sai_db_unlock();
    for (uint32_t ii = 0; ii < nhgs_count; ii++) {
        mlnx_nhgm_bulk_list_free(nhgs[ii].list);
    }
    return return_status;
}

static sai_status_t mlnx_nhgms_deallocate_bulk(_In_ uint32_t                 object_count,
                                               _In_ const sai_object_id_t   *object_id,
                                               _In_ sai_bulk_op_error_mode_t mode,
                                               _Out_ sai_status_t           *object_statuses)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sai_status_t            return_status = status;
    mlnx_nhgm_db_entry_t   *nhgm_db_entry;
    mlnx_shm_rm_array_idx_t nhgm_idx;
    mlnx_nhg_db_entry_t    *nhg_db_entry;

    sai_db_write_lock();

    for (uint32_t ii = 0; ii < object_count; ii++) {
        if (SAI_ERR(object_statuses[ii])) {
            continue;
        }

        status = mlnx_nhgm_oid_to_data(object_id[ii], &nhgm_db_entry, &nhgm_idx);
        if (SAI_ERR(status)) {
            return_status = status;
            object_statuses[ii] = status;
            SX_LOG_ERR("Failed getting NHGM DB entry [ii=%u]\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }

        status = mlnx_nhg_db_entry_idx_to_data(nhgm_db_entry->data.nhg_idx,
                                               &nhg_db_entry);
        if (SAI_ERR(status)) {
            return_status = status;
            object_statuses[ii] = status;
            SX_LOG_ERR("Failed getting NHG DB entry [ii=%u]\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }

        status = unlink_nhgm_from_nhg(nhgm_idx, nhgm_db_entry, nhg_db_entry);
        if (SAI_ERR(status)) {
            return_status = status;
            object_statuses[ii] = status;
            SX_LOG_ERR("Failed to unlink NHGM DB entry [ii=%u]\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }

        status = mlnx_nhgm_db_entry_free(nhgm_idx);
        if (SAI_ERR(status)) {
            return_status = status;
            object_statuses[ii] = status;
            SX_LOG_ERR("Failed to deallocate NHGM DB entry [ii=%u]\n", ii);
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                goto exit;
            }
        }
    }

exit:
    sai_db_unlock();
    return return_status;
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
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sai_status_t            return_status = status;
    mlnx_nhgm_bulk_entry_t *nhgs = NULL;
    uint64_t                nhgs_count = 0;

    for (uint32_t ii = 0; ii < object_count; ii++) {
        object_statuses[ii] = SAI_STATUS_NOT_EXECUTED;
    }

    status = mlnx_nhgms_mark_to_delete(object_count,
                                       object_id,
                                       mode,
                                       object_statuses);
    if (SAI_ERR(status)) {
        return_status = status;
        SX_LOG_ERR("Failed marking NHGMs 'to_delete'.\n");
        if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
            goto exit;
        }
    }

    nhgs = (mlnx_nhgm_bulk_entry_t*)calloc(sizeof(*nhgs), object_count);
    status = mlnx_nhgms_get_nhgs_set(object_count,
                                     object_id,
                                     mode,
                                     object_statuses,
                                     nhgs,
                                     &nhgs_count);
    if (SAI_ERR(status)) {
        return_status = status;
        SX_LOG_ERR("Failed getting NHGs list.\n");
        if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
            goto exit;
        }
    }

    SX_LOG_DBG("Got [%u] NHGs sets:\n", nhgs_count);
    for (uint32_t ii = 0; ii < nhgs_count; ii++) {
        SX_LOG_DBG("%u: NHG[0x%X]:\n", ii, nhgs[ii].nhg);
        mlnx_nhgm_bulk_node_t *list = nhgs[ii].list;
        while (list) {
            SX_LOG_DBG("\tmembers[%u]\n", list->ii);
            list = list->next;
        }
    }

    status = mlnx_nhgms_remove_bulk(nhgs,
                                    (uint32_t)nhgs_count,
                                    mode,
                                    object_count,
                                    object_statuses);
    if (SAI_ERR(status)) {
        return_status = status;
        SX_LOG_ERR("Failed removing NHGMs.\n");
        if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
            goto exit;
        }
    }

    status = mlnx_nhgms_deallocate_bulk(object_count,
                                        object_id,
                                        mode,
                                        object_statuses);
    if (SAI_ERR(status)) {
        return_status = status;
        SX_LOG_ERR("Failed to deallocate NHGMs.\n");
        if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
            goto exit;
        }
    }

exit:
    if (nhgs) {
        free(nhgs);
    }
    return return_status;
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
    NULL,
    NULL,
};
