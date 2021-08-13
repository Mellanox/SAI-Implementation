/*
 *  Copyright (C) 2014-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#define __MODULE__ SAI_UDF

#define UDF_MATCH_L2_TYPE_ARP  (0x0806)
#define UDF_MATCH_L2_TYPE_IPv4 (0x0800)
#define UDF_MATCH_L2_TYPE_IPv6 (0x86DD)
#define UDF_MATCH_DEF_PRIO     (0)

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

/*..... Function Prototypes ..................*/
static void udf_key_to_str(_In_ sai_object_id_t   object_id,
                           _In_ sai_object_type_t object_type,
                           _Out_ char            *key_str);
static sai_status_t mlnx_udf_db_size_get(_In_ sai_object_type_t udf_type, _Out_ uint32_t         *size);
static bool mlnx_udf_db_is_created(_In_ uint32_t index, _In_ sai_object_type_t udf_type);
static sai_status_t mlnx_udf_db_find_free_index(_In_ sai_object_type_t udf_type, _Out_ uint32_t          *index);
static sai_status_t mlnx_udf_match_type_is_not_created(_In_ mlnx_udf_match_type_t type);
static sai_status_t mlnx_udf_match_l2_type_convert(_In_ const sai_acl_field_data_t *l2_match,
                                                   _In_ uint32_t                    attr_index,
                                                   _Out_ mlnx_udf_match_type_t     *match_type);
static sai_status_t mlnx_udf_match_type_to_l2(_In_ mlnx_udf_match_type_t  match_type,
                                              _Out_ sai_acl_field_data_t *l2_match);
static sai_status_t mlnx_udf_group_mask_to_indexes(_In_ udf_group_mask_t udf_group_mask,
                                                   _Out_ sai_u32_list_t *udf_groups_db_indexes);
static sai_status_t mlnx_udf_group_db_index_references_set(_In_ uint32_t udf_group_db_index, _In_ bool add_reference);
static sai_status_t mlnx_udf_group_mask_references_set(_In_ udf_group_mask_t udf_group_mask, _In_ bool add_reference);
static sai_status_t mlnx_acl_udf_group_list_references_set(_In_ const acl_udf_group_list_t udf_group_list,
                                                           _In_ bool                       add_reference);
static sai_status_t mlnx_udf_oid_validate_and_fetch(_In_ sai_object_id_t   udf_id,
                                                    _In_ sai_object_type_t udf_type,
                                                    _In_ uint32_t          attr_index,
                                                    _Out_ uint32_t        *db_index);
static sai_status_t mlnx_udf_hash_mask_validate(_In_ const sai_u8_list_t *hash_mask,
                                                _In_ uint32_t             attr_index,
                                                _In_ uint32_t             group_db_index);
static sai_status_t mlnx_udf_base_validate(_In_ sai_udf_base_t base,
                                           _In_ uint32_t       attr_index,
                                           _In_ uint32_t       match_db_index);
static sai_status_t mlnx_udf_group_sx_custom_bytes_remove(_In_ uint32_t group_db_index);
static sai_status_t mlnx_udf_group_sx_custom_bytes_create_or_update(_In_ uint32_t group_db_index);
static sai_status_t mlnx_udf_group_update(_In_ uint32_t group_db_index);
static sai_status_t mlnx_udf_group_add_udf(_In_ uint32_t group_db_index, _In_ uint32_t udf_db_index);
static sai_status_t mlnx_udf_group_remove_udf(_In_ uint32_t udf_db_index);
static sai_status_t mlnx_udf_remove_udf_match(_In_ uint32_t udf_db_index);
static sai_status_t mlnx_udf_attrib_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_udf_match_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_udf_group_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_udf_attrib_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_udf_group_sx_acl_key_ids_copy_spc(_In_ uint32_t       udf_group_db_index,
                                                           _Out_ sx_acl_key_t *flex_acl_key_ids,
                                                           _Inout_ uint32_t   *flex_acl_key_ids_num,
                                                           _Inout_ uint32_t   *custom_bytes_num);
static sai_status_t mlnx_udf_flex_acl_key_to_ecmp_hash_field_spc(_In_ sx_acl_key_t                  flex_acl_key_id,
                                                                 _Out_ sx_router_ecmp_hash_field_t *ecmp_hash_field);
static sai_status_t mlnx_udf_custom_bytes_to_ecmp_hash_fields_spc(
    _In_ uint32_t                        flex_acl_keys_num,
    _In_ uint32_t                        custom_bytes_num,
    _In_ const sx_acl_key_t             *flex_acl_key_ids,
    _Inout_ sx_router_ecmp_hash_field_t *ecmp_hash_fields,
    _In_ uint32_t                        ecmp_hash_fields_idx);
static void* mlnx_udf_alloc_group_list_spc(void);
static sai_status_t mlnx_udf_group_sx_reg_ext_points_get_spc2(_In_ sx_gp_register_e        reg_id,
                                                              _Out_ sx_extraction_point_t *ext_point_list,
                                                              _Out_ uint32_t              *ext_point_cnt);
static sai_status_t mlnx_udf_group_match_type_to_extr_point_spc2(_In_ mlnx_udf_match_type_t        udf_match_type,
                                                                 _Out_ sx_extraction_point_type_e *sx_ext_point_type);
static sai_status_t mlnx_udf_group_validate_match_type(_In_ mlnx_udf_match_type_t udf_match_type,
                                                       _In_ uint32_t              udf_count);
static sai_status_t mlnx_udf_group_flex_acl_key_ids_add_spc2(_In_ uint32_t group_db_index);
static sai_status_t mlnx_udf_group_flex_acl_key_ids_del_spc2(_In_ uint32_t group_db_index);
static sai_status_t mlnx_udf_group_flex_acl_key_ids_copy_spc2(_In_ uint32_t       udf_group_db_index,
                                                              _Out_ sx_acl_key_t *flex_acl_key_ids,
                                                              _Inout_ uint32_t   *flex_acl_key_ids_num,
                                                              _Inout_ uint32_t   *custom_bytes_num);
static sai_status_t mlnx_udf_custom_bytes_to_ecmp_hash_fields_spc2(
    _In_ uint32_t                        flex_acl_keys_num,
    _In_ uint32_t                        custom_bytes_num,
    _In_ const sx_acl_key_t             *flex_acl_key_ids,
    _Inout_ sx_router_ecmp_hash_field_t *ecmp_hash_fields,
    _In_ uint32_t                        ecmp_hash_fields_idx);
static void* mlnx_udf_alloc_group_list_spc2(void);

typedef sai_status_t (*mlnx_udf_group_flex_acl_keys_update_fn)(_In_ uint32_t group_db_index);
typedef sai_status_t (*mlnx_udf_group_flex_acl_keys_copy_fn)(_In_ uint32_t       udf_group_db_index,
                                                             _Out_ sx_acl_key_t *flex_acl_key_ids,
                                                             _Inout_ uint32_t   *flex_acl_key_ids_num,
                                                             _Inout_ uint32_t   *custom_bytes_num);
typedef sai_status_t (*mlnx_udf_mask_flex_acl_keys_to_ecmp_hash_field_fn)(_In_ uint32_t
                                                                          flex_acl_keys_num,
                                                                          _In_ uint32_t
                                                                          custom_bytes_num,
                                                                          _In_ const sx_acl_key_t             *
                                                                          flex_acl_key_ids,
                                                                          _Inout_ sx_router_ecmp_hash_field_t *
                                                                          ecmp_hash_fields,
                                                                          _In_ uint32_t
                                                                          ecmp_hash_fields_idx);
typedef void* (*mlnx_udf_alloc_group_list_fn)(void);

typedef struct _mlnx_udf_cb_table_t {
    mlnx_udf_group_flex_acl_keys_update_fn            flex_acl_key_ids_add;
    mlnx_udf_group_flex_acl_keys_update_fn            flex_acl_key_ids_del;
    mlnx_udf_group_flex_acl_keys_copy_fn              flex_acl_key_ids_copy;
    mlnx_udf_mask_flex_acl_keys_to_ecmp_hash_field_fn custom_bytes_to_ecmp_hash_fields;
    mlnx_udf_alloc_group_list_fn                      alloc_group_list;
} mlnx_udf_cb_table_t;

static mlnx_udf_cb_table_t mlnx_udf_cb_sp = {
    mlnx_udf_group_sx_custom_bytes_create_or_update,
    mlnx_udf_group_sx_custom_bytes_remove,
    mlnx_udf_group_sx_acl_key_ids_copy_spc,
    mlnx_udf_custom_bytes_to_ecmp_hash_fields_spc,
    mlnx_udf_alloc_group_list_spc
};

static mlnx_udf_cb_table_t mlnx_udf_cb_sp2 = {
    mlnx_udf_group_flex_acl_key_ids_add_spc2,
    mlnx_udf_group_flex_acl_key_ids_del_spc2,
    mlnx_udf_group_flex_acl_key_ids_copy_spc2,
    mlnx_udf_custom_bytes_to_ecmp_hash_fields_spc2,
    mlnx_udf_alloc_group_list_spc2
};

mlnx_udf_cb_table_t *mlnx_udf_cb = NULL;

extern sai_status_t mlnx_init_flex_parser();

/* UDF vendor attributes */
static const sai_vendor_attribute_entry_t udf_vendor_attribs[] = {
    { SAI_UDF_ATTR_MATCH_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_attrib_get, (void*)SAI_UDF_ATTR_MATCH_ID,
      NULL, NULL },
    { SAI_UDF_ATTR_GROUP_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_attrib_get, (void*)SAI_UDF_ATTR_GROUP_ID,
      NULL, NULL },
    { SAI_UDF_ATTR_BASE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_attrib_get, (void*)SAI_UDF_ATTR_BASE,
      NULL, NULL },
    { SAI_UDF_ATTR_OFFSET,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_attrib_get, (void*)SAI_UDF_ATTR_OFFSET,
      NULL, NULL },
    { SAI_UDF_ATTR_HASH_MASK,
      {true, false, true, true},
      {true, false, true, true},
      mlnx_udf_attrib_get, (void*)SAI_UDF_ATTR_HASH_MASK,
      mlnx_udf_attrib_set, (void*)SAI_UDF_ATTR_HASH_MASK },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        udf_enum_info[] = {
    [SAI_UDF_ATTR_BASE] = ATTR_ENUM_VALUES_LIST(
        SAI_UDF_BASE_L2,
        SAI_UDF_BASE_L3)
};
const mlnx_obj_type_attrs_info_t          mlnx_udf_obj_type_info =
{ udf_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(udf_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};
/* UDF Match vendor attributes */
static const sai_vendor_attribute_entry_t udf_match_vendor_attribs[] = {
    { SAI_UDF_MATCH_ATTR_L2_TYPE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_match_attrib_get, (void*)SAI_UDF_MATCH_ATTR_L2_TYPE,
      NULL, NULL },
    { SAI_UDF_MATCH_ATTR_L3_TYPE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_match_attrib_get, (void*)SAI_UDF_MATCH_ATTR_L3_TYPE,
      NULL, NULL },
    { SAI_UDF_MATCH_ATTR_GRE_TYPE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_match_attrib_get, (void*)SAI_UDF_MATCH_ATTR_GRE_TYPE,
      NULL, NULL },
    { SAI_UDF_MATCH_ATTR_PRIORITY,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_match_attrib_get, (void*)SAI_UDF_MATCH_ATTR_PRIORITY,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_obj_type_attrs_info_t          mlnx_udf_match_obj_type_info =
{ udf_match_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY()};
/* UDF Group vendor attributes */
static const sai_vendor_attribute_entry_t udf_group_vendor_attribs[] = {
    { SAI_UDF_GROUP_ATTR_UDF_LIST,
      {false, false, false, true},
      {false, false, false, true},
      mlnx_udf_group_attrib_get, (void*)SAI_UDF_GROUP_ATTR_UDF_LIST,
      NULL, NULL },
    { SAI_UDF_GROUP_ATTR_TYPE,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_group_attrib_get, (void*)SAI_UDF_GROUP_ATTR_TYPE,
      NULL, NULL },
    { SAI_UDF_GROUP_ATTR_LENGTH,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_udf_group_attrib_get, (void*)SAI_UDF_GROUP_ATTR_LENGTH,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        udf_group_enum_info[] = {
    [SAI_UDF_GROUP_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_UDF_GROUP_TYPE_GENERIC)
};
const mlnx_obj_type_attrs_info_t          mlnx_udf_group_obj_type_info =
{ udf_group_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(udf_group_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};
static void udf_key_to_str(_In_ sai_object_id_t   object_id,
                           _In_ sai_object_type_t object_type,
                           _Out_ char            *key_str)
{
    uint32_t data;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(object_id, object_type, &data, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid %s", SAI_TYPE_STR(object_type));
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "%s %u", SAI_TYPE_STR(object_type), data);
    }
}

static sai_status_t mlnx_udf_db_size_get(_In_ sai_object_type_t udf_type, _Out_ uint32_t         *size)
{
    assert(size);

    switch (udf_type) {
    case SAI_OBJECT_TYPE_UDF:
        *size = MLNX_UDF_COUNT_MAX;
        break;

    case SAI_OBJECT_TYPE_UDF_GROUP:
        *size = MLNX_UDF_GROUP_COUNT_MAX;
        break;

    case SAI_OBJECT_TYPE_UDF_MATCH:
        *size = MLNX_UDF_MATCH_COUNT_MAX;
        break;

    default:
        SX_LOG_ERR("Unknown udf type - %d\n", udf_type);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static bool mlnx_udf_db_is_created(_In_ uint32_t index, _In_ sai_object_type_t udf_type)
{
    assert((SAI_OBJECT_TYPE_UDF == udf_type) ||
           (SAI_OBJECT_TYPE_UDF_GROUP == udf_type) ||
           (SAI_OBJECT_TYPE_UDF_MATCH == udf_type));

    if (SAI_OBJECT_TYPE_UDF == udf_type) {
        return udf_db_udf(index).is_created;
    } else if (SAI_OBJECT_TYPE_UDF_MATCH == udf_type) {
        return udf_db_match(index).is_created;
    } else {
        return udf_db_group_ptr(index)->is_created;
    }
}

static sai_status_t mlnx_udf_db_find_free_index(_In_ sai_object_type_t udf_type, _Out_ uint32_t          *index)
{
    sai_status_t status;
    uint32_t     ii, db_size;

    assert(NULL != index);
    assert((SAI_OBJECT_TYPE_UDF == udf_type) ||
           (SAI_OBJECT_TYPE_UDF_GROUP == udf_type) ||
           (SAI_OBJECT_TYPE_UDF_MATCH == udf_type));

    status = mlnx_udf_db_size_get(udf_type, &db_size);
    if (SAI_ERR(status)) {
        return status;
    }

    for (ii = 0; ii < db_size; ii++) {
        if (false == mlnx_udf_db_is_created(ii, udf_type)) {
            *index = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("DB for %s is full, max number allowed (%d)\n", SAI_TYPE_STR(udf_type), db_size);

    return SAI_STATUS_INSUFFICIENT_RESOURCES;
}

static sai_status_t mlnx_udf_match_type_is_not_created(_In_ mlnx_udf_match_type_t type)
{
    uint32_t ii;

    for (ii = 0; ii < MLNX_UDF_MATCH_COUNT_MAX; ii++) {
        if (udf_db_match(ii).is_created &&
            (udf_db_match(ii).type == type)) {
            SX_LOG_ERR("Failed to create UDF Match - The same UDF Match is already created [%lx]\n", udf_db_match(
                           ii).sai_object);
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_custom_bytes_set(_In_ sx_access_cmd_t                             cmd,
                                   _In_ const sx_acl_custom_bytes_set_attributes_t *attrs,
                                   _Inout_ sx_acl_key_t                            *keys,
                                   _In_ uint32_t                                    length)
{
    sx_status_t sx_status;
    uint32_t    bytes_count;

    assert((SX_ACCESS_CMD_CREATE == cmd) ||
           (SX_ACCESS_CMD_EDIT == cmd) ||
           (SX_ACCESS_CMD_DESTROY == cmd));

    assert(NULL != attrs);
    assert(NULL != keys);

    bytes_count = length;

    sx_status = sx_api_acl_custom_bytes_set(gh_sdk, cmd, attrs, keys, &bytes_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s sx acl custom bytes set - %s\n", SX_ACCESS_CMD_STR(cmd),
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SX_ACCESS_CMD_CREATE == cmd) {
        if (bytes_count != length) {
            SX_LOG_ERR("Failed to create enough custom bytes. Created (%d), needed (%d)\n", bytes_count, length);

            sx_status = sx_api_acl_custom_bytes_set(gh_sdk, SX_ACCESS_CMD_DESTROY, attrs, keys, &bytes_count);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to perform a rollback (destroy sx custom bytes)\n");
            }

            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_match_l2_type_convert(_In_ const sai_acl_field_data_t *l2_match,
                                                   _In_ uint32_t                    attr_index,
                                                   _Out_ mlnx_udf_match_type_t     *match_type)
{
    assert(NULL != match_type);

    if ((false == l2_match->enable) || (0x0 == l2_match->mask.u16)) {
        *match_type = MLNX_UDF_MATCH_TYPE_EMPTY;
        return SAI_STATUS_SUCCESS;
    }

    if (l2_match->mask.u16 != 0xFFFF) {
        SX_LOG_ERR("Unsupported value for L2 Type Mask, the only supported is 0xFFFF\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    switch (l2_match->data.u16) {
    case UDF_MATCH_L2_TYPE_ARP:
        *match_type = MLNX_UDF_MATCH_TYPE_ARP;
        break;

    case UDF_MATCH_L2_TYPE_IPv4:
        *match_type = MLNX_UDF_MATCH_TYPE_IPv4;
        break;

    case UDF_MATCH_L2_TYPE_IPv6:
        *match_type = MLNX_UDF_MATCH_TYPE_IPv6;
        break;

    default:
        SX_LOG_ERR("Unsupported type of L2 match type (%u)\n", l2_match->data.u16);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_match_type_to_l2(_In_ mlnx_udf_match_type_t  match_type,
                                              _Out_ sai_acl_field_data_t *l2_match)
{
    assert(NULL != l2_match);

    l2_match->mask.u16 = 0xFFFF;

    switch (match_type) {
    case MLNX_UDF_MATCH_TYPE_EMPTY:
        l2_match->data.u16 = 0x0;
        l2_match->mask.u16 = 0x0;
        break;

    case MLNX_UDF_MATCH_TYPE_ARP:
        l2_match->data.u16 = UDF_MATCH_L2_TYPE_ARP;
        break;

    case MLNX_UDF_MATCH_TYPE_IPv4:
        l2_match->data.u16 = UDF_MATCH_L2_TYPE_IPv4;
        break;

    case MLNX_UDF_MATCH_TYPE_IPv6:
        l2_match->data.u16 = UDF_MATCH_L2_TYPE_IPv6;
        break;

    default:
        SX_LOG_ERR("Invalid udf match type - %d\n", match_type);
        return SAI_STATUS_FAILURE;
    }

    l2_match->enable = true;

    return SAI_STATUS_SUCCESS;
}

static void* mlnx_udf_alloc_group_list_spc(void)
{
    return calloc(MLNX_UDF_GROUP_COUNT_MAX, sizeof(uint32_t));
}

static void* mlnx_udf_alloc_group_list_spc2(void)
{
    return calloc(MLNX_UDF_GP_REG_COUNT, sizeof(uint32_t));
}

static sai_status_t mlnx_udf_group_mask_to_indexes(_In_ udf_group_mask_t udf_group_mask,
                                                   _Out_ sai_u32_list_t *udf_groups_db_indexes)
{
    uint32_t group_count, ii;

    assert(NULL != udf_groups_db_indexes);
    assert(mlnx_udf_cb);

    udf_groups_db_indexes->list = mlnx_udf_cb->alloc_group_list();

    if (NULL == udf_groups_db_indexes->list) {
        SX_LOG_ERR("Failed to allocate memory for udf_groups_db_indexes\n");
        return SAI_STATUS_NO_MEMORY;
    }

    group_count = ii = 0;
    while (udf_group_mask) {
        if (udf_group_mask & 0x1) {
            udf_groups_db_indexes->list[group_count] = ii;
            group_count++;
        }

        udf_group_mask >>= 1;
        ii++;
    }

    udf_groups_db_indexes->count = group_count;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_mask_to_objlist(_In_ udf_group_mask_t udf_group_mask, _Out_ sai_object_list_t *objlist)
{
    sai_status_t   status;
    sai_u32_list_t udf_groups_db_indexes = (sai_u32_list_t) {.list = NULL};
    uint32_t       ii;

    assert(NULL != objlist);

    status = mlnx_udf_group_mask_to_indexes(udf_group_mask, &udf_groups_db_indexes);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_attribute_value_list_size_check(&objlist->count, udf_groups_db_indexes.count);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (ii = 0; ii < udf_groups_db_indexes.count; ii++) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_UDF_GROUP, udf_groups_db_indexes.list[ii],
                                    NULL, &objlist->list[ii]);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    free(udf_groups_db_indexes.list);
    return status;
}

sai_status_t mlnx_udf_group_oid_validate_and_fetch(_In_ sai_object_id_t udf_group_id,
                                                   _In_ uint32_t        attr_index,
                                                   _Out_ uint32_t      *udf_group_db_index)
{
    sai_status_t status;

    assert(NULL != udf_group_db_index);

    status = mlnx_udf_oid_validate_and_fetch(udf_group_id, SAI_OBJECT_TYPE_UDF_GROUP,
                                             attr_index, udf_group_db_index);
    if (SAI_ERR(status)) {
        return status;
    }

    if (0 == udf_db_group_udfs_ptr(*udf_group_db_index)->count) {
        SX_LOG_ERR("Group (%lx) is empty\n", udf_group_id);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_objlist_validate_and_fetch_mask(_In_ const sai_object_list_t *udf_groups,
                                                            _In_ uint32_t                 attr_index,
                                                            _Out_ udf_group_mask_t       *udf_group_mask)
{
    sai_status_t status;
    uint64_t     mask;
    uint32_t     udf_group_db_index, ii;

    assert(NULL != udf_group_mask);
    assert(NULL != udf_groups);

    mask = 0;
    for (ii = 0; ii < udf_groups->count; ii++) {
        status = mlnx_udf_group_oid_validate_and_fetch(udf_groups->list[ii], attr_index, &udf_group_db_index);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_sai_udf_issu_flow_validate_udf_group_hw_configured(udf_group_db_index);
        if (SAI_ERR(status)) {
            return status;
        }

        mask |= UINT64_C(1) << udf_group_db_index;
    }

    *udf_group_mask = mask;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_mask_is_hash_applicable(_In_ udf_group_mask_t                   udf_group_mask,
                                                    _In_ mlnx_switch_usage_hash_object_id_t hash_oper_type,
                                                    _In_ bool                              *is_applicable)
{
    sai_status_t          status = SAI_STATUS_SUCCESS;
    sai_u32_list_t        udf_groups_db_indexes = (sai_u32_list_t) {.list = NULL};
    mlnx_udf_match_type_t udf_match_type;
    uint32_t              udf_group_db_index, udf_db_index, udf_match_db_index, ii;

    assert(NULL != is_applicable);
    assert(hash_oper_type <= SAI_HASH_MAX_OBJ_ID);

    if (MLNX_UDF_GROUP_MASK_EMPTY == udf_group_mask) {
        *is_applicable = true;
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_HASH_MAX_OBJ_ID == hash_oper_type) {
        *is_applicable = true;
        return SAI_STATUS_SUCCESS;
    }

    if ((SAI_HASH_LAG_ID <= hash_oper_type) && (hash_oper_type < SAI_HASH_MAX_OBJ_ID)) {
        SX_LOG_ERR("UDF Group list is only supported for ECMP Hash objects\n");
        *is_applicable = false;
        return SAI_STATUS_SUCCESS;
    }

    /* SAI_HASH_ECMP_ID is the only type that supports all possible UDF Groups */
    if (SAI_HASH_ECMP_ID == hash_oper_type) {
        *is_applicable = true;
        return SAI_STATUS_SUCCESS;
    }

    /* SAI_HASH_ECMP_IPINIP_ID is not supported for UDF Group
     * because there is no supported UDF Match for that */
    if (SAI_HASH_ECMP_IPINIP_ID == hash_oper_type) {
        SX_LOG_ERR("UDF Group is not supported for ECMP_HASH_IPV4_IN_IPV4\n");
        *is_applicable = false;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_udf_group_mask_to_indexes(udf_group_mask, &udf_groups_db_indexes);
    if (SAI_ERR(status)) {
        return status;
    }

    for (ii = 0; ii < udf_groups_db_indexes.count; ii++) {
        udf_group_db_index = udf_groups_db_indexes.list[ii];

        if (udf_db_group_udfs_ptr(udf_group_db_index)->count > 1) {
            SX_LOG_ERR("UDF Group for ECMP Hash attribute can only contain one UDF with corresponding UDF match\n");
            *is_applicable = false;
            goto out;
        }

        udf_db_index = udf_db_group_udfs_ptr(udf_group_db_index)->udf_indexes[0];
        udf_match_db_index = udf_db_udf(udf_db_index).match_index;
        udf_match_type = udf_db_match(udf_match_db_index).type;

        switch (hash_oper_type) {
        case SAI_HASH_ECMP_IP4_ID:
            if (MLNX_UDF_MATCH_TYPE_IPv4 != udf_match_type) {
                SX_LOG_ERR("UDF Group should contain a UDF with UDF Match for IPv4\n");
                *is_applicable = false;
                goto out;
            }
            break;

        case SAI_HASH_ECMP_IP6_ID:
            if (MLNX_UDF_MATCH_TYPE_IPv6 != udf_match_type) {
                SX_LOG_ERR("UDF Group should contain a UDF with UDF Match for IPv6\n");
                *is_applicable = false;
                goto out;
            }
            break;

        default:
            SX_LOG_ERR("Unexpected type of Hash oper type\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    *is_applicable = true;

out:
    free(udf_groups_db_indexes.list);
    return status;
}

sai_status_t mlnx_udf_group_sx_acl_key_ids_copy_spc(_In_ uint32_t       udf_group_db_index,
                                                    _Out_ sx_acl_key_t *flex_acl_key_ids,
                                                    _Inout_ uint32_t   *flex_acl_key_ids_num,
                                                    _Inout_ uint32_t   *custom_bytes_num)
{
    assert(flex_acl_key_ids);
    assert(flex_acl_key_ids_num);
    assert(custom_bytes_num);
    memcpy(&flex_acl_key_ids[*flex_acl_key_ids_num], udf_db_group_ptr(udf_group_db_index)->sx_custom_bytes_keys,
           sizeof(sx_acl_key_t) * udf_db_group_ptr(udf_group_db_index)->length);

    *flex_acl_key_ids_num += udf_db_group_ptr(udf_group_db_index)->length;
    *custom_bytes_num += udf_db_group_ptr(udf_group_db_index)->length;
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_flex_acl_key_ids_copy_spc2(_In_ uint32_t       udf_group_db_index,
                                                       _Out_ sx_acl_key_t *flex_acl_key_ids,
                                                       _Inout_ uint32_t   *flex_acl_key_ids_num,
                                                       _Inout_ uint32_t   *custom_bytes_num)
{
    assert(flex_acl_key_ids);
    assert(flex_acl_key_ids_num);
    assert(custom_bytes_num);

    flex_acl_key_ids[*flex_acl_key_ids_num] = udf_db_group_ptr(udf_group_db_index)->sx_custom_bytes_keys[0];
    ++(*flex_acl_key_ids_num);
    *custom_bytes_num += udf_db_group_ptr(udf_group_db_index)->length;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_db_index_to_sx_acl_keys(_In_ uint32_t       udf_group_db_index,
                                                    _Out_ sx_acl_key_t *flex_acl_key_ids,
                                                    _Inout_ uint32_t   *flex_acl_key_ids_num,
                                                    _Inout_ uint32_t   *custom_bytes_num)
{
    assert(flex_acl_key_ids);
    assert(flex_acl_key_ids_num);
    assert(custom_bytes_num);
    assert(mlnx_udf_cb);
    assert(udf_db_group_ptr(udf_group_db_index)->is_created);
    assert(udf_db_group_ptr(udf_group_db_index)->is_sx_custom_bytes_created);

    mlnx_udf_cb->flex_acl_key_ids_copy(udf_group_db_index, flex_acl_key_ids, flex_acl_key_ids_num, custom_bytes_num);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_length_get(_In_ uint32_t udf_group_db_index, _Out_ uint32_t *size)
{
    assert(NULL != size);
    assert(udf_db_group_ptr(udf_group_db_index)->is_created);

    *size = udf_db_group_ptr(udf_group_db_index)->length;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_flex_acl_key_to_ecmp_hash_field_spc(_In_ sx_acl_key_t                  flex_acl_key_id,
                                                                 _Out_ sx_router_ecmp_hash_field_t *ecmp_hash_field)
{
    int32_t      general_fields_range = 0;
    sx_acl_key_t last_hash_allowed_acl_key = FLEX_ACL_KEY_CUSTOM_BYTES_START;

    assert(NULL != ecmp_hash_field);

    general_fields_range =
        (SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_CUSTOM_BYTE_LAST - SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_CUSTOM_BYTE_0);
    assert(general_fields_range >= 0);
    last_hash_allowed_acl_key = FLEX_ACL_KEY_CUSTOM_BYTES_START + general_fields_range;

    if ((flex_acl_key_id < FLEX_ACL_KEY_CUSTOM_BYTES_START) || (last_hash_allowed_acl_key < flex_acl_key_id)) {
        SX_LOG_ERR("Invalid sx_acl_key_t for custom byte - %d\n", flex_acl_key_id);
        return SAI_STATUS_FAILURE;
    }

    *ecmp_hash_field = flex_acl_key_id - FLEX_ACL_KEY_CUSTOM_BYTES_START +
                       SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_CUSTOM_BYTE_0;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_custom_bytes_to_ecmp_hash_fields_spc(
    _In_ uint32_t                        flex_acl_keys_num,
    _In_ uint32_t                        custom_bytes_num,
    _In_ const sx_acl_key_t             *flex_acl_key_ids,
    _Inout_ sx_router_ecmp_hash_field_t *ecmp_hash_fields,
    _In_ uint32_t                        ecmp_hash_fields_idx)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii = 0;
    uint32_t     jj = ecmp_hash_fields_idx;

    assert(flex_acl_key_ids);
    assert(ecmp_hash_fields);

    for (ii = 0; ii < flex_acl_keys_num; ++ii, ++jj) {
        status = mlnx_udf_flex_acl_key_to_ecmp_hash_field_spc(flex_acl_key_ids[ii], &ecmp_hash_fields[jj]);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    return status;
}

static sai_status_t mlnx_udf_custom_bytes_to_ecmp_hash_fields_spc2(
    _In_ uint32_t                        flex_acl_keys_num,
    _In_ uint32_t                        custom_bytes_num,
    _In_ const sx_acl_key_t             *flex_acl_key_ids,
    _Inout_ sx_router_ecmp_hash_field_t *ecmp_hash_fields,
    _In_ uint32_t                        ecmp_hash_fields_idx)
{
    sai_status_t                status = SAI_STATUS_SUCCESS;
    int32_t                     general_fields_range = 0;
    sx_acl_key_t                last_hash_allowed_acl_key = FLEX_ACL_KEY_GP_REGISTER_0;
    sx_router_ecmp_hash_field_t ecmp_hash_field = SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_GP_REGISTER_LAST;

    assert(flex_acl_key_ids);
    assert(ecmp_hash_fields);

    general_fields_range = SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_GP_REGISTER_LAST -
                           SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_GP_REGISTER_0_BYTE_0;
    assert(general_fields_range >= 0);
    last_hash_allowed_acl_key = FLEX_ACL_KEY_GP_REGISTER_0 + (general_fields_range / 2);

    if ((flex_acl_key_ids[0] < FLEX_ACL_KEY_GP_REGISTER_0) || (last_hash_allowed_acl_key < flex_acl_key_ids[0])) {
        SX_LOG_ERR("Invalid sx_acl_key_t \n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    ecmp_hash_field = (flex_acl_key_ids[0] - FLEX_ACL_KEY_GP_REGISTER_START) * 2 +
                      SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_GP_REGISTER_0_BYTE_0;

    ecmp_hash_fields[ecmp_hash_fields_idx++] = ecmp_hash_field;
    if (custom_bytes_num > 1) {
        ecmp_hash_fields[ecmp_hash_fields_idx] = ++ecmp_hash_field;
    }

out:
    return status;
}

sai_status_t mlnx_udf_group_mask_to_ecmp_hash_fields(_In_ udf_group_mask_t              udf_group_mask,
                                                     _Out_ sx_router_ecmp_hash_field_t *ecmp_hash_fields,
                                                     _Out_ uint32_t                    *ecmp_hash_field_count)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    uint32_t       sx_custom_bytes_count = 0;
    sai_u32_list_t udf_groups_db_indexes = (sai_u32_list_t) {.list = NULL};
    uint32_t       custom_bytes_num = 0;
    uint32_t       flex_acl_key_ids_num = 0;
    sx_acl_key_t   flex_acl_key_ids[10] = {0};
    uint32_t       ii = 0;

    assert(NULL != ecmp_hash_fields);
    assert(NULL != ecmp_hash_field_count);

    status = mlnx_udf_group_mask_to_indexes(udf_group_mask, &udf_groups_db_indexes);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (ii = 0; ii < udf_groups_db_indexes.count; ii++) {
        custom_bytes_num = 0;
        flex_acl_key_ids_num = 0;

        status = mlnx_udf_group_db_index_to_sx_acl_keys
                     (udf_groups_db_indexes.list[ii], flex_acl_key_ids, &flex_acl_key_ids_num, &custom_bytes_num);
        if (SAI_ERR(status)) {
            goto out;
        }

        assert(mlnx_udf_cb);
        status = mlnx_udf_cb->custom_bytes_to_ecmp_hash_fields
                     (flex_acl_key_ids_num, custom_bytes_num, flex_acl_key_ids, ecmp_hash_fields,
                     sx_custom_bytes_count);
        if (SAI_ERR(status)) {
            goto out;
        }

        sx_custom_bytes_count += custom_bytes_num;
    }

    *ecmp_hash_field_count = sx_custom_bytes_count;

out:
    safe_free(udf_groups_db_indexes.list);
    return status;
}

static sai_status_t mlnx_udf_group_db_index_references_set(_In_ uint32_t udf_group_db_index, _In_ bool add_reference)
{
    if (add_reference) {
        udf_db_group_ptr(udf_group_db_index)->refs++;
    } else {
        if (0 == udf_db_group_ptr(udf_group_db_index)->refs) {
            SX_LOG_ERR("Failed to remove reference to UDF Group (%lx)\n",
                       udf_db_group_ptr(udf_group_db_index)->sai_object);
            return SAI_STATUS_FAILURE;
        }

        udf_db_group_ptr(udf_group_db_index)->refs--;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_group_mask_references_set(_In_ udf_group_mask_t udf_group_mask, _In_ bool add_reference)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sai_u32_list_t udf_groups_db_indexes = (sai_u32_list_t) {.list = NULL};
    uint32_t       ii;

    if (MLNX_UDF_GROUP_MASK_EMPTY == udf_group_mask) {
        goto out;
    }

    status = mlnx_udf_group_mask_to_indexes(udf_group_mask, &udf_groups_db_indexes);
    if (SAI_ERR(status)) {
        return status;
    }

    for (ii = 0; ii < udf_groups_db_indexes.count; ii++) {
        status = mlnx_udf_group_db_index_references_set(udf_groups_db_indexes.list[ii], add_reference);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    free(udf_groups_db_indexes.list);
    return status;
}

static sai_status_t mlnx_acl_udf_group_list_references_set(_In_ const acl_udf_group_list_t udf_group_list,
                                                           _In_ bool                       add_reference)
{
    sai_status_t status;
    uint32_t     ii;

    for (ii = 0; ii < ACL_UDF_GROUP_COUNT_MAX; ii++) {
        if (udf_group_list[ii].is_set) {
            status = mlnx_udf_group_db_index_references_set(udf_group_list[ii].udf_group_db_index, add_reference);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_mask_references_add(_In_ udf_group_mask_t udf_group_mask)
{
    return mlnx_udf_group_mask_references_set(udf_group_mask, true);
}

sai_status_t mlnx_udf_group_mask_references_del(_In_ udf_group_mask_t udf_group_mask)
{
    return mlnx_udf_group_mask_references_set(udf_group_mask, false);
}

sai_status_t mlnx_acl_udf_group_list_references_add(_In_ const acl_udf_group_list_t udf_group_list)
{
    return mlnx_acl_udf_group_list_references_set(udf_group_list, true);
}

sai_status_t mlnx_acl_udf_group_list_references_del(_In_ const acl_udf_group_list_t udf_group_list)
{
    return mlnx_acl_udf_group_list_references_set(udf_group_list, false);
}

static sai_status_t mlnx_udf_oid_validate_and_fetch(_In_ sai_object_id_t   udf_id,
                                                    _In_ sai_object_type_t udf_type,
                                                    _In_ uint32_t          attr_index,
                                                    _Out_ uint32_t        *db_index)
{
    sai_status_t status;
    uint32_t     db_size;

    assert(NULL != db_index);
    assert((SAI_OBJECT_TYPE_UDF == udf_type) ||
           (SAI_OBJECT_TYPE_UDF_GROUP == udf_type) ||
           (SAI_OBJECT_TYPE_UDF_MATCH == udf_type));

    status = mlnx_object_to_type(udf_id, udf_type, db_index, NULL);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    status = mlnx_udf_db_size_get(udf_type, &db_size);
    if (SAI_ERR(status)) {
        return status;
    }

    if (db_size <= *db_index) {
        SX_LOG_ERR("Invalid %s db index - %d\n", SAI_TYPE_STR(udf_type), *db_index);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if (false == mlnx_udf_db_is_created(*db_index, udf_type)) {
        SX_LOG_ERR("%s object [%lx] is deleted or not created\n", SAI_TYPE_STR(udf_type), udf_id);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_hash_mask_validate(_In_ const sai_u8_list_t *hash_mask,
                                                _In_ uint32_t             attr_index,
                                                _In_ uint32_t             group_db_index)
{
    uint32_t group_length, ii;

    assert(NULL != hash_mask);

    group_length = udf_db_group_ptr(group_db_index)->length;

    if (hash_mask->count != group_length) {
        SX_LOG_ERR("Invalid hash mask size - %d, must be %d\n", hash_mask->count, group_length);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    for (ii = 0; ii < hash_mask->count; ii++) {
        if (hash_mask->list[ii] != 0xFF) {
            SX_LOG_ERR("Invalid value for hash mask (%x) the only valid one is 0xFF\n", hash_mask->list[ii]);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_base_validate(_In_ sai_udf_base_t base,
                                           _In_ uint32_t       attr_index,
                                           _In_ uint32_t       match_db_index)
{
    mlnx_udf_match_type_t udf_match_type;

    if (SAI_UDF_BASE_L4 < base) {
        SX_LOG_ERR("Invalid value for base (%d)\n", base);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if (SAI_UDF_BASE_L4 == base) {
        SX_LOG_ERR("SAI_UDF_BASE_L4 is not supported\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    udf_match_type = udf_db_match(match_db_index).type;

    if ((MLNX_UDF_MATCH_TYPE_EMPTY == udf_match_type) && (SAI_UDF_BASE_L2 != base)) {
        SX_LOG_ERR("Unsupported combination of UDF Match and UDF Base - "
                   "Empty UDF Match can only be used with SAI_UDF_BASE_L2\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if ((MLNX_UDF_MATCH_TYPE_EMPTY != udf_match_type) && (SAI_UDF_BASE_L3 != base)) {
        SX_LOG_ERR("Unsupported combination of UDF Match and UDF Base - "
                   "L2 UDF Match can only be used with SAI_UDF_BASE_L3\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_group_sx_custom_bytes_remove(_In_ uint32_t group_db_index)
{
    sai_status_t                         status;
    sx_acl_custom_bytes_set_attributes_t sx_custom_bytes_attrs;
    sx_acl_key_t                        *sx_keys;
    uint32_t                             bytes_count;

    assert(udf_db_group_ptr(group_db_index)->is_created);
    assert(udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created);
    assert(0 == udf_db_group_udfs_ptr(group_db_index)->count);

    memset(&sx_custom_bytes_attrs, 0, sizeof(sx_custom_bytes_attrs));

    sx_keys = udf_db_group_ptr(group_db_index)->sx_custom_bytes_keys;
    bytes_count = udf_db_group_ptr(group_db_index)->length;

    status = mlnx_custom_bytes_set(SX_ACCESS_CMD_DESTROY, &sx_custom_bytes_attrs, sx_keys, bytes_count);
    if (SAI_ERR(status)) {
        return status;
    }

    memset(sx_keys, 0, sizeof(sx_keys[0]) * MLNX_UDF_GROUP_LENGTH_MAX);

    udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created = false;

    SX_LOG_NTC("Removed the Custom Bytes Set for UDF Group %lx\n", udf_db_group_ptr(group_db_index)->sai_object);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_group_sx_custom_bytes_create_or_update(_In_ uint32_t group_db_index)
{
    sai_status_t                         status;
    sx_acl_custom_bytes_set_attributes_t sx_custom_bytes_attrs;
    sx_acl_key_t                        *sx_keys;
    sx_access_cmd_t                      sx_custom_bytes_cmd;
    mlnx_udf_match_type_t                udf_match_type;
    uint32_t                             udf_count, bytes_count, ii;
    uint32_t                             udf_offset, udf_db_index, udf_match_db_index;
    bool                                 sx_custom_bytes_created;

    assert(udf_db_group_ptr(group_db_index)->is_created);
    assert(udf_db_group_udfs_ptr(group_db_index)->count > 0);

    memset(&sx_custom_bytes_attrs, 0, sizeof(sx_custom_bytes_attrs));

    udf_count = udf_db_group_udfs_ptr(group_db_index)->count;
    sx_custom_bytes_created = udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created;

    for (ii = 0; ii < udf_count; ii++) {
        udf_db_index = udf_db_group_udfs_ptr(group_db_index)->udf_indexes[ii];
        udf_offset = udf_db_udf(udf_db_index).offset;
        udf_match_db_index = udf_db_udf(udf_db_index).match_index;
        udf_match_type = udf_db_match(udf_match_db_index).type;

        switch (udf_match_type) {
        case MLNX_UDF_MATCH_TYPE_EMPTY:
            sx_custom_bytes_attrs.extraction_point.extraction_group_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_GROUP_L2;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l2_group.extraction_l2.extraction_point_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_POINT_TYPE_L2_START_OF_HEADER;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l2_group.extraction_l2.offset = udf_offset;

            assert(1 == udf_db_group_udfs_ptr(group_db_index)->count);
            break;

        case MLNX_UDF_MATCH_TYPE_ARP:
            sx_custom_bytes_attrs.extraction_point.extraction_group_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_GROUP_L3;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_arp.extraction_point_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_POINT_TYPE_ARP_START_OF_HEADER;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_arp.offset = udf_offset;
            break;

        case MLNX_UDF_MATCH_TYPE_IPv4:
            sx_custom_bytes_attrs.extraction_point.extraction_group_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_GROUP_L3;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_ipv4.extraction_point_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_POINT_TYPE_IPV4_START_OF_HEADER;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_ipv4.offset = udf_offset;
            break;

        case MLNX_UDF_MATCH_TYPE_IPv6:
            sx_custom_bytes_attrs.extraction_point.extraction_group_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_GROUP_L3;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_ipv6.extraction_point_type =
                SX_ACL_CUSTOM_BYTES_EXTRACTION_POINT_TYPE_IPV6_START_OF_HEADER;
            sx_custom_bytes_attrs.extraction_point.params.extraction_l3_group.extraction_ipv6.offset = udf_offset;
            break;

        default:
            SX_LOG_ERR("Unexpected type of udf match (%d)\n", udf_match_type);
            return SAI_STATUS_FAILURE;
        }
    }

    sx_keys = udf_db_group_ptr(group_db_index)->sx_custom_bytes_keys;
    bytes_count = udf_db_group_ptr(group_db_index)->length;

    if (!sx_custom_bytes_created) {
        assert(udf_count == 1);
        sx_custom_bytes_cmd = SX_ACCESS_CMD_CREATE;
    } else {
        sx_custom_bytes_cmd = SX_ACCESS_CMD_EDIT;
    }

    status = mlnx_custom_bytes_set(sx_custom_bytes_cmd, &sx_custom_bytes_attrs, sx_keys, bytes_count);
    if (SAI_ERR(status)) {
        return status;
    }

    udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created = true;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_group_update(_In_ uint32_t group_db_index)
{
    sai_status_t status;
    uint32_t     udf_count;

    assert(mlnx_udf_cb);
    assert(udf_db_group_ptr(group_db_index)->is_created);

    udf_count = udf_db_group_udfs_ptr(group_db_index)->count;

    if (0 == udf_count) {
        status = mlnx_udf_cb->flex_acl_key_ids_del(group_db_index);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = mlnx_udf_cb->flex_acl_key_ids_add(group_db_index);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_group_add_udf(_In_ uint32_t group_db_index, _In_ uint32_t udf_db_index)
{
    sai_status_t          status;
    sai_udf_base_t        group_member_udf_base, udf_base;
    mlnx_udf_match_type_t group_member_udf_match_type, udf_match_type;
    uint32_t              udf_match_db_index;
    uint32_t              group_size, group_udf_db_index, group_udf_match_index, ii;

    if (udf_db_group_ptr(group_db_index)->refs > 0) {
        SX_LOG_ERR("Failed to add UDF to UDF Group - UDF Group is in use\n");
        return SAI_STATUS_OBJECT_IN_USE;
    }

    group_size = udf_db_group_udfs_ptr(group_db_index)->count;

    if (group_size == MLNX_UDF_GROUP_SIZE_MAX) {
        SX_LOG_ERR("Failed to add a udf to group[%d] - group is full\n", group_db_index);
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    udf_base = udf_db_udf(udf_db_index).base;
    udf_match_db_index = udf_db_udf(udf_db_index).match_index;

    if (0 != group_size) {
        group_udf_db_index = udf_db_group_udfs_ptr(group_db_index)->udf_indexes[0];
        group_member_udf_base = udf_db_udf(group_udf_db_index).base;

        if (SAI_UDF_BASE_L2 == group_member_udf_base) {
            SX_LOG_ERR("Failed to add a udf to group[%d] - "
                       "The max size of UDF group that contains a UDF with base L2 is 1 (group is full)\n",
                       group_udf_db_index);
            return SAI_STATUS_NOT_SUPPORTED;
        } else {
            if (SAI_UDF_BASE_L3 != udf_base) {
                SX_LOG_ERR("Failed to add a udf to group[%d] - "
                           "This group can only contain a UDFs with SAI_UDF_BASE_L3\n", group_udf_db_index);
                return SAI_STATUS_NOT_SUPPORTED;
            }

            udf_match_type = udf_db_match(udf_match_db_index).type;

            for (ii = 0; ii < udf_db_group_udfs_ptr(group_db_index)->count; ii++) {
                group_udf_db_index = udf_db_group_udfs_ptr(group_db_index)->udf_indexes[ii];
                group_udf_match_index = udf_db_udf(group_udf_db_index).match_index;
                group_member_udf_match_type = udf_db_match(group_udf_match_index).type;

                if (group_member_udf_match_type == udf_match_type) {
                    SX_LOG_ERR("Failed to add a udf to group[%d] - "
                               "Group can only contain the UDFs with different UDF Matches\n", group_udf_db_index);
                    return SAI_STATUS_NOT_SUPPORTED;
                }
            }

            assert(udf_db_group_udfs_ptr(group_db_index)->count < MLNX_UDF_GROUP_SIZE_MAX);
        }
    }

    udf_db_group_udfs_ptr(group_db_index)->udf_indexes[group_size] = udf_db_index;
    udf_db_group_udfs_ptr(group_db_index)->count++;

    status = mlnx_udf_group_update(group_db_index);
    if (SAI_ERR(status)) {
        udf_db_group_udfs_ptr(group_db_index)->count--;
        return status;
    }

    udf_db_udf(udf_db_index).group_index = group_db_index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_group_remove_udf(_In_ uint32_t udf_db_index)
{
    sai_status_t      status;
    mlnx_udf_group_t *udf_group;
    mlnx_udf_list_t  *group_udfs;
    uint32_t          udf_group_db_index, ii;

    udf_group_db_index = udf_db_udf(udf_db_index).group_index;
    udf_group = udf_db_group_ptr(udf_group_db_index);
    group_udfs = udf_db_group_udfs_ptr(udf_group_db_index);

    if (udf_group->refs > 0) {
        SX_LOG_ERR("Failed to remove UDF from UDF Group - UDF Group is in use\n");
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if ((udf_group->refs > 0) && (group_udfs->count == 1)) {
        SX_LOG_ERR("Failed to remove the last UDF (%lx) from a UDF Group (%lx) - UDF Group is in use\n",
                   udf_db_udf(udf_db_index).sai_object, udf_db_group_ptr(udf_group_db_index)->sai_object);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    for (ii = 0; ii < group_udfs->count; ii++) {
        if (udf_db_index == group_udfs->udf_indexes[ii]) {
            break;
        }
    }

    if (ii == group_udfs->count) {
        SX_LOG_ERR("Failed to remove UDF (%lx) from a UDF Group (%lx) - UDF is not in a Group\n",
                   udf_db_udf(udf_db_index).sai_object, udf_db_group_ptr(udf_group_db_index)->sai_object);
        return SAI_STATUS_FAILURE;
    }

    group_udfs->udf_indexes[ii] = group_udfs->udf_indexes[group_udfs->count - 1];
    group_udfs->count--;

    status = mlnx_udf_group_update(udf_group_db_index);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_remove_udf_match(_In_ uint32_t udf_db_index)
{
    uint32_t udf_match_db_index;

    udf_match_db_index = udf_db_udf(udf_db_index).match_index;

    if (0 == udf_db_match(udf_match_db_index).refs) {
        SX_LOG_ERR("Failed to remove a UDF's (%lx) UDF Match (%lx) - UDF Match has no references\n",
                   udf_db_udf(udf_db_index).sai_object, udf_db_match(udf_match_db_index).sai_object);
        return SAI_STATUS_FAILURE;
    }

    udf_db_match(udf_match_db_index).refs--;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_udf_attrib_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sai_udf_attr_t attr;
    uint32_t       udf_db_index, group_db_index, match_db_index, udf_length, ii;

    SX_LOG_ENTER();

    attr = (int64_t)(arg);

    sai_db_read_lock();

    status = mlnx_udf_oid_validate_and_fetch(key->key.object_id, SAI_OBJECT_TYPE_UDF, 0, &udf_db_index);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    group_db_index = udf_db_udf(udf_db_index).group_index;
    match_db_index = udf_db_udf(udf_db_index).match_index;

    switch (attr) {
    case SAI_UDF_ATTR_GROUP_ID:
        value->oid = udf_db_group_ptr(group_db_index)->sai_object;
        break;

    case SAI_UDF_ATTR_MATCH_ID:
        value->oid = udf_db_match(match_db_index).sai_object;
        break;

    case SAI_UDF_ATTR_BASE:
        value->s32 = udf_db_udf(udf_db_index).base;
        break;

    case SAI_UDF_ATTR_OFFSET:
        value->u16 = udf_db_udf(udf_db_index).offset;
        break;

    case SAI_UDF_ATTR_HASH_MASK:
        udf_length = udf_db_group_ptr(group_db_index)->length;

        status = mlnx_attribute_value_list_size_check(&value->u8list.count, udf_length);
        if (SAI_ERR(status)) {
            goto out;
        }

        for (ii = 0; ii < udf_length; ii++) {
            value->u8list.list[ii] = 0xFF;
        }

        break;

    default:
        SX_LOG_ERR("Unexpected type of UDF ATTR - %d\n", attr);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_udf_match_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t         status = SAI_STATUS_SUCCESS;
    uint32_t             match_db_index;
    sai_udf_match_attr_t attr;

    SX_LOG_ENTER();

    attr = (int64_t)(arg);

    sai_db_read_lock();

    status = mlnx_udf_oid_validate_and_fetch(key->key.object_id, SAI_OBJECT_TYPE_UDF_MATCH, 0, &match_db_index);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    switch (attr) {
    case SAI_UDF_MATCH_ATTR_L2_TYPE:
        status = mlnx_udf_match_type_to_l2(udf_db_match(match_db_index).type, &value->aclfield);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    case SAI_UDF_MATCH_ATTR_L3_TYPE:
    case SAI_UDF_MATCH_ATTR_GRE_TYPE:
        value->aclfield.enable = false;
        value->aclfield.data.u16 = 0x0;
        value->aclfield.mask.u16 = 0x0;
        break;

    case SAI_UDF_MATCH_ATTR_PRIORITY:
        value->s32 = udf_db_match(match_db_index).priority;
        break;

    default:
        SX_LOG_ERR("Unexpected type of UDF Match ATTR - %d\n", attr);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_udf_group_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t           status = SAI_STATUS_SUCCESS;
    const mlnx_udf_list_t *udfs;
    uint32_t               group_db_index, ii;
    sai_udf_group_attr_t   attr;

    SX_LOG_ENTER();

    attr = (int64_t)(arg);

    sai_db_read_lock();

    status = mlnx_udf_oid_validate_and_fetch(key->key.object_id, SAI_OBJECT_TYPE_UDF_GROUP, 0, &group_db_index);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    switch (attr) {
    case SAI_UDF_GROUP_ATTR_UDF_LIST:
        udfs = udf_db_group_udfs_ptr(group_db_index);

        status = mlnx_attribute_value_list_size_check(&value->objlist.count, udfs->count);
        if (SAI_ERR(status)) {
            goto out;
        }

        for (ii = 0; ii < udfs->count; ii++) {
            value->objlist.list[ii] = udf_db_udf(udfs->udf_indexes[ii]).sai_object;
        }
        break;

    case SAI_UDF_GROUP_ATTR_TYPE:
        value->s32 = udf_db_group_ptr(group_db_index)->type;
        break;

    case SAI_UDF_GROUP_ATTR_LENGTH:
        value->u32 = udf_db_group_ptr(group_db_index)->length;
        break;

    default:
        SX_LOG_ERR("Unexpected type of UDF Group ATTR - %d\n", attr);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_udf_attrib_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    uint32_t       udf_db_index;
    sai_udf_attr_t attr;

    attr = (int64_t)(arg);

    sai_db_read_lock();

    status = mlnx_udf_oid_validate_and_fetch(key->key.object_id, SAI_OBJECT_TYPE_UDF, 0, &udf_db_index);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    switch (attr) {
    case SAI_UDF_ATTR_HASH_MASK:
        status = mlnx_udf_hash_mask_validate(&value->u8list, 0, udf_db_udf(udf_db_index).group_index);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected type of UDF ATTR - %d\n", attr);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Create UDF
 *
 * @param[out] udf_id UDF id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_create_udf(_Out_ sai_object_id_t      *udf_id,
                                        _In_ sai_object_id_t        switch_id,
                                        _In_ uint32_t               attr_count,
                                        _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *attr_match_id, *attr_group_id, *attr_base, *attr_offset, *attr_hash_mask;
    sai_udf_base_t               udf_base;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                         key_str[MAX_KEY_STR_LEN] = {0};
    uint32_t                     group_db_index, match_db_index, udf_offset, udf_db_index, attr_index;

    SX_LOG_ENTER();

    if (NULL == udf_id) {
        SX_LOG_ERR("NULL udf id param.\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count,
                                    attr_list,
                                    SAI_OBJECT_TYPE_UDF,
                                    udf_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check.\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_UDF, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create udf object.\n");
    SX_LOG_NTC("Attribs %s.\n", list_str);

    sai_db_write_lock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_ATTR_MATCH_ID,
                                 &attr_match_id, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_udf_oid_validate_and_fetch(attr_match_id->oid, SAI_OBJECT_TYPE_UDF_MATCH,
                                             attr_index, &match_db_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_ATTR_GROUP_ID,
                                 &attr_group_id, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_udf_oid_validate_and_fetch(attr_group_id->oid, SAI_OBJECT_TYPE_UDF_GROUP,
                                             attr_index, &group_db_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_base = SAI_UDF_BASE_L2;

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_ATTR_BASE,
                                 &attr_base, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        udf_base = attr_base->s32;
    }

    status = mlnx_udf_base_validate(udf_base, attr_index, match_db_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_ATTR_OFFSET,
                                 &attr_offset, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    udf_offset = attr_offset->u16;

    if (MLNX_UDF_OFFSET_MAX < udf_offset) {
        SX_LOG_ERR("Invalid value for offset (%d), the maximum offset is (%d)\n", udf_offset, MLNX_UDF_OFFSET_MAX);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out_unlock;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_ATTR_HASH_MASK,
                                 &attr_hash_mask, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_udf_hash_mask_validate(&attr_hash_mask->u8list, attr_index, group_db_index);
        if (SAI_ERR(status)) {
            goto out_unlock;
        }
    }

    status = mlnx_udf_db_find_free_index(SAI_OBJECT_TYPE_UDF, &udf_db_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_db_udf(udf_db_index).base = udf_base;
    udf_db_udf(udf_db_index).offset = udf_offset;
    udf_db_udf(udf_db_index).match_index = match_db_index;

    status = mlnx_udf_group_add_udf(group_db_index, udf_db_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_db_match(match_db_index).refs++;

    udf_db_udf(udf_db_index).is_created = true;

    status = mlnx_create_object(SAI_OBJECT_TYPE_UDF, udf_db_index, NULL, udf_id);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_db_udf(udf_db_index).sai_object = *udf_id;

    udf_key_to_str(*udf_id, SAI_OBJECT_TYPE_UDF, key_str);
    SX_LOG_NTC("Created %s. Object id [%lx]\n", key_str, *udf_id);

out_unlock:
    sai_db_unlock();
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove UDF
 *
 * @param[in] udf_id UDF id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_remove_udf(_In_ sai_object_id_t udf_id)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     udf_db_index;
    char         key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    udf_key_to_str(udf_id, SAI_OBJECT_TYPE_UDF, key_str);
    SX_LOG_NTC("Remove %s.\n", key_str);

    sai_db_write_lock();

    if (g_sai_db_ptr->is_issu_gp_reg_restore) {
        SX_LOG_ERR("Failed to remove UDF object on issu flow");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = mlnx_udf_oid_validate_and_fetch(udf_id, SAI_OBJECT_TYPE_UDF, 0, &udf_db_index);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    status = mlnx_udf_group_remove_udf(udf_db_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_udf_remove_udf_match(udf_db_index);
    if (SAI_ERR(status)) {
        goto out;
    }

    memset(&udf_db_udf(udf_db_index), 0, sizeof(udf_db_udf(udf_db_index)));

    udf_db_udf(udf_db_index).is_created = false;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set UDF attribute
 *
 * @param[in] udf_id UDF id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_set_udf_attribute(_In_ sai_object_id_t udf_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = udf_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    udf_key_to_str(udf_id, SAI_OBJECT_TYPE_UDF, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_UDF, udf_vendor_attribs, attr);
}

/**
 * @brief Get UDF attribute value
 *
 * @param[in] udf_id UDF id
 * @param[in] attr_count number of attributes
 * @param[inout] attrs -rray of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_get_udf_attribute(_In_ sai_object_id_t     udf_id,
                                               _In_ uint32_t            attr_count,
                                               _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = udf_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    udf_key_to_str(udf_id, SAI_OBJECT_TYPE_UDF, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_UDF, udf_vendor_attribs, attr_count, attr_list);
}

/**
 * @brief Create UDF match
 *
 * @param[out] udf_match_id UDF match id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_create_udf_match(_Out_ sai_object_id_t      *udf_match_id,
                                              _In_ sai_object_id_t        switch_id,
                                              _In_ uint32_t               attr_count,
                                              _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *l2_type_attr, *l3_type_attr, *gre_type_attr, *prio_attr;
    mlnx_udf_match_type_t        match_type;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                         key_str[MAX_KEY_STR_LEN] = {0};
    uint32_t                     attr_index, db_index;
    uint8_t                      match_prio;

    SX_LOG_ENTER();

    if (NULL == udf_match_id) {
        SX_LOG_ERR("NULL udf match id param.\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_UDF_MATCH, udf_match_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check.\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_UDF_MATCH, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create udf match object.\n");
    SX_LOG_NTC("Attribs %s.\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_MATCH_ATTR_GRE_TYPE,
                                 &gre_type_attr, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        SX_LOG_ERR("SAI_UDF_MATCH_ATTR_GRE_TYPE is not supported\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_MATCH_ATTR_L3_TYPE,
                                 &l3_type_attr, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        SX_LOG_ERR("SAI_UDF_MATCH_ATTR_L3_TYPE is not supported\n");
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    match_type = MLNX_UDF_MATCH_TYPE_EMPTY;

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_MATCH_ATTR_L2_TYPE,
                                 &l2_type_attr, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_udf_match_l2_type_convert(&l2_type_attr->aclfield, attr_index, &match_type);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    match_prio = UDF_MATCH_DEF_PRIO;

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_MATCH_ATTR_PRIORITY,
                                 &prio_attr, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        match_prio = prio_attr->u8;
    }

    sai_db_write_lock();

    status = mlnx_udf_match_type_is_not_created(match_type);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    status = mlnx_udf_db_find_free_index(SAI_OBJECT_TYPE_UDF_MATCH, &db_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_db_match(db_index).priority = match_prio;
    udf_db_match(db_index).type = match_type;
    udf_db_match(db_index).refs = 0;
    udf_db_match(db_index).is_created = true;

    status = mlnx_create_object(SAI_OBJECT_TYPE_UDF_MATCH, db_index, NULL, udf_match_id);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_db_match(db_index).sai_object = *udf_match_id;

    udf_key_to_str(*udf_match_id, SAI_OBJECT_TYPE_UDF_MATCH, key_str);
    SX_LOG_NTC("Created %s. Object id [%lx]\n", key_str, *udf_match_id);

out_unlock:
    sai_db_unlock();
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove UDF match
 *
 * @param[in] udf_match_id UDF match id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_remove_udf_match(_In_ sai_object_id_t udf_match_id)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     match_db_index;
    char         key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    udf_key_to_str(udf_match_id, SAI_OBJECT_TYPE_UDF_MATCH, key_str);
    SX_LOG_NTC("Remove %s.\n", key_str);

    sai_db_write_lock();

    status = mlnx_udf_oid_validate_and_fetch(udf_match_id, SAI_OBJECT_TYPE_UDF_MATCH, 0, &match_db_index);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    if (udf_db_match(match_db_index).refs > 0) {
        SX_LOG_ERR("Failed to remove UDF Match (%lx) - Object is in use\n", udf_db_match(match_db_index).sai_object);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    memset(&udf_db_match(match_db_index), 0, sizeof(udf_db_match(match_db_index)));
    udf_db_match(match_db_index).is_created = false;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set UDF match attribute
 *
 * @param[in] udf_match_id UDF match id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_set_udf_match_attribute(_In_ sai_object_id_t        udf_match_id,
                                                     _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = udf_match_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    udf_key_to_str(udf_match_id, SAI_OBJECT_TYPE_UDF_MATCH, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_UDF_MATCH, udf_match_vendor_attribs, attr);
}

/**
 * @brief Get UDF match attribute value
 *
 * @param[in] udf_match_id UDF match id
 * @param[in] attr_count Number of attributes
 * @param[inout] attrs Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_get_udf_match_attribute(_In_ sai_object_id_t     udf_match_id,
                                                     _In_ uint32_t            attr_count,
                                                     _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = udf_match_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    udf_key_to_str(udf_match_id, SAI_OBJECT_TYPE_UDF_MATCH, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_UDF_MATCH, udf_match_vendor_attribs, attr_count,
                              attr_list);
}

/**
 * @brief Create UDF group
 *
 * @param[out] udf_group_id UDF group id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_create_udf_group(_Out_ sai_object_id_t      *udf_group_id,
                                              _In_ sai_object_id_t        switch_id,
                                              _In_ uint32_t               attr_count,
                                              _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *attr_group_type, *attr_group_length;
    sai_udf_group_type_t         group_type;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                         key_str[MAX_KEY_STR_LEN] = {0};
    uint32_t                     group_lengh, db_index, attr_index;

    SX_LOG_ENTER();

    if (NULL == udf_group_id) {
        SX_LOG_ERR("NULL udf group id param.\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_UDF_GROUP, udf_group_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check.\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_UDF_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create udf group object.\n");
    SX_LOG_NTC("Attribs %s.\n", list_str);

    group_type = SAI_UDF_GROUP_TYPE_GENERIC;

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_GROUP_ATTR_TYPE,
                                 &attr_group_type, &attr_index);
    if (SAI_STATUS_SUCCESS == status) {
        group_type = attr_group_type->s32;
        if (group_type != SAI_UDF_GROUP_TYPE_GENERIC) {
            SX_LOG_ERR("Invalid value for group type (%d), the only valid value is GENERIC\n", group_type);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
            goto out;
        }
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_UDF_GROUP_ATTR_LENGTH,
                                 &attr_group_length, &attr_index);
    assert(SAI_STATUS_SUCCESS == status);

    group_lengh = attr_group_length->u16;

    if ((0 == group_lengh) || (MLNX_UDF_GROUP_LENGTH_MAX < group_lengh)) {
        SX_LOG_ERR("Invalid value for group length (%d), valid value is [1, %d]\n",
                   group_lengh,
                   MLNX_UDF_GROUP_LENGTH_MAX);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    sai_db_write_lock();

    status = mlnx_udf_db_find_free_index(SAI_OBJECT_TYPE_UDF_GROUP, &db_index);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_db_group_ptr(db_index)->type = group_type;
    udf_db_group_ptr(db_index)->length = group_lengh;
    udf_db_group_ptr(db_index)->refs = 0;
    udf_db_group_ptr(db_index)->is_created = true;
    udf_db_group_udfs_ptr(db_index)->count = 0;

    status = mlnx_create_object(SAI_OBJECT_TYPE_UDF_GROUP, db_index, NULL, udf_group_id);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    udf_db_group_ptr(db_index)->sai_object = *udf_group_id;

    udf_key_to_str(*udf_group_id, SAI_OBJECT_TYPE_UDF_GROUP, key_str);
    SX_LOG_NTC("Created %s. Object id [%lx]\n", key_str, *udf_group_id);

out_unlock:
    sai_db_unlock();
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove UDF group
 *
 * @param[in] udf_group_id UDF group id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_remove_udf_group(_In_ sai_object_id_t udf_group_id)
{
    sai_status_t      status;
    mlnx_udf_group_t *udf_group;
    mlnx_udf_list_t  *udf_group_udfs;
    uint32_t          group_db_index;
    char              key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    udf_key_to_str(udf_group_id, SAI_OBJECT_TYPE_UDF_GROUP, key_str);
    SX_LOG_NTC("Remove %s.\n", key_str);

    sai_db_write_lock();

    status = mlnx_udf_oid_validate_and_fetch(udf_group_id, SAI_OBJECT_TYPE_UDF_GROUP, 0, &group_db_index);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    udf_group = udf_db_group_ptr(group_db_index);
    udf_group_udfs = udf_db_group_udfs_ptr(group_db_index);

    if (udf_group->refs > 0) {
        SX_LOG_ERR("Failed to remove UDF Group (%lx) - Object is in use\n", udf_group->sai_object);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    if (udf_group_udfs->count > 0) {
        SX_LOG_ERR("Failed to remove UDF Group (%lx) - Group is not empty (UDFs count = %d)\n",
                   udf_group->sai_object, udf_group_udfs->count);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    udf_group->is_created = false;

    memset(udf_group, 0, MLNX_UDF_DB_UDF_GROUP_SIZE);
    memset(udf_group_udfs, 0, MLNX_UDF_DB_UDF_GROUP_UDFS_SIZE);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set UDF group attribute
 *
 * @param[in] udf_group_id UDF group id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_set_udf_group_attribute(_In_ sai_object_id_t        udf_group_id,
                                                     _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = udf_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    udf_key_to_str(udf_group_id, SAI_OBJECT_TYPE_UDF_GROUP, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_UDF_GROUP, udf_group_vendor_attribs, attr);
}

/**
 * @brief Get UDF group attribute value
 *
 * @param[in] udf_group_id UDF group id
 * @param[in] attr_count Number of attributes
 * @param[inout] attrs Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_sai_get_udf_group_attribute(_In_ sai_object_id_t     udf_group_id,
                                                     _In_ uint32_t            attr_count,
                                                     _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = udf_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    udf_key_to_str(udf_group_id, SAI_OBJECT_TYPE_UDF_GROUP, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_UDF_GROUP, udf_group_vendor_attribs, attr_count,
                              attr_list);
}

sai_status_t mlnx_udf_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_acl_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

sai_status_t mlnx_udf_cb_table_init(void)
{
    sx_chip_types_t chip_type = SX_CHIP_TYPE_UNKNOWN;

    chip_type = g_sai_db_ptr->sx_chip_type;

    switch (chip_type) {
    case SX_CHIP_TYPE_SPECTRUM:
    case SX_CHIP_TYPE_SPECTRUM_A1:
        mlnx_udf_cb = &mlnx_udf_cb_sp;
        break;

    case SX_CHIP_TYPE_SPECTRUM2:
        mlnx_udf_cb = &mlnx_udf_cb_sp2;
        break;

    case SX_CHIP_TYPE_SPECTRUM3:
        mlnx_udf_cb = &mlnx_udf_cb_sp2;
        break;

    default:
        MLNX_SAI_LOG_ERR("g_sai_db_ptr->sxd_chip_type = %s\n", SX_CHIP_TYPE_STR(chip_type));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_udf_group_sx_reg_ext_point_set_spc2(_In_ sx_access_cmd_t              cmd,
                                                      _In_ sx_gp_register_e             reg_id,
                                                      _In_ const sx_extraction_point_t *ext_point_list,
                                                      _In_ uint32_t                     ext_point_cnt)
{
    sai_status_t      sai_status = SAI_STATUS_SUCCESS;
    sx_status_t       sx_status = SX_STATUS_SUCCESS;
    sx_register_key_t register_key = {0};
    uint32_t          point_cnt = ext_point_cnt;

    assert(ext_point_list);
    assert(point_cnt > 0);
    assert((SX_ACCESS_CMD_SET == cmd) ||
           (SX_ACCESS_CMD_UNSET == cmd));

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_init_flex_parser())) {
        SX_LOG_ERR("Failed to init_flex_parser\n");
        goto out;
    }

    register_key.type = SX_REGISTER_KEY_TYPE_GENERAL_PURPOSE_E;
    register_key.key.gp_reg.reg_id = reg_id;

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_flex_parser_reg_ext_point_set
                         (gh_sdk, cmd, register_key, ext_point_list, &point_cnt))) {
        SX_LOG_ERR("Failed to %s extraction points for register %s.\n",
                   (SX_ACCESS_CMD_SET == cmd) ? "SET" : "UNSET",
                   SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    return sai_status;
}

static sai_status_t mlnx_udf_group_sx_reg_ext_points_get_spc2(_In_ sx_gp_register_e        reg_id,
                                                              _Out_ sx_extraction_point_t *ext_point_list,
                                                              _Out_ uint32_t              *ext_point_cnt)
{
    sai_status_t      sai_status = SAI_STATUS_SUCCESS;
    sx_status_t       sx_status = SX_STATUS_SUCCESS;
    sx_register_key_t register_key = {0};

    assert(ext_point_list);
    assert(ext_point_cnt);

    register_key.type = SX_REGISTER_KEY_TYPE_GENERAL_PURPOSE_E;
    register_key.key.gp_reg.reg_id = reg_id;

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_init_flex_parser())) {
        SX_LOG_ERR("Failed to init_flex_parser\n");
        goto out;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_flex_parser_reg_ext_point_get
                         (gh_sdk, register_key, ext_point_list, ext_point_cnt))) {
        SX_LOG_ERR("Failed to get extraction points for register %s.\n",
                   SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    return sai_status;
}

sai_status_t mlnx_udf_group_sx_gp_registers_create_destroy_spc2(_In_ sx_access_cmd_t         cmd,
                                                                _In_ const sx_gp_register_e *reg_ids,
                                                                _In_ uint32_t                reg_ids_count)
{
    sai_status_t      sai_status = SAI_STATUS_SUCCESS;
    sx_status_t       sx_status = SX_STATUS_SUCCESS;
    sx_register_key_t register_keys_list[10] = {0};
    uint32_t          ii = 0;

    assert(reg_ids);
    assert(reg_ids_count != 0);
    assert(reg_ids_count <= MLNX_UDF_GP_REG_COUNT);
    assert((SX_ACCESS_CMD_CREATE == cmd) ||
           (SX_ACCESS_CMD_DESTROY == cmd));

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_init_flex_parser())) {
        SX_LOG_ERR("Failed to init_flex_parser\n");
        goto out;
    }

    for (ii = 0; ii < reg_ids_count; ++ii) {
        register_keys_list[ii].type = SX_REGISTER_KEY_TYPE_GENERAL_PURPOSE_E;
        register_keys_list[ii].key.gp_reg.reg_id = reg_ids[ii];
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_register_set
                         (gh_sdk, cmd, register_keys_list, &reg_ids_count))) {
        SX_LOG_ERR("Failed to %s gp register %s.\n",
                   (SX_ACCESS_CMD_CREATE == cmd) ? "CREATE" : "DESTROY",
                   SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    return sai_status;
}

static sai_status_t mlnx_udf_group_match_type_to_extr_point_spc2(_In_ mlnx_udf_match_type_t        udf_match_type,
                                                                 _Out_ sx_extraction_point_type_e *sx_ext_point_type)
{
    sai_status_t               sai_status = SAI_STATUS_SUCCESS;
    sx_extraction_point_type_e sx_point_type = SX_EXTRACTION_POINT_TYPE_LAST_E;

    assert(sx_ext_point_type);

    switch (udf_match_type) {
    case MLNX_UDF_MATCH_TYPE_EMPTY:
        sx_point_type = SX_EXTRACTION_POINT_TYPE_L2_START_OF_HEADER_E;
        break;

    case MLNX_UDF_MATCH_TYPE_ARP:
        sx_point_type = SX_EXTRACTION_POINT_TYPE_ARP_START_OF_HEADER_E;
        break;

    case MLNX_UDF_MATCH_TYPE_IPv4:
        sx_point_type = SX_EXTRACTION_POINT_TYPE_IPV4_START_OF_HEADER_E;
        break;

    case MLNX_UDF_MATCH_TYPE_IPv6:
        sx_point_type = SX_EXTRACTION_POINT_TYPE_IPV6_START_OF_HEADER_E;
        break;

    default:
        SX_LOG_ERR("Unexpected type of udf match (%d)\n", udf_match_type);
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    *sx_ext_point_type = sx_point_type;
out:
    return sai_status;
}

static sai_status_t mlnx_udf_group_validate_match_type(_In_ mlnx_udf_match_type_t udf_match_type,
                                                       _In_ uint32_t              udf_count)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    if ((MLNX_UDF_MATCH_TYPE_EMPTY == udf_match_type) && (udf_count != 1)) {
        sai_status = SAI_STATUS_FAILURE;
    }

    return sai_status;
}

static sai_status_t mlnx_udf_group_construct_extr_point_list_from_db(_In_ uint32_t                group_db_index,
                                                                     _In_ uint32_t                udf_count,
                                                                     _Out_ sx_extraction_point_t *ext_point_list)
{
    sai_status_t               sai_status = SAI_STATUS_SUCCESS;
    uint32_t                   udf_db_index = 0;
    uint32_t                   ii = 0;
    uint32_t                   udf_offset = 0;
    uint32_t                   udf_match_db_index = 0;
    mlnx_udf_match_type_t      udf_match_type = MLNX_UDF_MATCH_TYPE_EMPTY;
    sx_extraction_point_type_e sx_ext_point_type = SX_EXTRACTION_POINT_TYPE_LAST_E;

    assert(ext_point_list);
    assert(MLNX_UDF_GROUP_SIZE_MAX >= udf_count);

    /* construct list of extraction points from internal db */
    for (ii = 0; ii < udf_count; ++ii) {
        udf_db_index = udf_db_group_udfs_ptr(group_db_index)->udf_indexes[ii];
        udf_offset = udf_db_udf(udf_db_index).offset;
        udf_match_db_index = udf_db_udf(udf_db_index).match_index;
        udf_match_type = udf_db_match(udf_match_db_index).type;

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_udf_group_validate_match_type
                              (udf_match_type, udf_count))) {
            goto out;
        }

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_udf_group_match_type_to_extr_point_spc2
                              (udf_match_type, &sx_ext_point_type))) {
            goto out;
        }

        ext_point_list[ii].type = sx_ext_point_type;
        ext_point_list[ii].offset = udf_offset;
    }

out:
    return sai_status;
}

static sai_status_t mlnx_udf_group_flex_acl_key_ids_add_spc2(_In_ uint32_t group_db_index)
{
    sai_status_t            sai_status = SAI_STATUS_SUCCESS;
    sx_acl_key_t           *sx_keys = NULL;
    mlnx_gp_reg_db_t       *reg_entry = NULL;
    mlnx_shm_rm_array_idx_t gp_reg_db_idx = {0};
    sx_gp_register_e        reg_id = SX_GP_REGISTER_LAST_E;
    uint32_t                ext_point_cnt = MLNX_EXT_POINT_MAX_NUM;
    sx_extraction_point_t   ext_point_list[MLNX_EXT_POINT_MAX_NUM] = {0};
    uint32_t                udf_count = 0;

    assert(udf_db_group_ptr(group_db_index)->is_created);
    assert(udf_db_group_udfs_ptr(group_db_index)->count > 0);

    sx_keys = udf_db_group_ptr(group_db_index)->sx_custom_bytes_keys;

    /* update flow */
    if (udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created) {
        assert(!(g_sai_db_ptr->is_issu_gp_reg_restore));

        reg_id = MLNX_FLEX_ACL_KEY_TO_SX_GP_REG(sx_keys[0]);
        assert(reg_id != SX_GP_REGISTER_LAST_E);

        /* get list of extraction points mapped to register key from SDK */
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_udf_group_sx_reg_ext_points_get_spc2
                              (reg_id, ext_point_list, &ext_point_cnt))) {
            goto out;
        }

        assert(ext_point_cnt > 0);

        /* unset list of extraction points from register key in SDK*/
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_udf_group_sx_reg_ext_point_set_spc2
                              (SX_ACCESS_CMD_UNSET, reg_id, ext_point_list, ext_point_cnt))) {
            goto out;
        }
    } else {
        /* creation flow */
        if (g_sai_db_ptr->is_issu_gp_reg_restore) {
            sai_status = mlnx_sai_issu_storage_udf_gp_reg_idx_lookup(&reg_id, group_db_index);
            if (SAI_STATUS_ITEM_NOT_FOUND == sai_status) {
                sai_status = SAI_STATUS_SUCCESS;
                goto out;
            }
            if (SAI_ERR(sai_status)) {
                goto out;
            }

            sai_status = mlnx_gp_reg_db_alloc_by_gp_reg_id(&reg_entry, reg_id);
            if (SAI_ERR(sai_status)) {
                goto out;
            }
        } else {
            /* get register id from the pool */
            sai_status = mlnx_gp_reg_db_alloc_first_free(&reg_entry, &gp_reg_db_idx, GP_REG_USED_UDF);
            if (SAI_ERR(sai_status)) {
                goto out;
            }

            reg_id = gp_reg_db_idx.idx;
        }

        assert(reg_id < SX_GP_REGISTER_LAST_E);

        /* create register key */
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_udf_group_sx_gp_registers_create_destroy_spc2
                              (SX_ACCESS_CMD_CREATE, &reg_id, 1))) {
            goto out;
        }
        reg_entry->gp_usage = GP_REG_USED_UDF;
    }

    udf_count = udf_db_group_udfs_ptr(group_db_index)->count;
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_udf_group_construct_extr_point_list_from_db
                          (group_db_index, udf_count, ext_point_list))) {
        goto out;
    }

    /* set list of extraction points to register key in SDK */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_udf_group_sx_reg_ext_point_set_spc2
                          (SX_ACCESS_CMD_SET, reg_id, ext_point_list, udf_count))) {
        goto out;
    }

    /* allocate FLEX ACL key id*/
    sx_keys[0] = MLNX_SX_GP_REG_TO_FLEX_ACL_KEY(reg_id);

    udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created = true;

out:
    if (SAI_STATUS_SUCCESS != sai_status) {
        if (reg_entry) {
            mlnx_gp_reg_db_free(gp_reg_db_idx);
        }
    }
    return sai_status;
}

static sai_status_t mlnx_udf_group_flex_acl_key_ids_del_spc2(_In_ uint32_t group_db_index)
{
    sai_status_t            sai_status = SAI_STATUS_SUCCESS;
    sx_acl_key_t           *sx_keys = NULL;
    sx_gp_register_e        reg_id = SX_GP_REGISTER_LAST_E;
    mlnx_shm_rm_array_idx_t gp_reg_db_idx = {0};
    sx_extraction_point_t   ext_point[MLNX_EXT_POINT_MAX_NUM] = {0};
    uint32_t                ext_point_cnt = MLNX_EXT_POINT_MAX_NUM;

    assert(udf_db_group_ptr(group_db_index)->is_created);
    assert(udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created);
    assert(0 == udf_db_group_udfs_ptr(group_db_index)->count);

    sx_keys = udf_db_group_ptr(group_db_index)->sx_custom_bytes_keys;

    reg_id = MLNX_FLEX_ACL_KEY_TO_SX_GP_REG(sx_keys[0]);
    assert(reg_id != SX_GP_REGISTER_LAST_E);

    /* get list of extraction points mapped to register key from SDK */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_udf_group_sx_reg_ext_points_get_spc2
                          (reg_id, ext_point, &ext_point_cnt))) {
        goto out;
    }

    /* unset extraction points from register key */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_udf_group_sx_reg_ext_point_set_spc2
                          (SX_ACCESS_CMD_UNSET, reg_id, ext_point, ext_point_cnt))) {
        goto out;
    }

    /* destroy register key */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_udf_group_sx_gp_registers_create_destroy_spc2
                          (SX_ACCESS_CMD_DESTROY, &reg_id, 1))) {
        goto out;
    }

    gp_reg_db_idx.type = MLNX_SHM_RM_ARRAY_TYPE_GP_REG;
    gp_reg_db_idx.idx = reg_id;

    /* return register id to the pool */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_gp_reg_db_free(gp_reg_db_idx))) {
        goto out;
    }

    memset(sx_keys, 0, sizeof(sx_keys[0]) * MLNX_UDF_GROUP_LENGTH_MAX);

    udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created = false;

    SX_LOG_NTC("Removed the GP Registers for UDF Group %lx\n",
               udf_db_group_ptr(group_db_index)->sai_object);

out:
    return sai_status;
}

sai_status_t mlnx_udf_db_udf_group_size_get(uint32_t *db_size)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    sai_status = mlnx_udf_db_size_get(SAI_OBJECT_TYPE_UDF_GROUP, db_size);

    return sai_status;
}

sai_status_t mlnx_sai_udf_get_issu_udf_info(_In_ uint32_t group_db_index, _Out_ mlnx_issu_gp_reg_udf_info *udf_info)
{
    sai_status_t          sai_status = SAI_STATUS_SUCCESS;
    uint32_t              ii = 0;
    uint32_t              udf_db_index = 0;
    uint32_t              udf_match_db_index = 0;
    sai_uint16_t          offset = 0;
    mlnx_udf_match_type_t match_type = 0;

    SX_LOG_ENTER();

    assert(udf_info);

    udf_info->udf_group_type = udf_db_group_ptr(group_db_index)->type;
    udf_info->udf_group_length = udf_db_group_ptr(group_db_index)->length;

    for (ii = 0; ii < udf_db_group_udfs_ptr(group_db_index)->count; ++ii) {
        udf_db_index = udf_db_group_udfs_ptr(group_db_index)->udf_indexes[ii];
        udf_match_db_index = udf_db_udf(udf_db_index).match_index;

        offset = udf_db_udf(udf_db_index).offset;
        match_type = udf_db_match(udf_match_db_index).type;

        udf_info->udf_offsets_arr[match_type] = offset;
        udf_info->udf_match_type_bitmask |= (1 << match_type);
    }

    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_udf_get_gp_reg_issu_info_from_udf_db(_In_ uint32_t                         group_db_index,
                                                           _Out_ mlnx_sai_issu_gp_reg_info_elem *elem,
                                                           _Inout_ uint32_t                     *count)
{
    sai_status_t     sai_status = SAI_STATUS_SUCCESS;
    sx_gp_register_e gp_reg_idx = SX_GP_REGISTER_LAST_E;

    SX_LOG_ENTER();

    assert(elem);
    assert(count);

    if (mlnx_udf_db_is_created(group_db_index, SAI_OBJECT_TYPE_UDF_GROUP) &&
        udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created) {
        gp_reg_idx = MLNX_FLEX_ACL_KEY_TO_SX_GP_REG(udf_db_group_ptr(group_db_index)->sx_custom_bytes_keys[0]);
        elem->gp_reg_bitmask |= (1 << gp_reg_idx);

        elem->type = GP_REG_USED_UDF;

        sai_status = mlnx_sai_udf_get_issu_udf_info(group_db_index, &elem->udf);
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        (*count)++;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_udf_issu_flow_validate_udf_group_hw_configured(uint32_t udf_group_db_index)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if (g_sai_db_ptr->is_issu_gp_reg_restore &&
        !udf_db_group_ptr(udf_group_db_index)->is_sx_custom_bytes_created) {
        SX_LOG_ERR("ISSU flow failed. UDF is not applied in HW\n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_udf_check_udf_db_is_set_to_hw(void)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     db_size = 0;
    uint32_t     group_db_index = 0;

    SX_LOG_ENTER();

    sai_status = mlnx_udf_db_udf_group_size_get(&db_size);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    for (group_db_index = 0; group_db_index < db_size; ++group_db_index) {
        if (mlnx_udf_db_is_created(group_db_index, SAI_OBJECT_TYPE_UDF_GROUP) &&
            udf_db_group_udfs_ptr(group_db_index)->count &&
            !udf_db_group_ptr(group_db_index)->is_sx_custom_bytes_created) {
            sai_status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

const sai_udf_api_t mlnx_udf_api = {
    mlnx_sai_create_udf,
    mlnx_sai_remove_udf,
    mlnx_sai_set_udf_attribute,
    mlnx_sai_get_udf_attribute,
    mlnx_sai_create_udf_match,
    mlnx_sai_remove_udf_match,
    mlnx_sai_set_udf_match_attribute,
    mlnx_sai_get_udf_match_attribute,
    mlnx_sai_create_udf_group,
    mlnx_sai_remove_udf_group,
    mlnx_sai_set_udf_group_attribute,
    mlnx_sai_get_udf_group_attribute
};
