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
#define __MODULE__ SAI_HASH

#define SAI_HASH_FIELDS_COUNT_MAX 64
#define SAI_HASH_DEFAULT_SEED     0

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_hash_native_field_list_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_hash_native_field_list_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_hash_fg_field_list_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_hash_fg_field_list_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_hash_udf_group_list_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_hash_udf_group_list_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
sai_status_t mlnx_hash_ecmp_sx_config_update(void);
static sai_status_t mlnx_hash_ecmp_global_config_get(_Out_ sx_router_ecmp_port_hash_params_t  *port_hash_param,
                                                     _Out_ sx_router_ecmp_hash_field_enable_t *enable_list,
                                                     _Out_ uint32_t                           *enable_count,
                                                     _Out_ sx_router_ecmp_hash_field_t        *field_list,
                                                     _Out_ uint32_t                           *field_count);
static sai_status_t mlnx_hash_lag_global_config_get(_Out_ sx_lag_port_hash_params_t  *lag_hash_params,
                                                    _Out_ sx_lag_hash_field_enable_t *enable_list,
                                                    _Out_ uint32_t                   *enable_count,
                                                    _Out_ sx_lag_hash_field_t        *field_list,
                                                    _Out_ uint32_t                   *field_count);
static sai_status_t mlnx_fine_grained_hash_field_attribute_get(_In_ const sai_object_key_t   *key,
                                                               _Inout_ sai_attribute_value_t *value,
                                                               _In_ uint32_t                  attr_index,
                                                               _Inout_ vendor_cache_t        *cache,
                                                               void                          *arg);
static sai_status_t gp_registers_availability_check(_In_ uint32_t                        fields_count,
                                                    _In_ const mlnx_sai_fg_hash_field_t *fields_list,
                                                    _In_ bool                            optimized);
static sai_status_t ipv4_reg_lookup(_Inout_ mlnx_gp_reg_db_t           **gp_reg_db_data,
                                    _Inout_ mlnx_shm_rm_array_idx_t     *db_idx,
                                    _In_ const mlnx_sai_fg_hash_field_t *field,
                                    _In_ bool                            is_gp_reg_restore,
                                    _In_ mlnx_gp_reg_usage_t             gp_reg_usage,
                                    _In_ mlnx_gp_reg_usage_t             gp_reg_usage_prev);
static sai_status_t ipv4_reg_allocate(_Inout_ mlnx_sai_fg_hash_field_t *field,
                                      _In_ bool                         optimized,
                                      _In_ bool                         is_gp_reg_restore,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage_prev);
static sai_status_t ipv6_reg_allocate(_Inout_ mlnx_sai_fg_hash_field_t *field,
                                      _In_ bool                         optimized,
                                      _In_ bool                         is_gp_reg_restore,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage_prev);
static sai_status_t l4_reg_allocate(_Inout_ mlnx_sai_fg_hash_field_t *field,
                                    _In_ bool                         is_gp_reg_restore,
                                    _In_ mlnx_gp_reg_usage_t          gp_reg_usage,
                                    _In_ mlnx_gp_reg_usage_t          gp_reg_usage_prev);
static sai_status_t gp_registers_allocation(_In_ uint32_t                     fields_count,
                                            _Inout_ mlnx_sai_fg_hash_field_t *fields_list,
                                            _In_ bool                         optimized);
sai_status_t gp_registers_delete(_Inout_ mlnx_sai_fg_hash_field_t *fields_list);

static void mlnx_fg_hash_action_list_create(_In_ sx_flex_acl_action_hash_type_t action_type,
                                            _In_ uint32_t                       fields_count,
                                            _In_ mlnx_sai_fg_hash_field_t      *fields_list,
                                            _Inout_ sx_flex_acl_flex_action_t * action_list,
                                            _Inout_ uint32_t                   *action_num);
static void mlnx_fg_optimized_hash_action_list_create(_In_ sx_flex_acl_action_hash_type_t action_type,
                                                      _In_ uint32_t                       fields_count,
                                                      _In_ mlnx_sai_fg_hash_field_t      *fields_list,
                                                      _Inout_ sx_flex_acl_flex_action_t * action_list,
                                                      _Inout_ uint32_t                   *action_num);
sai_status_t mlnx_fine_grained_hash_create(_In_ sai_object_id_t                hash_id,
                                           _In_ sx_flex_acl_action_hash_type_t action_type,
                                           _Inout_ sx_flex_acl_flex_action_t  *action_list,
                                           _Inout_ uint32_t                   *action_num);

extern sai_status_t mlnx_init_flex_parser();

static const sai_vendor_attribute_entry_t hash_vendor_attribs[] = {
    { SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_hash_native_field_list_get, NULL,
      mlnx_hash_native_field_list_set, NULL },
    { SAI_HASH_ATTR_UDF_GROUP_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_hash_udf_group_list_get, NULL,
      mlnx_hash_udf_group_list_set, NULL },
    { SAI_HASH_ATTR_FINE_GRAINED_HASH_FIELD_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_hash_fg_field_list_get, NULL,
      mlnx_hash_fg_field_list_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};

static const sai_vendor_attribute_entry_t fg_hash_field_vendor_attribs[] = {
    { SAI_FINE_GRAINED_HASH_FIELD_ATTR_NATIVE_HASH_FIELD,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_fine_grained_hash_field_attribute_get, (void*)SAI_FINE_GRAINED_HASH_FIELD_ATTR_NATIVE_HASH_FIELD,
      NULL, NULL },
    { SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV4_MASK,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_fine_grained_hash_field_attribute_get, (void*)SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV4_MASK,
      NULL, NULL },
    { SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV6_MASK,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_fine_grained_hash_field_attribute_get, (void*)SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV6_MASK,
      NULL, NULL },
    { SAI_FINE_GRAINED_HASH_FIELD_ATTR_SEQUENCE_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_fine_grained_hash_field_attribute_get, (void*)SAI_FINE_GRAINED_HASH_FIELD_ATTR_SEQUENCE_ID,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};

static const mlnx_attr_enum_info_t fg_hash_field_enum_info[] = {
    [SAI_FINE_GRAINED_HASH_FIELD_ATTR_NATIVE_HASH_FIELD] = ATTR_ENUM_VALUES_LIST(
        SAI_NATIVE_HASH_FIELD_SRC_IPV4,
        SAI_NATIVE_HASH_FIELD_DST_IPV4,
        SAI_NATIVE_HASH_FIELD_SRC_IPV6,
        SAI_NATIVE_HASH_FIELD_DST_IPV6,
        SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4,
        SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4,
        SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6,
        SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6,
        SAI_NATIVE_HASH_FIELD_IP_PROTOCOL,
        SAI_NATIVE_HASH_FIELD_L4_SRC_PORT,
        SAI_NATIVE_HASH_FIELD_L4_DST_PORT,
        SAI_NATIVE_HASH_FIELD_INNER_IP_PROTOCOL,
        SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT,
        SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT
        )
};
const mlnx_obj_type_attrs_info_t   mlnx_fg_hash_field_obj_type_info = {
    fg_hash_field_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(fg_hash_field_enum_info), OBJ_STAT_CAP_INFO_EMPTY()
};

static const mlnx_attr_enum_info_t hash_enum_info[] = {
    [SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST] = ATTR_ENUM_VALUES_LIST(
        SAI_NATIVE_HASH_FIELD_SRC_IP,
        SAI_NATIVE_HASH_FIELD_DST_IP,
        SAI_NATIVE_HASH_FIELD_INNER_SRC_IP,
        SAI_NATIVE_HASH_FIELD_INNER_DST_IP,
        SAI_NATIVE_HASH_FIELD_VLAN_ID,
        SAI_NATIVE_HASH_FIELD_IP_PROTOCOL,
        SAI_NATIVE_HASH_FIELD_ETHERTYPE,
        SAI_NATIVE_HASH_FIELD_L4_SRC_PORT,
        SAI_NATIVE_HASH_FIELD_L4_DST_PORT,
        SAI_NATIVE_HASH_FIELD_SRC_MAC,
        SAI_NATIVE_HASH_FIELD_DST_MAC,
        SAI_NATIVE_HASH_FIELD_IN_PORT,
        )
};
const mlnx_obj_type_attrs_info_t   mlnx_hash_obj_type_info = {
    hash_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(hash_enum_info), OBJ_STAT_CAP_INFO_EMPTY()
};

static void hash_key_to_str(_In_ sai_object_id_t hash_id, _Out_ char *key_str)
{
    uint32_t hash_data = 0;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid hash id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "hash id %u", hash_data);
    }
}

/* Create new hash object. */
static sai_status_t mlnx_hash_obj_create(sai_object_id_t* new_object)
{
    uint32_t     ii = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_db_write_lock();

    /* Find next free index in hash_arr. */
    while (ii < SAI_HASH_MAX_OBJ_COUNT &&
           g_sai_db_ptr->hash_list[ii].hash_id != SAI_NULL_OBJECT_ID) {
        ++ii;
    }

    if (ii == SAI_HASH_MAX_OBJ_COUNT) {
        sai_db_unlock();
        SX_LOG_ERR("Failed to create new hash object - hash DB is full.\n");
        return SAI_STATUS_TABLE_FULL;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HASH, ii, NULL, new_object))) {
        sai_db_unlock();
        return status;
    }

    g_sai_db_ptr->hash_list[ii].hash_id = *new_object;

    sai_db_sync();
    sai_db_unlock();

    return status;
}

/* Create new FG hash field object. */
static sai_status_t mlnx_fg_hash_field_obj_create(sai_object_id_t* new_object, uint32_t* obj_index)
{
    uint32_t     ii = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_db_write_lock();

    /* Find next free index in fg_hash_fields array */
    while (ii < MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT &&
           g_sai_db_ptr->fg_hash_fields[ii].fg_field_id != SAI_NULL_OBJECT_ID) {
        ++ii;
    }

    if (ii == MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT) {
        sai_db_unlock();
        SX_LOG_ERR("Failed to create new fine grained hash field object - hash DB is full.\n");
        return SAI_STATUS_TABLE_FULL;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD, ii, NULL, new_object))) {
        sai_db_unlock();
        return status;
    }

    g_sai_db_ptr->fg_hash_fields[ii].fg_field_id = *new_object;
    *obj_index = ii;

    sai_db_sync();
    sai_db_unlock();

    return status;
}

/* Set native fields for specified hash object */
static sai_status_t mlnx_hash_obj_native_fields_set(const sai_object_id_t hash_id, const sai_attribute_value_t* value)
{
    uint32_t     ii = 0;
    int32_t      field = 0;
    uint64_t     field_mask = 0;
    uint32_t     hash_data = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    for (ii = 0; ii < value->s32list.count; ii++) {
        field = value->s32list.list[ii];
        if ((field < SAI_NATIVE_HASH_FIELD_SRC_IP) ||
            (field > SAI_NATIVE_HASH_FIELD_IN_PORT)) {
            SX_LOG_ERR("Invalid native filed value %d.\n", field);
            return SAI_STATUS_INVALID_ATTR_VALUE_0;
        }

        field_mask |= (uint64_t)1 << field;
    }

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    g_sai_db_ptr->hash_list[hash_data].field_mask = field_mask;
    return status;
}

/* Check if fields can be symmetric */
static sai_status_t mlnx_hash_obj_symmetric_fg_fields_check(mlnx_sai_fg_hash_field_t* fg_fields, uint32_t fields_count)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii = 0;

    SX_LOG_ENTER();

    for (; ii < fields_count; ii++) {
        if (fg_fields[ii].sequence_id == fg_fields[ii + 1].sequence_id) {
            switch (fg_fields[ii].field) {
            case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_DST_IPV4) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (fg_fields[ii].ip_mask.ip4 != fg_fields[ii + 1].ip_mask.ip4) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_DST_IPV4:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_SRC_IPV4) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (fg_fields[ii].ip_mask.ip4 != fg_fields[ii + 1].ip_mask.ip4) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_DST_IPV6) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (memcmp(&(fg_fields[ii].ip_mask.ip6[0]), &(fg_fields[ii + 1].ip_mask.ip6[0]), sizeof(sai_ip6_t))) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_DST_IPV6:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_SRC_IPV6) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (memcmp(&(fg_fields[ii].ip_mask.ip6[0]), &(fg_fields[ii + 1].ip_mask.ip6[0]), sizeof(sai_ip6_t))) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (fg_fields[ii].ip_mask.ip4 != fg_fields[ii + 1].ip_mask.ip4) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (fg_fields[ii].ip_mask.ip4 != fg_fields[ii + 1].ip_mask.ip4) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (memcmp(&(fg_fields[ii].ip_mask.ip6[0]), &(fg_fields[ii + 1].ip_mask.ip6[0]), sizeof(sai_ip6_t))) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                if (memcmp(&(fg_fields[ii].ip_mask.ip6[0]), &(fg_fields[ii + 1].ip_mask.ip6[0]), sizeof(sai_ip6_t))) {
                    status = SAI_STATUS_NOT_SUPPORTED;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_L4_DST_PORT) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_L4_SRC_PORT) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
                if (fg_fields[ii + 1].field != SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT) {
                    status = SAI_STATUS_INVALID_PARAMETER;
                    goto out;
                }
                break;

            default:
                SX_LOG_ERR("Only source and destination IPs or ports can have equal sequence ids!\n");
                return SAI_STATUS_FAILURE;
            }
        }
    }

out:
    if (status == SAI_STATUS_INVALID_PARAMETER) {
        SX_LOG_ERR("These fields [%s] and [%s] can not have equal sequence ids \n",
                   MLNX_SAI_NATIVE_HASH_FIELD_STR(fg_fields[ii].field),
                   MLNX_SAI_NATIVE_HASH_FIELD_STR(fg_fields[ii + 1].field));
    } else if (status == SAI_STATUS_NOT_SUPPORTED) {
        SX_LOG_ERR("Masks of the symmetric fields [%s] and [%s] should be equal! \n",
                   MLNX_SAI_NATIVE_HASH_FIELD_STR(fg_fields[ii].field),
                   MLNX_SAI_NATIVE_HASH_FIELD_STR(fg_fields[ii + 1].field));
    }
    SX_LOG_EXIT();
    return status;
}

/* Set native fields for specified hash object */
static sai_status_t mlnx_hash_obj_fg_fields_list_set(const sai_object_id_t     hash_id,
                                                     mlnx_sai_fg_hash_field_t* fg_fields,
                                                     uint32_t                  fields_count)
{
    uint32_t                 hash_data = 0;
    mlnx_sai_fg_hash_field_t fg_fields_list[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT] = {SAI_NULL_OBJECT_ID};
    sai_status_t             status = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    /*set sequence id for fields where it was not set by user */
    uint8_t  not_set_count = 0;
    uint8_t  set_count = 0;
    uint32_t max_seq_id = 0;

    for (uint32_t ind = 0; ind < fields_count; ind++) {
        if (fg_fields[ind].sequence_id == 0) {
            ++not_set_count;
        } else {
            if (max_seq_id < fg_fields[ind].sequence_id) {
                max_seq_id = fg_fields[ind].sequence_id;
            }
            fg_fields_list[set_count] = fg_fields[ind];
            ++set_count;
        }
    }

    for (uint32_t ind = 0; ind < fields_count; ind++) {
        if (fg_fields[ind].sequence_id == 0) {
            fg_fields_list[set_count] = fg_fields[ind];
            ++set_count;
        }
    }

    if (not_set_count > 0) {
        for (uint8_t ii = 0; ii < not_set_count; ++ii) {
            for (uint32_t ind = 0; ind < fields_count; ind++) {
                if (fg_fields_list[ind].sequence_id == 0) {
                    if (max_seq_id == 0xffffffff) {
                        return SAI_STATUS_BUFFER_OVERFLOW;
                    }
                    ++max_seq_id;
                    fg_fields_list[ind].sequence_id = max_seq_id;
                }
            }
        }
    }
    /*sort fields array (increasing of the sequence id) */
    for (uint32_t ind = 0; ind < fields_count - 1; ind++) {
        bool swapped = false;
        for (uint32_t jj = 0; jj < fields_count - ind - 1; ++jj) {
            if (fg_fields_list[jj].sequence_id > fg_fields_list[jj + 1].sequence_id) {
                mlnx_sai_fg_hash_field_t tmp = fg_fields_list[jj];
                fg_fields_list[jj] = fg_fields_list[jj + 1];
                fg_fields_list[jj + 1] = tmp;
                swapped = true;
            }
        }
        if (!swapped) {
            break;
        }
    }

    status = mlnx_hash_obj_symmetric_fg_fields_check(fg_fields_list, set_count);
    if (SAI_ERR(status)) {
        return status;
    }

    memcpy(g_sai_db_ptr->hash_list[hash_data].fg_fields, fg_fields_list,
           MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT * sizeof(mlnx_sai_fg_hash_field_t));

    return SAI_STATUS_SUCCESS;
}
/* Get native fields configured for a specified hash object */
static sai_status_t mlnx_hash_obj_native_fileds_get(const sai_object_id_t hash_id, sai_attribute_value_t* value)
{
    uint32_t     ii = 0;
    uint64_t     field_mask = 0;
    int32_t      field_list[SAI_HASH_FIELDS_COUNT_MAX] = {0};
    uint32_t     field_count = 0;
    uint32_t     hash_data = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    if ((g_sai_db_ptr->hash_list[hash_data].hash_id == SAI_NULL_OBJECT_ID) ||
        (g_sai_db_ptr->hash_list[hash_data].hash_id != hash_id)) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }
    field_mask = g_sai_db_ptr->hash_list[hash_data].field_mask;

    for (ii = SAI_NATIVE_HASH_FIELD_SRC_IP; ii <= SAI_NATIVE_HASH_FIELD_IN_PORT; ii++) {
        if (field_mask & ((uint64_t)1 << ii)) {
            field_list[field_count++] = ii;
        }
    }

    status = mlnx_fill_s32list(field_list, field_count, &value->s32list);

    return status;
}

static sai_status_t mlnx_hash_object_udf_group_mask_get(_In_ const sai_object_id_t hash_id,
                                                        _Out_ udf_group_mask_t    *group_mask)
{
    sai_status_t status;
    uint32_t     hash_index;

    status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    *group_mask = g_sai_db_ptr->hash_list[hash_index].udf_group_mask;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_obj_udf_group_list_set(_In_ const sai_object_id_t        hash_id,
                                                     _In_ uint32_t                     attr_index,
                                                     _In_ const sai_attribute_value_t *value)
{
    sai_status_t     status;
    udf_group_mask_t udf_group_mask;
    uint32_t         hash_index;

    status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_udf_group_objlist_validate_and_fetch_mask(&value->objlist, attr_index, &udf_group_mask);
    if (SAI_ERR(status)) {
        return status;
    }

    assert(MLNX_UDF_GROUP_MASK_EMPTY == g_sai_db_ptr->hash_list[hash_index].udf_group_mask);

    g_sai_db_ptr->hash_list[hash_index].udf_group_mask = udf_group_mask;

    mlnx_udf_group_mask_references_add(udf_group_mask);

    return SAI_STATUS_SUCCESS;
}

/* Check if specified native fields are valid
 * for mentioned hash object id (L2, IPv4 or IpinIP) */
static sai_status_t mlnx_hash_obj_native_fields_validate(mlnx_switch_usage_hash_object_id_t hash_oper_id,
                                                         const sai_attribute_value_t      * value)
{
    uint32_t     ii = 0;
    int32_t      field = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (value->s32list.count == 0) {
        SX_LOG_ERR("Invalid empty native fields list, count - 0.\n");
        return SAI_STATUS_FAILURE;
    }

    if (hash_oper_id == SAI_HASH_MAX_OBJ_ID) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < value->s32list.count; ii++) {
        field = value->s32list.list[ii];
        switch (field) {
        case SAI_NATIVE_HASH_FIELD_ETHERTYPE:
        case SAI_NATIVE_HASH_FIELD_SRC_MAC:
        case SAI_NATIVE_HASH_FIELD_DST_MAC:
        case SAI_NATIVE_HASH_FIELD_IN_PORT:
        case SAI_NATIVE_HASH_FIELD_VLAN_ID:
            /* valid for all */
            break;

        case SAI_NATIVE_HASH_FIELD_SRC_IP:
        case SAI_NATIVE_HASH_FIELD_DST_IP:
        case SAI_NATIVE_HASH_FIELD_IP_PROTOCOL:
        case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
        case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            /* valid for IP and IPinIP */
/*
 *           if ((hash_oper_id == SAI_HASH_ECMP_ID) ||
 *               (hash_oper_id == SAI_HASH_LAG_ID)) {
 *               status = SAI_STATUS_FAILURE;
 *               SX_LOG_ERR("Invalid native field %d for object %u.\n", field, hash_oper_id);
 *           }
 */
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IP:
        case SAI_NATIVE_HASH_FIELD_INNER_DST_IP:
            /* valid for IPinIP*/
            if ((hash_oper_id != SAI_HASH_ECMP_IPINIP_ID) &&
                (hash_oper_id != SAI_HASH_LAG_IPINIP_ID) &&
                (hash_oper_id != SAI_HASH_ECMP_IP6_ID)) {
                status = SAI_STATUS_FAILURE;
                SX_LOG_ERR("Invalid native field %d for object %u.\n", field, hash_oper_id);
            }
            break;

        default:
            SX_LOG_ERR("Invalid native filed value %d.\n", field);
            return SAI_STATUS_INVALID_ATTR_VALUE_0;
        }
    }

    return status;
}

/* Check if the specified hash object is operational.
 * If IPinIP object is configured – no need to apply IP or default object.
 * Same if IP object configured - no need to apply default object. */
static bool mlnx_hash_obj_need_apply(mlnx_switch_usage_hash_object_id_t hash_oper_id)
{
    bool res = true;

    assert(hash_oper_id <= SAI_HASH_MAX_OBJ_ID);

    switch (hash_oper_id) {
    case SAI_HASH_ECMP_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP4_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
            break;
        }
    /* Falls through. */

    /* do not break here, need verify same condition as for IPv4 */
    case SAI_HASH_ECMP_IP4_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IPINIP_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
        }
        break;

    case SAI_HASH_LAG_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IP4_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
            break;
        }
    /* Falls through. */

    /* do not break here, need verify same condition as for IPv4 */
    case SAI_HASH_LAG_IP4_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IPINIP_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
        }
        break;

    case SAI_HASH_ECMP_IPINIP_ID:
    case SAI_HASH_LAG_IPINIP_ID:
    case SAI_HASH_ECMP_IP6_ID:
    case SAI_HASH_LAG_IP6_ID:
    case SAI_HASH_FG_1_ID:
    case SAI_HASH_FG_2_ID:
        break;

    case SAI_HASH_MAX_OBJ_ID:
        res = false;
        break;
    }

    return res;
}

/* Convert sai fields list to sx fields list and enable list */
static sai_status_t mlnx_hash_convert_ecmp_sai_field_to_sx(const sai_attribute_value_t       * value,
                                                           sx_router_ecmp_hash_field_enable_t* enable_list,
                                                           uint32_t                          * enable_count,
                                                           sx_router_ecmp_hash_field_t       * fields_list,
                                                           uint32_t                          * fields_count,
                                                           bool                                is_ipv6)
{
    uint32_t     ii = 0;
    bool         enable_ipv4 = false, enable_l4 = false, enable_inner = false;
    sai_status_t status = SAI_STATUS_SUCCESS;

    *fields_count = 0;
    *enable_count = 0;

    for (ii = 0; ii < value->s32list.count; ii++) {
        switch (value->s32list.list[ii]) {
        case SAI_NATIVE_HASH_FIELD_SRC_IP:
            if (is_ipv6) {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTES_0_TO_7;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_8;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_9;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_10;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_11;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_12;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_13;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_14;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_15;
            } else { /* ipv4 */
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_0;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_1;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_2;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_3;

                enable_ipv4 = true;
            }
            break;

        case SAI_NATIVE_HASH_FIELD_DST_IP:
            if (is_ipv6) {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTES_0_TO_7;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_8;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_9;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_10;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_11;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_12;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_13;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_14;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_15;
            } else {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_0;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_1;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_2;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_3;

                enable_ipv4 = true;
            }
            break;

        case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_TCP_UDP_SPORT;

            enable_l4 = true;
            break;

        case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_TCP_UDP_DPORT;

            enable_l4 = true;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IP:
            if (is_ipv6) {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTES_0_TO_7;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_8;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_9;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_10;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_11;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_12;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_13;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_14;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_SIP_BYTE_15;
            } else {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_0;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_1;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_2;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_3;

                enable_ipv4 = true;
            }

            enable_inner = true;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_DST_IP:
            if (is_ipv6) {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTES_0_TO_7;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_8;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_9;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_10;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_11;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_12;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_13;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_14;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV6_DIP_BYTE_15;
            } else {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_0;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_1;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_2;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_3;

                enable_ipv4 = true;
            }

            enable_inner = true;
            break;

        case SAI_NATIVE_HASH_FIELD_VLAN_ID:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_OVID;
            break;

        case SAI_NATIVE_HASH_FIELD_IP_PROTOCOL:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_PROTOCOL;
            enable_ipv4 = true;
            break;

        case SAI_NATIVE_HASH_FIELD_ETHERTYPE:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_ETHERTYPE;
            break;

        case SAI_NATIVE_HASH_FIELD_SRC_MAC:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_SMAC;
            break;

        case SAI_NATIVE_HASH_FIELD_DST_MAC:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_DMAC;
            break;

        case SAI_NATIVE_HASH_FIELD_IN_PORT:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_INGRESS_PORT_NUMBER;
            break;

        default:
            SX_LOG_ERR("Invalid ECMP hash field , element %d, value %d.\n", ii, value->s32list.list[ii]);
            return SAI_STATUS_INVALID_ATTR_VALUE_0;
        }
    }

    enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L2_NON_IP;
    enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L2_IPV4;
    if (enable_inner) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_L2_IPV4;
    }

    if (enable_ipv4) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV4_NON_TCP_UDP;
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV4_TCP_UDP;
        if (enable_inner) {
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_IPV4_NON_TCP_UDP;
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_IPV4_TCP_UDP;
        }
    }

    if (is_ipv6) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L2_IPV6;
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV6_NON_TCP_UDP;
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV6_TCP_UDP;
        if (enable_inner) {
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_IPV6_NON_TCP_UDP;
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_IPV6_TCP_UDP;
        }
    }

    if (enable_l4) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L4_IPV4;
        if (is_ipv6) {
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L4_IPV6;
        }
        if (enable_inner) {
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_L4_IPV4;
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_L4_IPV6;
        }
    }

    return status;
}

/* Get operational ECMP config and apply it for specified port */
/* SAI DB lock is needed */
static sai_status_t mlnx_hash_ecmp_cfg_apply_on_port(_In_ sx_port_log_id_t port_log_id)
{
    sai_status_t                       status;
    sx_router_ecmp_port_hash_params_t  port_hash_param;
    sx_router_ecmp_hash_field_enable_t hash_enable_list[FIELDS_ENABLES_NUM] = {0};
    sx_router_ecmp_hash_field_t        hash_field_list[FIELDS_NUM] = {0};
    uint32_t                           enable_count = 0;
    uint32_t                           field_count = 0;

    status = mlnx_hash_ecmp_global_config_get(&port_hash_param,
                                              hash_enable_list,
                                              &enable_count,
                                              hash_field_list,
                                              &field_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get ECMP hash config\n");
        return status;
    }

    status = sx_api_router_ecmp_port_hash_params_set(gh_sdk, SX_ACCESS_CMD_SET, port_log_id, &port_hash_param,
                                                     hash_enable_list, enable_count,
                                                     hash_field_list, field_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to set ECMP hash params for port %x.\n", port_log_id);
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_lag_cfg_apply_on_port(_In_ sx_port_log_id_t port_log_id)
{
    sai_status_t               status;
    sx_status_t                sx_status;
    sx_lag_port_hash_params_t  lag_hash_params;
    sx_lag_hash_field_enable_t hash_enable_list[FIELDS_ENABLES_NUM] = {0};
    sx_lag_hash_field_t        hash_field_list[FIELDS_NUM] = {0};
    uint32_t                   enable_count = 0;
    uint32_t                   field_count = 0;

    status = mlnx_hash_lag_global_config_get(&lag_hash_params, hash_enable_list, &enable_count,
                                             hash_field_list, &field_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get LAG hash config\n");
        return status;
    }

    sx_status = sx_api_lag_port_hash_flow_params_set(gh_sdk, SX_ACCESS_CMD_SET, port_log_id, &lag_hash_params,
                                                     hash_enable_list, enable_count,
                                                     hash_field_list, field_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set LAG hash params for LAG %x, - %s\n", port_log_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_hash_config_apply_to_port(_In_ sx_port_log_id_t sx_port)
{
    sai_status_t status;

    status = mlnx_hash_ecmp_cfg_apply_on_port(sx_port);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_hash_lag_cfg_apply_on_port(sx_port);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_ecmp_hash_params_apply_to_ports(
    const sx_router_ecmp_port_hash_params_t  *port_hash_param,
    const sx_router_ecmp_hash_field_enable_t *hash_enable_list,
    uint32_t                                  enable_count,
    const sx_router_ecmp_hash_field_t        *hash_field_list,
    uint32_t                                  field_count)
{
    sx_status_t         sx_status;
    mlnx_port_config_t *port;
    uint32_t            ii;
    const bool          is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                                 !g_sai_db_ptr->issu_end_called;

    assert(port_hash_param != NULL);
    assert(hash_enable_list != NULL);
    assert(hash_field_list != NULL);

    mlnx_port_not_in_lag_foreach(port, ii) {
        if (!is_warmboot_init_stage || (port->sdk_port_added && port->logical)) {
            sx_status = sx_api_router_ecmp_port_hash_params_set(gh_sdk, SX_ACCESS_CMD_SET, port->logical,
                                                                port_hash_param,
                                                                hash_enable_list, enable_count,
                                                                hash_field_list, field_count);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to set ecmp hash params for %s %x - %s.\n",
                           mlnx_port_type_str(port),
                           port->logical,
                           SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_lag_params_apply_to_ports(_In_ const sx_lag_port_hash_params_t  *lag_hash_params,
                                                        _In_ const sx_lag_hash_field_enable_t *enable_list,
                                                        _In_ uint32_t                          enable_count,
                                                        _In_ const sx_lag_hash_field_t        *field_list,
                                                        _In_ uint32_t                          field_count)
{
    sx_status_t         sx_status;
    mlnx_port_config_t *port;
    uint32_t            ii;
    const bool          is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                                 !g_sai_db_ptr->issu_end_called;

    assert(lag_hash_params);
    assert(enable_list);
    assert(field_list);

    mlnx_port_not_in_lag_foreach(port, ii) {
        if (!is_warmboot_init_stage || (port->sdk_port_added && port->logical)) {
            sx_status = sx_api_lag_port_hash_flow_params_set(gh_sdk, SX_ACCESS_CMD_SET, port->logical,
                                                             lag_hash_params, enable_list, enable_count,
                                                             field_list, field_count);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to apply LAG hash configuration to LAG %x\n", port->logical);
                return sdk_to_sai(sx_status);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* Finds the applied object IPinIP -> IPv4 -> default */
static sai_object_id_t mlnx_hash_ecmp_get_applied_object_ipv4(void)
{
    sai_object_id_t applied_object;

    applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IPINIP_ID];
    if (applied_object == SAI_NULL_OBJECT_ID) {
        applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP4_ID];
        if (applied_object == SAI_NULL_OBJECT_ID) {
            applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_ID];
        }
    }

    /* default object SAI_HASH_ECMP_ID is always applied (on init) */
    assert(applied_object != SAI_NULL_OBJECT_ID);

    return applied_object;
}

static sai_object_id_t mlnx_hash_ecmp_get_applied_object_ipv6(void)
{
    return g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP6_ID];
}

static sai_object_id_t mlnx_hash_lag_get_applied_object_ipv4(void)
{
    sai_object_id_t applied_object;

    applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IPINIP_ID];
    if (applied_object == SAI_NULL_OBJECT_ID) {
        applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IP4_ID];
        if (applied_object == SAI_NULL_OBJECT_ID) {
            applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_ID];
        }
    }

    /* default object SAI_HASH_LAG_ID is always applied (on init) */
    assert(applied_object != SAI_NULL_OBJECT_ID);

    return applied_object;
}

static sai_object_id_t mlnx_hash_lag_get_applied_object_ipv6(void)
{
    return g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IP6_ID];
}

static void mlnx_hash_inner_ip_proto_fields_get(_Out_ sx_router_ecmp_hash_field_t *field_list,
                                                _Inout_ uint32_t                  *field_count)
{
#ifdef MLNX_HASH_INNER_IP_PROTO_ENABLE
    assert(field_list);
    assert(field_count);

    field_list[*field_count] = SX_ROUTER_ECMP_HASH_INNER_IPV4_PROTOCOL;
    *field_count += 1;

    field_list[*field_count] = SX_ROUTER_ECMP_HASH_INNER_IPV6_NEXT_HEADER;
    *field_count += 1;
#endif /* MLNX_HASH_INNER_IP_PROTO_ENABLE */
}

static sai_status_t mlnx_hash_object_to_sx_fields(_In_ sai_object_id_t                      hash_oid,
                                                  _In_ bool                                 is_ipv6,
                                                  _Out_ sx_router_ecmp_hash_field_enable_t *enable_list,
                                                  _Out_ uint32_t                           *enable_count,
                                                  _Out_ sx_router_ecmp_hash_field_t        *field_list,
                                                  _Out_ uint32_t                           *field_count)
{
    sai_status_t                status;
    sai_attribute_value_t       sai_value;
    sai_native_hash_field_t     sai_fields_list[SAI_HASH_FIELDS_COUNT_MAX] = {0};
    udf_group_mask_t            udf_group_mask;
    sx_router_ecmp_hash_field_t udf_groups_hash_fields[GENERAL_FIELDS_NUM] = {0};
    uint32_t                    udf_groups_hash_field_count = 0;

    assert(enable_list);
    assert(enable_count);
    assert(field_list);
    assert(field_count);

    if (hash_oid == SAI_NULL_OBJECT_ID) {
        if (!is_ipv6) {
            SX_LOG_ERR("Invalid SAI DB state - Hash object for IPv4 is NULL\n");
            return SAI_STATUS_FAILURE;
        }

        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_hash_object_udf_group_mask_get(hash_oid, &udf_group_mask);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_value.s32list.list = (int32_t*)sai_fields_list;
    sai_value.s32list.count = sizeof(sai_fields_list);

    status = mlnx_hash_obj_native_fileds_get(hash_oid, &sai_value);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_hash_convert_ecmp_sai_field_to_sx(&sai_value, enable_list, enable_count,
                                                    field_list, field_count, is_ipv6);
    if (SAI_ERR(status)) {
        return status;
    }

    if (MLNX_UDF_GROUP_MASK_EMPTY != udf_group_mask) {
        status = mlnx_udf_group_mask_to_ecmp_hash_fields(udf_group_mask, udf_groups_hash_fields,
                                                         &udf_groups_hash_field_count);
        if (SAI_ERR(status)) {
            return status;
        }

        memcpy(&field_list[*field_count], udf_groups_hash_fields,
               sizeof(sx_router_ecmp_hash_field_t) * udf_groups_hash_field_count);

        *field_count += udf_groups_hash_field_count;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_objects_to_sx_fields(_In_ sai_object_id_t                      hash_object_v4,
                                                   _In_ sai_object_id_t                      hash_object_v6,
                                                   _Out_ sx_router_ecmp_hash_field_enable_t *enable_list,
                                                   _Out_ uint32_t                           *enable_count,
                                                   _Out_ sx_router_ecmp_hash_field_t        *field_list,
                                                   _Out_ uint32_t                           *field_count)
{
    sai_status_t                       status;
    sx_router_ecmp_hash_field_enable_t enable_list_v6[FIELDS_ENABLES_NUM] = {0};
    sx_router_ecmp_hash_field_t        field_list_v6[FIELDS_NUM] = {0};
    uint32_t                           enable_count_v6 = 0;
    uint32_t                           field_count_v6 = 0;
    uint32_t                           ii, jj;
    bool                               present;

    status = mlnx_hash_object_to_sx_fields(hash_object_v4, false,
                                           enable_list, enable_count,
                                           field_list, field_count);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_hash_object_to_sx_fields(hash_object_v6, true,
                                           enable_list_v6, &enable_count_v6,
                                           field_list_v6, &field_count_v6);
    if (SAI_ERR(status)) {
        return status;
    }

    /* add unique values from enable_list_v6 to enable_list */
    for (ii = 0; ii < enable_count_v6; ii++) {
        present = false;
        for (jj = 0; jj < *enable_count; jj++) {
            if (enable_list_v6[ii] == enable_list[jj]) {
                present = true;
                break;
            }
        }

        if (!present) {
            enable_list[*enable_count] = enable_list_v6[ii];
            (*enable_count)++;
        }
    }

    /* add unique values from field_list_v6 to field_list_v4 */
    for (ii = 0; ii < field_count_v6; ii++) {
        present = false;
        for (jj = 0; jj < *field_count; jj++) {
            if (field_list_v6[ii] == field_list[jj]) {
                present = true;
                break;
            }
        }

        if (!present) {
            field_list[*field_count] = field_list_v6[ii];
            (*field_count)++;
        }
    }

    mlnx_hash_inner_ip_proto_fields_get(field_list, field_count);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_ecmp_global_config_get(_Out_ sx_router_ecmp_port_hash_params_t  *port_hash_param,
                                                     _Out_ sx_router_ecmp_hash_field_enable_t *enable_list,
                                                     _Out_ uint32_t                           *enable_count,
                                                     _Out_ sx_router_ecmp_hash_field_t        *field_list,
                                                     _Out_ uint32_t                           *field_count)
{
    sai_object_id_t applied_hash_ipv4, applied_hash_ipv6;

    memset(port_hash_param, 0, sizeof(*port_hash_param));

    applied_hash_ipv4 = mlnx_hash_ecmp_get_applied_object_ipv4();
    applied_hash_ipv6 = mlnx_hash_ecmp_get_applied_object_ipv6();

    memcpy(port_hash_param, &g_sai_db_ptr->port_ecmp_hash_params, sizeof(*port_hash_param));

    return mlnx_hash_objects_to_sx_fields(applied_hash_ipv4, applied_hash_ipv6,
                                          enable_list, enable_count,
                                          field_list, field_count);
}

static sai_status_t mlnx_hash_lag_global_config_get(_Out_ sx_lag_port_hash_params_t  *lag_hash_params,
                                                    _Out_ sx_lag_hash_field_enable_t *enable_list,
                                                    _Out_ uint32_t                   *enable_count,
                                                    _Out_ sx_lag_hash_field_t        *field_list,
                                                    _Out_ uint32_t                   *field_count)
{
    sai_object_id_t applied_hash_ipv4, applied_hash_ipv6;

    memset(lag_hash_params, 0, sizeof(*lag_hash_params));

    applied_hash_ipv4 = mlnx_hash_lag_get_applied_object_ipv4();
    applied_hash_ipv6 = mlnx_hash_lag_get_applied_object_ipv6();

    memcpy(lag_hash_params, &g_sai_db_ptr->lag_hash_params, sizeof(*lag_hash_params));

    return mlnx_hash_objects_to_sx_fields(applied_hash_ipv4, applied_hash_ipv6,
                                          (sx_router_ecmp_hash_field_enable_t*)enable_list, enable_count,
                                          (sx_router_ecmp_hash_field_t*)field_list, field_count);
}

sai_status_t mlnx_hash_ecmp_sx_config_update(void)
{
    sai_status_t                       status;
    sx_router_ecmp_port_hash_params_t  port_hash_param;
    sx_router_ecmp_hash_field_enable_t enable_list[FIELDS_ENABLES_NUM] = {0};
    sx_router_ecmp_hash_field_t        field_list[FIELDS_NUM] = {0};
    uint32_t                           enable_count = 0;
    uint32_t                           field_count = 0;

    status = mlnx_hash_ecmp_global_config_get(&port_hash_param, enable_list, &enable_count, field_list, &field_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get ECMP hash config\n");
        return status;
    }

    status = mlnx_hash_ecmp_hash_params_apply_to_ports(&port_hash_param, enable_list, enable_count,
                                                       field_list, field_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_hash_lag_sx_config_update(void)
{
    sai_status_t               status;
    sx_lag_port_hash_params_t  lag_hash_params;
    sx_lag_hash_field_enable_t enable_list[FIELDS_ENABLES_NUM] = {0};
    sx_lag_hash_field_t        field_list[FIELDS_NUM] = {0};
    uint32_t                   enable_count = 0;
    uint32_t                   field_count = 0;

    status = mlnx_hash_lag_global_config_get(&lag_hash_params, enable_list, &enable_count, field_list, &field_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get LAG hash config\n");
        return status;
    }

    status = mlnx_hash_lag_params_apply_to_ports(&lag_hash_params, enable_list, enable_count,
                                                 field_list, field_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* Apply hash configuration */
static sai_status_t mlnx_hash_config_sx_update(mlnx_switch_usage_hash_object_id_t hash_oper_id)
{
    assert(hash_oper_id < SAI_HASH_MAX_OBJ_ID);

    if (hash_oper_id <= SAI_HASH_ECMP_ID_MAX) {
        return mlnx_hash_ecmp_sx_config_update();
    } else {
        return mlnx_hash_lag_sx_config_update();
    }
}

/* Find if mentioned hash object is set as a switch hash object,
 * if so - return it's operational object ID.
 * else - return SAI_HASH_MAX_OBJ_ID */
static mlnx_switch_usage_hash_object_id_t mlnx_hash_get_oper_id(sai_object_id_t hash_id)
{
    uint32_t ii = 0;

    /* check if the object is not used */
    for (ii = 0; ii < SAI_HASH_MAX_OBJ_ID; ii++) {
        if (g_sai_db_ptr->oper_hash_list[ii] == hash_id) {
            /* object in-use */
            break;
        }
    }

    return ii;
}

/* Remove hash object from DB if object is not in-use */
static sai_status_t mlnx_hash_obj_remove(sai_object_id_t hash_id)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     hash_data = 0;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    sai_db_write_lock();

    if (mlnx_hash_get_oper_id(hash_id) < SAI_HASH_MAX_OBJ_ID) {
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    status = mlnx_udf_group_mask_references_del(g_sai_db_ptr->hash_list[hash_data].udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

    g_sai_db_ptr->hash_list[hash_data].field_mask = 0;
    g_sai_db_ptr->hash_list[hash_data].udf_group_mask = MLNX_UDF_GROUP_MASK_EMPTY;
    g_sai_db_ptr->hash_list[hash_data].hash_id = SAI_NULL_OBJECT_ID;
    memset(g_sai_db_ptr->hash_list[hash_data].fg_fields,
           0,
           sizeof(mlnx_sai_fg_hash_field_t) * MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT);

out:
    sai_db_sync();
    sai_db_unlock();
    return status;
}

sai_status_t mlnx_hash_object_is_applicable(_In_ sai_object_id_t                    hash_oid,
                                            _In_ mlnx_switch_usage_hash_object_id_t hash_oper_id,
                                            _Out_ bool                             *is_applicable)
{
    sai_status_t          status = SAI_STATUS_SUCCESS;
    sai_attribute_value_t value;
    int32_t               field_list[SAI_HASH_FIELDS_COUNT_MAX] = {0};
    udf_group_mask_t      udf_group_mask;

    status = mlnx_hash_object_udf_group_mask_get(hash_oid, &udf_group_mask);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_udf_group_mask_is_hash_applicable(udf_group_mask, hash_oper_id, is_applicable);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!(*is_applicable)) {
        return SAI_STATUS_SUCCESS;
    }

    value.s32list.list = field_list;
    value.s32list.count = SAI_HASH_FIELDS_COUNT_MAX;

    status = mlnx_hash_obj_native_fileds_get(hash_oid, &value);
    if (SAI_ERR(status)) {
        return status;
    }

    /* validate fields */
    if (value.s32list.count > 0) {
        status = mlnx_hash_obj_native_fields_validate(hash_oper_id, &value);
        if (SAI_ERR(status)) {
            *is_applicable = false;
            return SAI_STATUS_SUCCESS;
        }
    }

    *is_applicable = true;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_hash_config_db_changes_commit(_In_ mlnx_switch_usage_hash_object_id_t hash_oper_id)
{
    assert(hash_oper_id <= SAI_HASH_MAX_OBJ_ID);

    if (mlnx_hash_obj_need_apply(hash_oper_id)) {
        return mlnx_hash_config_sx_update(hash_oper_id);
    }

    return SAI_STATUS_SUCCESS;
}

/* Add default hash configuration.
 * Create default ECMP and LAG hash object with default list of native fields enabled.
 * Set default ECMP and LAG hash algorithm and seed.
 */
sai_status_t mlnx_hash_initialize(void)
{
    sai_status_t                      status = SAI_STATUS_SUCCESS;
    sai_object_id_t                   ecmp_hash_obj = SAI_NULL_OBJECT_ID;
    sai_object_id_t                   lag_hash_obj = SAI_NULL_OBJECT_ID;
    sx_lag_hash_param_t               lag_hash_param;
    sx_router_ecmp_port_hash_params_t port_hash_param;
    sai_attribute_value_t             attr_value;
    int32_t                           def_hash_fields[] = { SAI_NATIVE_HASH_FIELD_SRC_MAC,
                                                            SAI_NATIVE_HASH_FIELD_DST_MAC,
                                                            SAI_NATIVE_HASH_FIELD_ETHERTYPE,
                                                            SAI_NATIVE_HASH_FIELD_SRC_IP,
                                                            SAI_NATIVE_HASH_FIELD_DST_IP,
                                                            SAI_NATIVE_HASH_FIELD_L4_SRC_PORT,
                                                            SAI_NATIVE_HASH_FIELD_L4_DST_PORT,
                                                            SAI_NATIVE_HASH_FIELD_INNER_SRC_IP,
                                                            SAI_NATIVE_HASH_FIELD_INNER_DST_IP, };

    memset(&lag_hash_param, 0, sizeof(lag_hash_param));
    memset(&port_hash_param, 0, sizeof(port_hash_param));

    attr_value.s32list.count = sizeof(def_hash_fields) / sizeof(def_hash_fields[0]);
    attr_value.s32list.list = def_hash_fields;

    memset(g_sai_db_ptr->hash_list, 0, sizeof(g_sai_db_ptr->hash_list));

    /* Create default hash objects */
    /* Default ECMP object */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HASH, 0, NULL, &ecmp_hash_obj))) {
        return status;
    }

    g_sai_db_ptr->hash_list[0].hash_id = ecmp_hash_obj;
    status = mlnx_hash_obj_native_fields_set(ecmp_hash_obj, &attr_value);
    if (SAI_ERR(status)) {
        return status;
    }

    g_sai_db_ptr->port_ecmp_hash_params.ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_CRC;
    g_sai_db_ptr->port_ecmp_hash_params.seed = SAI_HASH_DEFAULT_SEED;
    g_sai_db_ptr->port_ecmp_hash_params.symmetric_hash = false;

    g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_ID] = ecmp_hash_obj;
    g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP6_ID] = ecmp_hash_obj;

    status = mlnx_hash_ecmp_sx_config_update();
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update hash ecmp configuration\n");
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HASH, 1, NULL, &lag_hash_obj))) {
        return status;
    }

    g_sai_db_ptr->hash_list[1].hash_id = lag_hash_obj;
    status = mlnx_hash_obj_native_fields_set(lag_hash_obj, &attr_value);
    if (SAI_ERR(status)) {
        return status;
    }

    g_sai_db_ptr->lag_hash_params.lag_hash_type = SX_LAG_HASH_TYPE_XOR;
    g_sai_db_ptr->lag_hash_params.lag_seed = SAI_HASH_DEFAULT_SEED;
    g_sai_db_ptr->lag_hash_params.is_lag_hash_symmetric = false;

    g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_ID] = lag_hash_obj;
    g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IP6_ID] = lag_hash_obj;

    status = mlnx_hash_lag_sx_config_update();
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update hash LAG configuration\n");
        return status;
    }

    status = mlnx_parsing_depth_increase();
    if (SAI_ERR(status)) {
        return status;
    }

    return status;
}

/* Get Hash native fields [sai_u32_list_t(sai_native_hash_field)] */
static sai_status_t mlnx_hash_native_field_list_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    uint32_t        hash_data = 0;
    sai_object_id_t hash_id = key->key.object_id;
    char            key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t    status = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL))) {
        return status;
    }

    hash_key_to_str(hash_id, key_str);

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS != (status = mlnx_hash_obj_native_fileds_get(hash_id, value))) {
        SX_LOG_ERR("Failed to get native fields for %s.\n", key_str);
    }

    sai_db_unlock();
    return status;
}

/* Set Hash native fields [sai_u32_list_t(sai_native_hash_field)] */
static sai_status_t mlnx_hash_native_field_list_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    mlnx_switch_usage_hash_object_id_t hash_oper_id = 0;
    sai_object_id_t                    hash_id = key->key.object_id;
    char                               key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t                       status = SAI_STATUS_SUCCESS;

    hash_key_to_str(hash_id, key_str);

    sai_db_write_lock();

    hash_oper_id = mlnx_hash_get_oper_id(hash_id);

    status = mlnx_hash_obj_native_fields_validate(hash_oper_id, value);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_hash_obj_native_fields_set(hash_id, value);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_hash_config_db_changes_commit(hash_oper_id);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

/* Get Hash fine grained fields [sai_u32_list_t(sai_native_hash_field)] */
static sai_status_t mlnx_hash_fg_field_list_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    uint32_t         hash_data = 0;
    sai_object_id_t  hash_id = key->key.object_id;
    sai_status_t     status = SAI_STATUS_SUCCESS;
    sai_object_id_t  fg_field = SAI_NULL_OBJECT_ID;
    sai_object_id_t *fg_fields = NULL;
    uint32_t         fg_fields_count = 0;
    uint32_t         ii = 0;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL))) {
        return status;
    }

    fg_fields = calloc(MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT, sizeof(*fg_fields));
    if (!fg_fields) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    sai_db_read_lock();

    for (ii = 0; ii < MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT; ++ii) {
        fg_field = g_sai_db_ptr->hash_list[hash_data].fg_fields[ii].fg_field_id;
        if (SAI_NULL_OBJECT_ID == fg_field) {
            break;
        }
        fg_fields[ii] = fg_field;
        ++fg_fields_count;
    }

    sai_db_unlock();

    status = mlnx_fill_objlist(fg_fields, fg_fields_count, &value->objlist);

    safe_free(fg_fields);
    return status;
}

/* Set Hash fine grained fields [sai_u32_list_t(sai_native_hash_field)] */
static sai_status_t mlnx_hash_fg_field_list_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    mlnx_switch_usage_hash_object_id_t hash_oper_id = 0;
    sai_object_id_t                    hash_id = key->key.object_id;
    uint32_t                           hash_index = 0;
    uint32_t                           field_index = 0;
    sai_status_t                       status = SAI_STATUS_SUCCESS;
    mlnx_sai_fg_hash_field_t           fg_fields[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT] = {SAI_NULL_OBJECT_ID};

    SX_LOG_ENTER();


    sai_db_write_lock();

    hash_oper_id = mlnx_hash_get_oper_id(hash_id);

    if (hash_oper_id != SAI_HASH_MAX_OBJ_ID) {
        SX_LOG_ERR("Hash object is in use!\n");
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL)) {
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (g_sai_db_ptr->hash_list[hash_index].udf_group_mask || g_sai_db_ptr->hash_list[hash_index].field_mask) {
        MLNX_SAI_LOG_ERR(
            "Can not add fine grain hash field list - already configured native hash field list or UDF group list\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (value->objlist.count > MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT) {
        SX_LOG_ERR("Provided hash fields list member count is =  %u. ", value->objlist.count);
        SX_LOG_ERR("Maximum supported hash fields list members count is = %u\n", MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0;
        goto out;
    }

    for (uint32_t ind = 0; ind < value->objlist.count; ind++) {
        if (SAI_NULL_OBJECT_ID == value->objlist.list[ind]) {
            SX_LOG_ERR("NULL object in the fg fields list! ind = %u\n", ind);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0;
            goto out;
        }

        status = mlnx_object_to_type(value->objlist.list[ind],
                                     SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD,
                                     &field_index,
                                     NULL);
        if (SAI_ERR(status)) {
            goto out;
        }
        fg_fields[ind] = g_sai_db_ptr->fg_hash_fields[field_index];
    }

    status = mlnx_hash_obj_fg_fields_list_set(hash_id, fg_fields, value->objlist.count);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_sync();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_hash_udf_group_list_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t     status = SAI_STATUS_SUCCESS;
    udf_group_mask_t udf_group_mask;

    sai_db_read_lock();

    status = mlnx_hash_object_udf_group_mask_get(key->key.object_id, &udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (MLNX_UDF_GROUP_MASK_EMPTY == udf_group_mask) {
        value->objlist.count = 0;
        goto out;
    }

    status = mlnx_udf_group_mask_to_objlist(udf_group_mask, &value->objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_hash_udf_group_list_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t                       status;
    sai_object_id_t                    hash_id;
    mlnx_switch_usage_hash_object_id_t hash_oper_id;
    udf_group_mask_t                   udf_group_mask = MLNX_UDF_GROUP_MASK_EMPTY, old_udf_group_mask;
    uint32_t                           hash_index;
    bool                               is_applicable;

    hash_id = key->key.object_id;

    status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    hash_oper_id = mlnx_hash_get_oper_id(hash_id);

    status = mlnx_udf_group_objlist_validate_and_fetch_mask(&value->objlist, 0, &udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_udf_group_mask_is_hash_applicable(udf_group_mask, hash_oper_id, &is_applicable);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!is_applicable) {
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    old_udf_group_mask = g_sai_db_ptr->hash_list[hash_index].udf_group_mask;

    g_sai_db_ptr->hash_list[hash_index].udf_group_mask = udf_group_mask;

    status = mlnx_hash_config_db_changes_commit(hash_oper_id);
    if (SAI_ERR(status)) {
        g_sai_db_ptr->hash_list[hash_index].udf_group_mask = old_udf_group_mask;
        goto out;
    }

    status = mlnx_udf_group_mask_references_del(old_udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_udf_group_mask_references_add(udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

/**
 * Routine Description:
 *    @brief Create hash
 *
 * Arguments:
 *    @param[out] hash_id - hash id
 *    @param[in] attr_count - number of attributes
 *    @param[in] attr_list - array of attributes
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 *
 */
static sai_status_t mlnx_create_hash(_Out_ sai_object_id_t     * hash_id,
                                     _In_ sai_object_id_t        switch_id,
                                     _In_ uint32_t               attr_count,
                                     _In_ const sai_attribute_t *attr_list)
{
    uint32_t                     index = 0;
    const sai_attribute_value_t *native_filed_list, *udf_group_list, *fg_fields_list;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                         key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t                 status = SAI_STATUS_SUCCESS;
    mlnx_sai_fg_hash_field_t     fg_fields[MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT] = {SAI_NULL_OBJECT_ID};

    SX_LOG_ENTER();

    if (NULL == hash_id) {
        SX_LOG_ERR("NULL hash id param.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HASH, hash_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check.\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_HASH, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create hash object.\n");
    SX_LOG_NTC("Attribs %s.\n", list_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_hash_obj_create(hash_id))) {
        SX_LOG_EXIT();
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST,
                                 &native_filed_list, &index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_hash_obj_native_fields_set(*hash_id, native_filed_list);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to create %s.\n", key_str);
            mlnx_hash_obj_remove(*hash_id);
            SX_LOG_EXIT();
            return status;
        }
    }

    sai_db_write_lock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_HASH_ATTR_UDF_GROUP_LIST,
                                 &udf_group_list, &index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_hash_obj_udf_group_list_set(*hash_id, index, udf_group_list);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create %s.\n", key_str);
            goto out;
        }
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_HASH_ATTR_FINE_GRAINED_HASH_FIELD_LIST,
                                 &fg_fields_list, &index);

    if (SAI_STATUS_SUCCESS == status) {
        uint32_t field_index = 0;
        uint32_t hash_index = 0;

        if (SAI_STATUS_SUCCESS != mlnx_object_to_type(*hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL)) {
            return SAI_STATUS_FAILURE;
        }

        if (g_sai_db_ptr->hash_list[hash_index].udf_group_mask || g_sai_db_ptr->hash_list[hash_index].field_mask) {
            MLNX_SAI_LOG_ERR(
                "Can not add fine grain hash field list - already configured native hash field list or UDF group list\n");
            return SAI_STATUS_FAILURE;
        }

        if (fg_fields_list->objlist.count > MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT) {
            MLNX_SAI_LOG_ERR("Maximum supported hash fields list members count is = %u\n",
                             MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT);
            return SAI_STATUS_FAILURE;
        }
        for (uint32_t ind = 0; ind < fg_fields_list->objlist.count; ind++) {
            if (SAI_NULL_OBJECT_ID == fg_fields_list->objlist.list[ind]) {
                MLNX_SAI_LOG_ERR("NULL object in the fg fields list! ind = %u\n", ind);
                return SAI_STATUS_INVALID_OBJECT_ID;
            }

            status = mlnx_object_to_type(fg_fields_list->objlist.list[ind],
                                         SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD,
                                         &field_index,
                                         NULL);
            if (SAI_ERR(status)) {
                return SAI_STATUS_INVALID_OBJECT_ID;
            }
            fg_fields[ind] = g_sai_db_ptr->fg_hash_fields[field_index];
        }

        status = mlnx_hash_obj_fg_fields_list_set(*hash_id, fg_fields, fg_fields_list->objlist.count);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to create %s.\n", key_str);
            goto out;
        }
    }

    hash_key_to_str(*hash_id, key_str);
    SX_LOG_NTC("Created %s.\n", key_str);
    status = SAI_STATUS_SUCCESS;

out:
    sai_db_unlock();

    if (SAI_ERR(status) && (*hash_id != SAI_NULL_OBJECT_ID)) {
        mlnx_hash_obj_remove(*hash_id);
    }

    SX_LOG_EXIT();
    return status;
}

/**
 * Routine Description:
 *    @brief Remove hash
 *
 * Arguments:
 *    @param[in] hash_id - hash id
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_remove_hash(_In_ sai_object_id_t hash_id)
{
    uint32_t     hash_data = 0;
    char         key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    /* Validate object */
    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL))) {
        return status;
    }

    hash_key_to_str(hash_id, key_str);
    SX_LOG_NTC("Remove %s.\n", key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_hash_obj_remove(hash_id))) {
        SX_LOG_ERR("Failed to remove %s - err %d\n", key_str, status);
    }

    SX_LOG_EXIT();
    return status;
}

/**
 * Routine Description:
 *    @brief Set hash attribute
 *
 * Arguments:
 *    @param[in] hash_id - hash id
 *    @param[in] attr - attribute
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_set_hash_attribute(_In_ sai_object_id_t hash_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = hash_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    hash_key_to_str(hash_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_HASH, hash_vendor_attribs, attr);
}

/**
 * Routine Description:
 *    @brief Get hash attribute value
 *
 * Arguments:
 *    @param[in] hash_id - hash id
 *    @param[in] attr_count - number of attributes
 *    @param[inout] attrs - array of attributes
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_get_hash_attribute(_In_ sai_object_id_t     hash_id,
                                            _In_ uint32_t            attr_count,
                                            _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = hash_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    hash_key_to_str(hash_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_HASH, hash_vendor_attribs, attr_count, attr_list);
}
/*do not need this func, only print index */
static void fg_hash_field_key_to_str(_In_ sai_object_id_t hash_field_id, _Out_ char *key_str)
{
    sai_status_t     status;
    uint32_t         field_index;
    char             ip_str[40];
    sai_ip_address_t ip;

    status = mlnx_object_to_type(hash_field_id, SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD, &field_index, NULL);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid FG hash field id");
        return;
    }

    switch (g_sai_db_ptr->fg_hash_fields[field_index].field) {
    case SAI_NATIVE_HASH_FIELD_DST_IPV4:
    case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
    case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
    case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
        ip.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ip.addr = g_sai_db_ptr->fg_hash_fields[field_index].ip_mask;
        status = sai_ipaddr_to_str(ip, 40 - 1, ip_str, NULL);
        if (SAI_ERR(status)) {
            strcpy(ip_str, "-");
        }
        break;

    case SAI_NATIVE_HASH_FIELD_DST_IPV6:
    case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
    case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
    case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
        ip.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        ip.addr = g_sai_db_ptr->fg_hash_fields[field_index].ip_mask;
        status = sai_ipaddr_to_str(ip, 40 - 1, ip_str, NULL);
        if (SAI_ERR(status)) {
            strcpy(ip_str, "-");
        }
        break;

    default:
        strcpy(ip_str, "-");
        break;
    }

    snprintf(key_str,
             MAX_KEY_STR_LEN,
             "FG hash field [%u] type (field:%s, mask:%s, sequence_id: %u)",
             field_index,
             MLNX_SAI_NATIVE_HASH_FIELD_STR(g_sai_db_ptr->fg_hash_fields[field_index].field),
             ip_str,
             g_sai_db_ptr->fg_hash_fields[field_index].sequence_id);
}

void pbhash_offset_and_size_calculate(uint16_t mask, uint8_t *offset, uint8_t *size)
{
    uint8_t ii = 0;
    bool    first_found = false;

    for (ii = 0; ii < 16; ++ii) {
        if (!first_found) {
            if (!((mask >> ii) & 0x1)) {
                continue;
            } else {
                *offset = ii;
                first_found = true;
            }
        } else {
            if ((mask >> ii) & 0x1) {
                continue;
            } else {
                break;
            }
        }
    }
    *size = ii - *offset;
}

/*
 * Check the IP mask. Supported a simple IP mask which have only one sequence of bits
 * for every 16 bits
 */
static sai_status_t fg_hash_field_ip_mask_check(sai_ip_address_t addr)
{
    uint16_t mask = 0;
    uint16_t ii = 0;
    uint8_t  size = 0;
    uint8_t  offset = 0;

    if (addr.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        if (0 != (mask = addr.addr.ip4 >> 16)) {
            pbhash_offset_and_size_calculate(mask, &offset, &size);
            for (ii = offset + size; ii < 16; ++ii) {
                if ((mask >> ii) & 0x1) {
                    return SAI_STATUS_FAILURE;
                }
            }
        }
        if (0 != (mask = addr.addr.ip4 & 0xFFFF)) {
            pbhash_offset_and_size_calculate(mask, &offset, &size);
            for (ii = offset + size; ii < 16; ++ii) {
                if ((mask >> ii) & 0x1) {
                    return SAI_STATUS_FAILURE;
                }
            }
        }
    } else {
        for (int ii = 0; ii < 16; ii += 2) {
            mask = (addr.addr.ip6[ii] << 8) | addr.addr.ip6[ii + 1];
            SX_LOG_DBG("mask = %x, addr.addr.ip6[%i] = %x, addr.addr.ip6[%i] = %x\n",
                       mask,
                       ii,
                       addr.addr.ip6[ii],
                       ii + 1,
                       addr.addr.ip6[ii + 1]);
            if (mask) {
                pbhash_offset_and_size_calculate(mask, &offset, &size);
                for (int jj = offset + size; jj < 16; ++jj) {
                    if ((mask >> jj) & 0x1) {
                        return SAI_STATUS_FAILURE;
                    }
                }
            }
        }
    }
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Create fine grained hash field
 *
 * Arguments:
 *   [out] hash_field_id - fg hash field id
 *   [in] attr_count - number of attributes
 *   [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_fine_grained_hash_field(_Out_ sai_object_id_t      *hash_field_id,
                                                        _In_ sai_object_id_t        switch_id,
                                                        _In_ uint32_t               attr_count,
                                                        _In_ const sai_attribute_t *attr_list)
{
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    const sai_attribute_value_t *hash_field = NULL, *sequence = NULL, *mask = NULL;
    sai_ip_address_t             addr;
    uint32_t                     field_index;
    uint32_t                     sequence_id;
    uint32_t                     obj_index = 0;
    sai_status_t                 status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if (NULL == hash_field_id) {
        SX_LOG_ERR("NULL FG hash field ID\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD,
                                    fg_hash_field_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attributes check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD, MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create fine grain hash field object. Attributes %s.\n", list_str);

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_FINE_GRAINED_HASH_FIELD_ATTR_NATIVE_HASH_FIELD,
                                 &hash_field,
                                 &field_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_FINE_GRAINED_HASH_FIELD_ATTR_SEQUENCE_ID,
                                 &sequence,
                                 &field_index);
    if (status != SAI_STATUS_SUCCESS) {
        if (SAI_STATUS_ITEM_NOT_FOUND == status) {
            sequence_id = 0;
        } else {
            return status;
        }
    } else {
        if (sequence->u32 == 0xffffffff) {
            SX_LOG_ERR("Reserved sequence ID value\n");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + field_index;
        }
        sequence_id = sequence->u32 + 1;
    }

    if (SAI_ERR(status = mlnx_fg_hash_field_obj_create(hash_field_id, &obj_index))) {
        SX_LOG_ERR("Filed to create hash field obj\n");
        return status;
    }

    sai_db_write_lock();

    switch (hash_field->s32) {
    case SAI_NATIVE_HASH_FIELD_DST_IPV4:
    case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
    case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
    case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
        status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV4_MASK,
                                     &mask,
                                     &field_index);
        assert(SAI_STATUS_SUCCESS == status);

        addr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        addr.addr.ip4 = mask->ip4;
        if (SAI_ERR(status = fg_hash_field_ip_mask_check(addr))) {
            SX_LOG_ERR(
                "Such IPv4 mask is not supported! Supported a simple IP mask which have only one sequence of bits. \n");
            goto out;
        }
        g_sai_db_ptr->fg_hash_fields[obj_index].ip_mask.ip4 = mask->ip4;
        break;

    case SAI_NATIVE_HASH_FIELD_DST_IPV6:
    case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
    case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
    case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
        status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV6_MASK,
                                     &mask,
                                     &field_index);
        assert(SAI_STATUS_SUCCESS == status);

        addr.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(addr.addr.ip6, mask->ip6, sizeof(sai_ip6_t));
        if (SAI_ERR(status = fg_hash_field_ip_mask_check(addr))) {
            SX_LOG_ERR(
                "Such IPv6 mask is not supported! Supported a simple IP mask which have only one sequence of bits. \n");
            goto out;
        }
        memcpy(g_sai_db_ptr->fg_hash_fields[obj_index].ip_mask.ip6, mask->ip6, sizeof(sai_ip6_t));
        break;

    default:
        memset(&g_sai_db_ptr->fg_hash_fields[obj_index].ip_mask, 0, sizeof(sai_ip_addr_t));
        break;
    }

    g_sai_db_ptr->fg_hash_fields[obj_index].fg_field_id = *hash_field_id;
    g_sai_db_ptr->fg_hash_fields[obj_index].field = hash_field->s32;
    g_sai_db_ptr->fg_hash_fields[obj_index].sequence_id = sequence_id;
    fg_hash_field_key_to_str(*hash_field_id, key_str);

    SX_LOG_NTC("Created %s.\n", key_str);

out:
    SX_LOG_EXIT();
    if (SAI_ERR(status)) {
        g_sai_db_ptr->fg_hash_fields[obj_index].fg_field_id = SAI_NULL_OBJECT_ID;
    }
    sai_db_sync();
    sai_db_unlock();
    return status;
}

/* Remove FG hash field object from DB if object is not in-use */
static sai_status_t mlnx_fg_hash_field_obj_remove(sai_object_id_t field_id)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     field_index = 0;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(field_id, SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD, &field_index,
                                                  NULL)) {
        return SAI_STATUS_FAILURE;
    }

    sai_db_write_lock();

    for (uint32_t ii = 0; ii < SAI_HASH_MAX_OBJ_COUNT; ++ii) {
        for (uint32_t jj = 0; jj < MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT; ++jj) {
            if (g_sai_db_ptr->hash_list[ii].fg_fields[jj].fg_field_id == field_id) {
                status = SAI_STATUS_OBJECT_IN_USE;
                goto out;
            }
        }
    }
    memset(&g_sai_db_ptr->fg_hash_fields[field_index], 0, sizeof(mlnx_sai_fg_hash_field_t));

out:
    sai_db_sync();
    sai_db_unlock();
    return status;
}

/*
 * Routine Description:
 *   Remove fine grained hash field
 *
 * Arguments:
 *   [in] field_id - fg hash field id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_remove_fine_grained_hash_field(_In_ sai_object_id_t field_id)
{
    sai_status_t status;
    char         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    sai_db_read_lock();
    fg_hash_field_key_to_str(field_id, key_str);
    sai_db_unlock();

    if (SAI_ERR(status = mlnx_fg_hash_field_obj_remove(field_id))) {
        SX_LOG_ERR("Failed to remove %s - err %d\n", key_str, status);
    }

    SX_LOG_EXIT();
    return status;
}

/**
 * Routine Description:
 *    @brief Set hash attribute
 *
 * Arguments:
 *    @param[in] hash_id - hash id
 *    @param[in] attr - attribute
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_set_fine_grained_hash_field_attribute(_In_ sai_object_id_t        hash_fields_id,
                                                               _In_ const sai_attribute_t *attr)
{
    MLNX_SAI_LOG_ERR("Set is not supported for fine grained hash field attribute.");

    /*TODO add code */

    return SAI_STATUS_NOT_SUPPORTED;
}

static sai_status_t mlnx_get_fine_grained_hash_field_attribute(_In_ sai_object_id_t     fine_grained_hash_field_id,
                                                               _In_ uint32_t            attr_count,
                                                               _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = fine_grained_hash_field_id };
    char                   key_str[MAX_KEY_STR_LEN];

    sai_db_read_lock();
    fg_hash_field_key_to_str(fine_grained_hash_field_id, key_str);
    sai_db_unlock();

    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD,
                              hash_vendor_attribs,
                              attr_count,
                              attr_list);
}

static sai_status_t mlnx_fine_grained_hash_field_attribute_get(_In_ const sai_object_key_t   *key,
                                                               _Inout_ sai_attribute_value_t *value,
                                                               _In_ uint32_t                  attr_index,
                                                               _Inout_ vendor_cache_t        *cache,
                                                               void                          *arg)
{
    sai_status_t            status;
    uint32_t                field_index;
    sai_native_hash_field_t hash_field;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_FINE_GRAINED_HASH_FIELD, &field_index, NULL);
    if (SAI_ERR(status)) {
        goto out;
    }

    sai_db_read_lock();
    hash_field = g_sai_db_ptr->fg_hash_fields[field_index].field;

    switch ((int64_t)arg) {
    case SAI_FINE_GRAINED_HASH_FIELD_ATTR_NATIVE_HASH_FIELD:
        value->s32 = g_sai_db_ptr->fg_hash_fields[field_index].field;
        break;

    case SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV4_MASK:
        if ((hash_field != SAI_NATIVE_HASH_FIELD_SRC_IPV4)
            && (hash_field != SAI_NATIVE_HASH_FIELD_DST_IPV4)
            && (hash_field != SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4)
            && (hash_field != SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4)) {
            SX_LOG_ERR("IPv4 mask is not supported for this field\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        value->ip4 = g_sai_db_ptr->fg_hash_fields[field_index].ip_mask.ip4;
        break;

    case SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV6_MASK:
        if ((hash_field != SAI_NATIVE_HASH_FIELD_SRC_IPV6)
            && (hash_field != SAI_NATIVE_HASH_FIELD_DST_IPV6)
            && (hash_field != SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6)
            && (hash_field != SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6)) {
            SX_LOG_ERR("IPv6 mask is not supported for this field\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        memcpy(value->ip6, g_sai_db_ptr->fg_hash_fields[field_index].ip_mask.ip6,
               sizeof(g_sai_db_ptr->fg_hash_fields[field_index].ip_mask.ip6));
        break;

    case SAI_FINE_GRAINED_HASH_FIELD_ATTR_SEQUENCE_ID:
        value->s32 = g_sai_db_ptr->fg_hash_fields[field_index].sequence_id;
        break;

    default:
        SX_LOG_ERR("Unexpected type of arg (%ld)\n", (int64_t)arg);
        assert(false);
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

bool mlnx_sai_hash_check_optimized_hash_use_case(_In_ uint32_t hash_index, _In_ uint32_t fields_num)
{
    uint8_t  optimized_fields_num = 7;
    uint8_t  tmp_count = 0;
    uint32_t ii = 0;
    uint32_t inner_src_ipv4_seq_id = 0xffffffff;
    uint32_t inner_dst_ipv4_seq_id = 0xffffffff;
    uint32_t inner_src_ipv6_seq_id = 0xffffffff;
    uint32_t inner_dst_ipv6_seq_id = 0xffffffff;
    uint32_t inner_l4_src_seq_id = 0xffffffff;
    uint32_t inner_l4_dst_seq_id = 0xffffffff;
    bool     seq_ids_equal = false;

    /* check optimized hash use case */
    for (ii = 0; ii < fields_num; ++ii) {
        sai_ip6_t mask = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff };
        switch (g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].field) {
        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
        case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
            if (g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].ip_mask.ip4 == 0xffffffff) {
                if (SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4 == g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].field) {
                    inner_src_ipv4_seq_id = g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].sequence_id;
                } else {
                    inner_dst_ipv4_seq_id = g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].sequence_id;
                }
                ++tmp_count;
            }
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
        case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
            if (!memcmp(&(g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].ip_mask.ip6[0]), &mask[0],
                        sizeof(sai_ip6_t))) {
                if (SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6 == g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].field) {
                    inner_src_ipv6_seq_id = g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].sequence_id;
                } else {
                    inner_dst_ipv6_seq_id = g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].sequence_id;
                }
                ++tmp_count;
            }
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
        case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
            if (SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT == g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].field) {
                inner_l4_src_seq_id = g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].sequence_id;
            } else {
                inner_l4_dst_seq_id = g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].sequence_id;
            }
            ++tmp_count;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_IP_PROTOCOL:
            ++tmp_count;
            break;

        default:
            tmp_count = 0;
            break;
        }
    }

    seq_ids_equal = (inner_src_ipv4_seq_id == inner_dst_ipv4_seq_id) &&
                    (inner_src_ipv6_seq_id == inner_dst_ipv6_seq_id) &&
                    (inner_l4_src_seq_id == inner_l4_dst_seq_id);

    return ((tmp_count == optimized_fields_num) && seq_ids_equal);
}

sai_status_t mlnx_fine_grained_hash_create(_In_ sai_object_id_t                hash_id,
                                           _In_ sx_flex_acl_action_hash_type_t action_type,
                                           _Inout_ sx_flex_acl_flex_action_t  *action_list,
                                           _Inout_ uint32_t                   *action_num)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     hash_index;
    uint32_t     fields_num = 0;
    bool         revert_regs = false;
    bool         optimized_hash = false;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_init_flex_parser())) {
        SX_LOG_ERR("Failed to init_flex_parser\n");
        return status;
    }

    if ((g_sai_db_ptr->oper_hash_list[SAI_HASH_FG_1_ID] != SAI_NULL_OBJECT_ID) &&
        (g_sai_db_ptr->oper_hash_list[SAI_HASH_FG_2_ID] != SAI_NULL_OBJECT_ID) &&
        (g_sai_db_ptr->hash_list[hash_index].fg_hash_ref_count == 0)) {
        SX_LOG_ERR("Maximum possible number of fine-grained hash are already configured! \n");
        return SAI_STATUS_TABLE_FULL;
    }

    for (uint32_t ii = 0; ii < MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT; ++ii) {
        if (g_sai_db_ptr->hash_list[hash_index].fg_fields[ii].fg_field_id != SAI_NULL_OBJECT_ID) {
            ++fields_num;
        }
    }

    optimized_hash = mlnx_sai_hash_check_optimized_hash_use_case(hash_index, fields_num);

    if (g_sai_db_ptr->hash_list[hash_index].fg_hash_ref_count == 0) {
        if (SAI_ERR(status =
                        gp_registers_availability_check(fields_num, g_sai_db_ptr->hash_list[hash_index].fg_fields,
                                                        optimized_hash))) {
            MLNX_SAI_LOG_ERR("Not enough available general purpose registers for FG hash function!\n");
            goto out;
        }

        if (SAI_ERR(status =
                        gp_registers_allocation(fields_num, g_sai_db_ptr->hash_list[hash_index].fg_fields,
                                                optimized_hash))) {
            MLNX_SAI_LOG_ERR("Failed to allocate general purpose registers for FG hash function!\n");
            revert_regs = true;
            goto out;
        }
    }

    if (!optimized_hash) {
        mlnx_fg_hash_action_list_create(action_type,
                                        fields_num,
                                        g_sai_db_ptr->hash_list[hash_index].fg_fields,
                                        action_list,
                                        action_num);
    } else {
        mlnx_fg_optimized_hash_action_list_create(action_type,
                                                  fields_num,
                                                  g_sai_db_ptr->hash_list[hash_index].fg_fields,
                                                  action_list,
                                                  action_num);
    }

    g_sai_db_ptr->hash_list[hash_index].fg_hash_ref_count++;

out:
    if (revert_regs) {
        gp_registers_delete(g_sai_db_ptr->hash_list[hash_index].fg_fields);
    }
    return status;
}

static sai_status_t gp_registers_availability_check(_In_ uint32_t                        fields_count,
                                                    _In_ const mlnx_sai_fg_hash_field_t *fields_list,
                                                    _In_ bool                            optimized)
{
    uint8_t                 needed_reg_num = 0;
    uint8_t                 available_reg_num = 0;
    mlnx_shm_rm_array_idx_t reg_db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    mlnx_gp_reg_db_t       *gp_reg_db = NULL;
    uint32_t                gp_ger_max_num = 0;

    if (((fields_count) && (NULL == fields_list)) || (0 == fields_count)) {
        SX_LOG_ERR("NULL value fields list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (uint32_t ii = 0; ii < fields_count; ++ii) {
        if (fields_list[ii].sequence_id == fields_list[ii + 1].sequence_id) {
            uint16_t mask = 0;
            switch (fields_list[ii].field) {
            case SAI_NATIVE_HASH_FIELD_DST_IPV4:
            case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
                if (0 != (mask = fields_list[ii].ip_mask.ip4 >> 16)) {
                    needed_reg_num += 2;
                }
                if (0 != (mask = fields_list[ii].ip_mask.ip4 & 0xFFFF)) {
                    needed_reg_num += 2;
                }
                break;

            case SAI_NATIVE_HASH_FIELD_DST_IPV6:
            case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
                if (!optimized) {
                    for (int jj = 0; jj < 16; jj += 2) {
                        if ((0 != (fields_list[ii].ip_mask.ip6[jj] & 0xFF)) ||
                            (0 != (fields_list[ii].ip_mask.ip6[jj + 1] & 0xFF))) {
                            needed_reg_num += 2;
                        }
                    }
                }
                break;

            case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
                needed_reg_num += 2;
                break;

            default:
                break;
            }
            ++ii;
        }
    }

    gp_ger_max_num = g_resource_limits.gp_register_num_max;
    for (uint32_t ii = 0; ii < gp_ger_max_num; ++ii) {
        reg_db_idx.type = MLNX_SHM_RM_ARRAY_TYPE_GP_REG;
        reg_db_idx.idx = ii;
        if (SAI_ERR(mlnx_gp_reg_db_idx_to_data(reg_db_idx, &gp_reg_db))) {
            SX_LOG_ERR("mlnx_gp_reg_db_idx_to_data() FAILED\n");
            return SAI_STATUS_ITEM_NOT_FOUND;
        }

        if (gp_reg_db->gp_usage == GP_REG_USED_NONE) {
            ++available_reg_num;
        }
    }

    if (available_reg_num < needed_reg_num) {
        SX_LOG_ERR("Available number of registers [%u]. Requested number of registers [%u]\n",
                   available_reg_num,
                   needed_reg_num);
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t ipv4_reg_lookup(_Inout_ mlnx_gp_reg_db_t           **gp_reg_db_data,
                                    _Inout_ mlnx_shm_rm_array_idx_t     *db_idx,
                                    _In_ const mlnx_sai_fg_hash_field_t *field,
                                    _In_ bool                            is_gp_reg_restore,
                                    _In_ mlnx_gp_reg_usage_t             gp_reg_usage,
                                    _In_ mlnx_gp_reg_usage_t             gp_reg_usage_prev)
{
    sai_status_t     status = SAI_STATUS_SUCCESS;
    sx_gp_register_e reg_id = SX_GP_REGISTER_LAST_E;

    assert(gp_reg_db_data);
    assert(db_idx);
    assert(field);

    if (is_gp_reg_restore) {
        status = mlnx_sai_issu_storage_pbh_gp_reg_idx_lookup(field->field,
                                                             gp_reg_usage_prev,
                                                             &reg_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get register in persistent DB\n");
            return status;
        }

        status = mlnx_gp_reg_db_alloc_by_gp_reg_id(gp_reg_db_data, reg_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to allocate register for PBH field %d\n", field->field);
            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }
        db_idx->type = MLNX_SHM_RM_ARRAY_TYPE_GP_REG;
        db_idx->idx = reg_id;
    } else {
        if (SAI_ERR(status = mlnx_gp_reg_db_alloc_first_free(gp_reg_db_data, db_idx, gp_reg_usage))) {
            SX_LOG_ERR("GP registers DB is full\n");
            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    return status;
}

static sai_status_t ipv4_reg_allocate(_Inout_ mlnx_sai_fg_hash_field_t *field,
                                      _In_ bool                         optimized,
                                      _In_ bool                         is_gp_reg_restore,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage_prev)
{
    sx_status_t           sx_status;
    sx_register_key_t     reg_key;
    sx_extraction_point_t extraction_point_list[2];
    uint32_t              reg_key_cnt = 1;
    uint32_t              ext_point_cnt = 1;
    uint16_t              mask = 0;
    sai_status_t          status = SAI_STATUS_SUCCESS;

    if (0 != (mask = field->ip_mask.ip4 >> 16)) {
        mlnx_gp_reg_db_t       *gp_reg_db_data = NULL;
        mlnx_shm_rm_array_idx_t db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

        status = ipv4_reg_lookup(&gp_reg_db_data,
                                 &db_idx,
                                 field,
                                 is_gp_reg_restore,
                                 gp_reg_usage,
                                 gp_reg_usage_prev);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("GP register lookup failed\n");
            return status;
        }

        if ((db_idx.idx + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0 > SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_7)
            && ((field->field == SAI_NATIVE_HASH_FIELD_DST_IPV4)
                || (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4))) {
            SX_LOG_ERR("Not enough GP register to perform hash CRC command\n");
            mlnx_gp_reg_db_free(db_idx);
            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }
        reg_key.type = SX_REGISTER_KEY_TYPE_GENERAL_PURPOSE_E;
        reg_key.key.gp_reg.reg_id = db_idx.idx;

        if (SX_ERR(sx_status = sx_api_register_set(gh_sdk, SX_ACCESS_CMD_CREATE, &reg_key, &reg_key_cnt))) {
            SX_LOG_ERR("Failed to create register %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(sx_status);
        }
        if (!optimized) {
            ext_point_cnt = 1;
            if ((field->field == SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4)
                || (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4)) {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV4_START_OF_HEADER_E;
            } else {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_IPV4_START_OF_HEADER_E;
            }

            if ((field->field == SAI_NATIVE_HASH_FIELD_SRC_IPV4)
                || (field->field == SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4)) {
                extraction_point_list[0].offset = 12;
            } else {
                extraction_point_list[0].offset = 16;
            }
        } else {
            ext_point_cnt = 2;
            if (field->field == SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4) {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV4_START_OF_HEADER_E;
                extraction_point_list[0].offset = 12;
                extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV6_START_OF_HEADER_E;
                extraction_point_list[1].offset = 20;
            } else if (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4) {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV4_START_OF_HEADER_E;
                extraction_point_list[0].offset = 16;
                extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV6_START_OF_HEADER_E;
                extraction_point_list[1].offset = 36;
            }
        }
        sx_status = sx_api_flex_parser_reg_ext_point_set(gh_sdk,
                                                         SX_ACCESS_CMD_SET,
                                                         reg_key,
                                                         extraction_point_list,
                                                         &ext_point_cnt);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set extraction point for GP register %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
        field->reg_id[0] = reg_key;
        field->shm_rm_array_idx[0] = db_idx;
        gp_reg_db_data->gp_usage = gp_reg_usage;
    }
    if (0 != (mask = field->ip_mask.ip4 & 0xFFFF)) {
        mlnx_gp_reg_db_t       *gp_reg_db_data = NULL;
        mlnx_shm_rm_array_idx_t db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;

        status = ipv4_reg_lookup(&gp_reg_db_data,
                                 &db_idx,
                                 field,
                                 is_gp_reg_restore,
                                 gp_reg_usage,
                                 gp_reg_usage_prev);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("GP register lookup failed\n");
            return status;
        }

        if ((db_idx.idx + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0 > SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_7)
            && ((field->field == SAI_NATIVE_HASH_FIELD_DST_IPV4)
                || (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4))) {
            SX_LOG_ERR("Not enough GP register to perform hash CRC command\n");
            mlnx_gp_reg_db_free(db_idx);
            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }

        reg_key.type = SX_REGISTER_KEY_TYPE_GENERAL_PURPOSE_E;
        reg_key.key.gp_reg.reg_id = db_idx.idx;

        if (SX_ERR(sx_status = sx_api_register_set(gh_sdk, SX_ACCESS_CMD_CREATE, &reg_key, &reg_key_cnt))) {
            SX_LOG_ERR("Failed to create register %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
        if (!optimized) {
            ext_point_cnt = 1;
            if ((field->field == SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4)
                || (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4)) {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV4_START_OF_HEADER_E;
            } else {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_IPV4_START_OF_HEADER_E;
            }

            if ((field->field == SAI_NATIVE_HASH_FIELD_SRC_IPV4)
                || (field->field == SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4)) {
                extraction_point_list[0].offset = 14;
            } else {
                extraction_point_list[0].offset = 18;
            }
        } else {
            ext_point_cnt = 2;
            if (field->field == SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4) {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV4_START_OF_HEADER_E;
                extraction_point_list[0].offset = 14;
                extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV6_START_OF_HEADER_E;
                extraction_point_list[1].offset = 22;
            } else if (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4) {
                extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV4_START_OF_HEADER_E;
                extraction_point_list[0].offset = 18;
                extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV6_START_OF_HEADER_E;
                extraction_point_list[1].offset = 38;
            }
        }
        sx_status = sx_api_flex_parser_reg_ext_point_set(gh_sdk,
                                                         SX_ACCESS_CMD_SET,
                                                         reg_key,
                                                         extraction_point_list,
                                                         &ext_point_cnt);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set extraction point for GP register %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
        field->reg_id[1] = reg_key;
        field->shm_rm_array_idx[1] = db_idx;

        gp_reg_db_data->gp_usage = gp_reg_usage;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t ipv6_reg_allocate(_Inout_ mlnx_sai_fg_hash_field_t *field,
                                      _In_ bool                         optimized,
                                      _In_ bool                         is_gp_reg_restore,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage,
                                      _In_ mlnx_gp_reg_usage_t          gp_reg_usage_prev)
{
    sx_status_t           sx_status;
    sx_register_key_t     reg_key;
    sx_extraction_point_t extraction_point_list[2];
    uint32_t              reg_key_cnt = 1;
    uint32_t              ext_point_cnt = 1;
    sai_status_t          status = SAI_STATUS_SUCCESS;
    sx_gp_register_e      reg_id = SX_GP_REGISTER_LAST_E;

    if (!optimized) {
        for (int jj = 0; jj < 16; jj += 2) {
            if ((0 != (field->ip_mask.ip6[jj] & 0xFF)) || (0 != (field->ip_mask.ip6[jj + 1] & 0xFF))) {
                mlnx_gp_reg_db_t       *gp_reg_db_data;
                mlnx_shm_rm_array_idx_t db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
                if (is_gp_reg_restore) {
                    status = mlnx_sai_issu_storage_pbh_gp_reg_idx_lookup(field->field,
                                                                         gp_reg_usage_prev,
                                                                         &reg_id);
                    if (SAI_ERR(status)) {
                        SX_LOG_ERR("Failed to get register in persistent DB\n");
                        return status;
                    }

                    status = mlnx_gp_reg_db_alloc_by_gp_reg_id(&gp_reg_db_data, reg_id);
                    if (SAI_ERR(status)) {
                        SX_LOG_ERR("Failed to allocate register for PBH field %d\n", field->field);
                        return SAI_STATUS_INSUFFICIENT_RESOURCES;
                    }
                    db_idx.type = MLNX_SHM_RM_ARRAY_TYPE_GP_REG;
                    db_idx.idx = reg_id;
                } else {
                    if (SAI_ERR(status = mlnx_gp_reg_db_alloc_first_free(&gp_reg_db_data, &db_idx, gp_reg_usage))) {
                        SX_LOG_ERR("GP registers DB is full\n");
                        return SAI_STATUS_INSUFFICIENT_RESOURCES;
                    }
                }

                if ((db_idx.idx + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0 > SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_7)
                    && ((field->field == SAI_NATIVE_HASH_FIELD_DST_IPV6)
                        || (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6))) {
                    SX_LOG_ERR("Not enough GP register to perform hash CRC command\n");
                    mlnx_gp_reg_db_free(db_idx);
                    return SAI_STATUS_INSUFFICIENT_RESOURCES;
                }

                reg_key.type = SX_REGISTER_KEY_TYPE_GENERAL_PURPOSE_E;
                reg_key.key.gp_reg.reg_id = db_idx.idx;

                if (SAI_ERR(sx_status = sx_api_register_set(gh_sdk, SX_ACCESS_CMD_CREATE, &reg_key, &reg_key_cnt))) {
                    SX_LOG_ERR("Failed to create register %s.\n", SX_STATUS_MSG(sx_status));
                    return sdk_to_sai(sx_status);
                }
                ext_point_cnt = 1;
                if (field->field == SAI_NATIVE_HASH_FIELD_SRC_IPV6) {
                    extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_IPV6_START_OF_HEADER_E;
                    extraction_point_list[0].offset = 8 + jj;
                } else if (field->field == SAI_NATIVE_HASH_FIELD_DST_IPV6) {
                    extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_IPV6_START_OF_HEADER_E;
                    extraction_point_list[0].offset = 24 + jj;
                } else if (field->field == SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6) {
                    extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV6_START_OF_HEADER_E;
                    extraction_point_list[0].offset = 8 + jj;
                } else if (field->field == SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6) {
                    extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_IPV6_START_OF_HEADER_E;
                    extraction_point_list[0].offset = 24 + jj;
                }
                sx_status = sx_api_flex_parser_reg_ext_point_set(gh_sdk,
                                                                 SX_ACCESS_CMD_SET,
                                                                 reg_key,
                                                                 extraction_point_list,
                                                                 &ext_point_cnt);
                if (SX_ERR(sx_status)) {
                    SX_LOG_ERR("Failed to set extraction point for GP register %s.\n", SX_STATUS_MSG(sx_status));
                    return sdk_to_sai(sx_status);
                }
                field->reg_id[jj / 2] = reg_key;
                field->shm_rm_array_idx[jj / 2] = db_idx;

                gp_reg_db_data->gp_usage = gp_reg_usage;
            }
        }
    }
    return status;
}

static sai_status_t l4_reg_allocate(_Inout_ mlnx_sai_fg_hash_field_t *field,
                                    _In_ bool                         is_gp_reg_restore,
                                    _In_ mlnx_gp_reg_usage_t          gp_reg_usage,
                                    _In_ mlnx_gp_reg_usage_t          gp_reg_usage_prev)
{
    sai_status_t            status = SAI_STATUS_SUCCESS;
    sx_register_key_t       reg_key = {0};
    sx_status_t             sx_status = SX_STATUS_SUCCESS;
    sx_extraction_point_t   extraction_point_list[2] = {0};
    uint32_t                reg_key_cnt = 1;
    uint32_t                ext_point_cnt = 1;
    mlnx_gp_reg_db_t       *gp_reg_db_data = NULL;
    mlnx_shm_rm_array_idx_t db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    sx_gp_register_e        reg_id = SX_GP_REGISTER_LAST_E;

    if (is_gp_reg_restore) {
        status = mlnx_sai_issu_storage_pbh_gp_reg_idx_lookup(field->field,
                                                             gp_reg_usage_prev,
                                                             &reg_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get register in persistent DB\n");
            goto out;
        }

        status = mlnx_gp_reg_db_alloc_by_gp_reg_id(&gp_reg_db_data, reg_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to allocate register for PBH field %d\n", field->field);
            goto out;
        }
        db_idx.type = MLNX_SHM_RM_ARRAY_TYPE_GP_REG;
        db_idx.idx = reg_id;
    } else {
        if (SAI_ERR(status = mlnx_gp_reg_db_alloc_first_free(&gp_reg_db_data, &db_idx, gp_reg_usage))) {
            SX_LOG_ERR("GP registers DB is full\n");
            status = SAI_STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    }
    if ((db_idx.idx + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0 > SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_7)
        && ((field->field == SAI_NATIVE_HASH_FIELD_L4_DST_PORT)
            || (field->field == SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT))) {
        SX_LOG_ERR("Not enough GP register to perform hash CRC command\n");
        mlnx_gp_reg_db_free(db_idx);
        status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    reg_key.type = SX_REGISTER_KEY_TYPE_GENERAL_PURPOSE_E;
    reg_key.key.gp_reg.reg_id = db_idx.idx;

    if (SX_ERR(sx_status =
                   sx_api_register_set(gh_sdk, SX_ACCESS_CMD_CREATE, &reg_key, &reg_key_cnt))) {
        SX_LOG_ERR("Failed to create register %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    ext_point_cnt = 2;
    if (field->field == SAI_NATIVE_HASH_FIELD_L4_SRC_PORT) {
        extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_TCP_HEADER_E;
        extraction_point_list[0].offset = 0;
        extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_UDP_HEADER_E;
        extraction_point_list[1].offset = 0;
    } else if (field->field == SAI_NATIVE_HASH_FIELD_L4_DST_PORT) {
        extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_TCP_HEADER_E;
        extraction_point_list[0].offset = 2;
        extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_UDP_HEADER_E;
        extraction_point_list[1].offset = 2;
    } else if (field->field == SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT) {
        extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_TCP_HEADER_E;
        extraction_point_list[0].offset = 0;
        extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_INNER_UDP_HEADER_E;
        extraction_point_list[1].offset = 0;
    } else if (field->field == SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT) {
        extraction_point_list[0].type = SX_EXTRACTION_POINT_TYPE_INNER_TCP_HEADER_E;
        extraction_point_list[0].offset = 2;
        extraction_point_list[1].type = SX_EXTRACTION_POINT_TYPE_INNER_UDP_HEADER_E;
        extraction_point_list[1].offset = 2;
    }
    sx_status = sx_api_flex_parser_reg_ext_point_set(gh_sdk,
                                                     SX_ACCESS_CMD_SET,
                                                     reg_key,
                                                     extraction_point_list,
                                                     &ext_point_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set extraction point for GP register %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }
    field->reg_id[0] = reg_key;
    field->shm_rm_array_idx[0] = db_idx;

    gp_reg_db_data->gp_usage = gp_reg_usage;

out:
    return status;
}

static sai_status_t gp_registers_allocation(_In_ uint32_t                     fields_count,
                                            _Inout_ mlnx_sai_fg_hash_field_t *fields_list,
                                            _In_ bool                         optimized)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_gp_reg_usage_t gp_reg_usage = GP_REG_USED_NONE;
    mlnx_gp_reg_usage_t gp_reg_usage_prev = GP_REG_USED_NONE;
    const bool          is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                                 (!g_sai_db_ptr->issu_end_called);
    bool is_gp_reg_restore = false;

    if (((fields_count) && (NULL == fields_list)) || (0 == fields_count)) {
        SX_LOG_ERR("NULL value fields list\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (g_sai_db_ptr->oper_hash_list[SAI_HASH_FG_1_ID] == SAI_NULL_OBJECT_ID) {
        gp_reg_usage = GP_REG_USED_HASH_1;
    } else {
        gp_reg_usage = GP_REG_USED_HASH_2;
    }

    /* regular transition between dynamic PBH to dynamic PBH on warmboot */
    if (g_sai_db_ptr->is_issu_gp_reg_restore) {
        /* check if allocation of register is required for current field list */
        for (uint32_t ind = 0; ind < fields_count; ++ind) {
            if (fields_list[ind].sequence_id == fields_list[ind + 1].sequence_id) {
                is_gp_reg_restore = true;
                break;
            }
        }
        /* Special case: transition between static PBH to dynamic PBH on warmboot */
    } else if (is_warmboot_init_stage && g_sai_db_ptr->pbhash_transition) {
        is_gp_reg_restore = true;
    }

    if (is_gp_reg_restore) {
        status = mlnx_sai_issu_storage_get_pbh_stored_gp_reg_usage(fields_count,
                                                                   fields_list,
                                                                   optimized,
                                                                   &gp_reg_usage_prev);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to restore register info for fine grained hash\n");
            goto out;
        }
    }

    for (uint32_t ind = 0; ind < fields_count; ++ind) {
        if (fields_list[ind].sequence_id == fields_list[ind + 1].sequence_id) {
            for (uint32_t ii = ind; ii < ind + 2; ++ii) {
                switch (fields_list[ii].field) {
                case SAI_NATIVE_HASH_FIELD_DST_IPV4:
                case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
                case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
                case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
                    if (SAI_ERR(status = ipv4_reg_allocate(&fields_list[ii],
                                                           optimized,
                                                           is_gp_reg_restore,
                                                           gp_reg_usage,
                                                           gp_reg_usage_prev))) {
                        goto out;
                    }
                    break;

                case SAI_NATIVE_HASH_FIELD_DST_IPV6:
                case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
                case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
                case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
                    if (SAI_ERR(status = ipv6_reg_allocate(&fields_list[ii],
                                                           optimized,
                                                           is_gp_reg_restore,
                                                           gp_reg_usage,
                                                           gp_reg_usage_prev))) {
                        goto out;
                    }
                    break;

                case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
                case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
                case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
                case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
                    if (SAI_ERR(status = l4_reg_allocate(&fields_list[ii],
                                                         is_gp_reg_restore,
                                                         gp_reg_usage,
                                                         gp_reg_usage_prev))) {
                        goto out;
                    }

                    break;

                default:
                    break;
                }
            }
            ++ind;
        }
    }

out:
    return status;
}

sai_status_t gp_registers_delete(_Inout_ mlnx_sai_fg_hash_field_t *fields_list)
{
    uint32_t     reg_key_cnt = 1;
    sx_status_t  sx_status;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (NULL == fields_list) {
        SX_LOG_ERR("NULL value fields list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_init_flex_parser())) {
        SX_LOG_ERR("Failed to init_flex_parser\n");
        return status;
    }

    for (uint32_t ii = 0; ii < MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT; ++ii) {
        if (fields_list[ii].fg_field_id == SAI_NULL_OBJECT_ID) {
            break;
        }

        if (fields_list[ii].sequence_id == fields_list[ii + 1].sequence_id) {
            uint32_t start = ii;
            uint32_t end = ii + 1;
            for (; start <= end; ++start) {
                for (uint32_t jj = 0; jj < MLNX_SAI_FG_HASH_FIELD_SHM_RM_ARRAY_MAX_COUNT; ++jj) {
                    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(fields_list[start].shm_rm_array_idx[jj])) {
                        sx_status = sx_api_flex_parser_reg_ext_point_set(gh_sdk,
                                                                         SX_ACCESS_CMD_UNSET,
                                                                         fields_list[start].reg_id[jj],
                                                                         NULL,
                                                                         NULL);
                        if (SX_ERR(sx_status)) {
                            SX_LOG_ERR("Failed to unset extraction point for GP register %s.\n",
                                       SX_STATUS_MSG(sx_status));
                            status = sdk_to_sai(sx_status);
                            goto out;
                        }
                        if (SAI_ERR(sx_status =
                                        sx_api_register_set(gh_sdk, SX_ACCESS_CMD_DESTROY,
                                                            &fields_list[start].reg_id[jj],
                                                            &reg_key_cnt))) {
                            SX_LOG_ERR("Failed to delete register %s.\n", SX_STATUS_MSG(status));
                            status = sdk_to_sai(sx_status);
                            goto out;
                        }
                    }
                    mlnx_gp_reg_db_free(fields_list[start].shm_rm_array_idx[jj]);
                    fields_list[start].shm_rm_array_idx[jj] = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
                }
            }
            ++ii;
        }
    }
out:
    return status;
}

void mlnx_create_alu_reg_action(_Inout_ sx_flex_acl_flex_action_t *action,
                                _In_ sx_gp_register_e              src_reg,
                                _In_ sx_gp_register_e              dst_reg,
                                _In_ uint8_t                       offset,
                                uint8_t                            size)
{
    action->type = SX_FLEX_ACL_ACTION_ALU_REG;
    action->fields.action_alu_reg.command = SX_ACL_ACTION_ALU_REG_COMMAND_XOR;
    action->fields.action_alu_reg.src_register = src_reg;
    action->fields.action_alu_reg.src_offset = offset;
    action->fields.action_alu_reg.dst_register = dst_reg;
    action->fields.action_alu_reg.dst_offset = offset;
    action->fields.action_alu_reg.size = size;
}

void mlnx_create_hash_action(_Inout_ sx_flex_acl_flex_action_t       *action,
                             _In_ sx_flex_acl_action_hash_type_t      hash_type,
                             _In_ sx_flex_acl_action_hash_crc_field_t field,
                             _In_ sx_flex_acl_action_hash_crc_mask_t  mask)
{
    action->type = SX_FLEX_ACL_ACTION_HASH;
    action->fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_CRC;
    action->fields.action_hash.type = hash_type;
    action->fields.action_hash.hash_crc.field = field;
    action->fields.action_hash.hash_crc.mask = mask;
}

static void mlnx_fg_hash_action_list_create(_In_ sx_flex_acl_action_hash_type_t action_type,
                                            _In_ uint32_t                       fields_count,
                                            _In_ mlnx_sai_fg_hash_field_t      *fields_list,
                                            _Inout_ sx_flex_acl_flex_action_t * action_list,
                                            _Inout_ uint32_t                   *action_num)
{
    uint8_t act_num = 0;

    action_list[act_num].type = SX_FLEX_ACL_ACTION_HASH;
    action_list[act_num].fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_SET;
    action_list[act_num].fields.action_hash.type = action_type;
    if (action_type == SX_ACL_ACTION_HASH_TYPE_ECMP) {
        action_list[act_num].fields.action_hash.hash_value = g_sai_db_ptr->port_ecmp_hash_params.seed;
    } else {
        action_list[act_num].fields.action_hash.hash_value = g_sai_db_ptr->lag_hash_params.lag_seed;
    }

    ++act_num;

    for (uint32_t ii = 0; ii < fields_count; ++ii) {
        if (fields_list[ii].sequence_id == fields_list[ii + 1].sequence_id) {
            uint16_t                           mask = 0;
            uint8_t                            offset = 0;
            uint8_t                            size = 0;
            sx_flex_acl_action_hash_crc_mask_t crc_mask = {0};
            uint32_t                           src_idx = 0;
            uint32_t                           dst_idx = 0;

            crc_mask.gp_register = 0xffff;
            switch (fields_list[ii].field) {
            case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
            case SAI_NATIVE_HASH_FIELD_DST_IPV4:
            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:

                switch (fields_list[ii].field) {
                case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
                case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
                    src_idx = ii;
                    dst_idx = ii + 1;
                    break;

                case SAI_NATIVE_HASH_FIELD_DST_IPV4:
                case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
                    src_idx = ii + 1;
                    dst_idx = ii;
                    break;

                default:
                    break;
                }
                if (0 != (mask = fields_list[ii].ip_mask.ip4 & 0xFFFF)) {
                    pbhash_offset_and_size_calculate(mask, &offset, &size);
                    mlnx_create_alu_reg_action(&action_list[act_num],
                                               fields_list[src_idx].reg_id[1].key.gp_reg.reg_id,
                                               fields_list[dst_idx].reg_id[1].key.gp_reg.reg_id,
                                               offset,
                                               size);
                    ++act_num;
                }
                if (0 != (mask = fields_list[ii].ip_mask.ip4 >> 16)) {
                    pbhash_offset_and_size_calculate(mask, &offset, &size);
                    mlnx_create_alu_reg_action(&action_list[act_num],
                                               fields_list[src_idx].reg_id[0].key.gp_reg.reg_id,
                                               fields_list[dst_idx].reg_id[0].key.gp_reg.reg_id,
                                               offset,
                                               size);
                    ++act_num;
                }
                mlnx_create_hash_action(&action_list[act_num],
                                        action_type,
                                        fields_list[dst_idx].reg_id[1].key.gp_reg.reg_id + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0,
                                        crc_mask);
                ++act_num;
                mlnx_create_hash_action(&action_list[act_num],
                                        action_type,
                                        fields_list[dst_idx].reg_id[0].key.gp_reg.reg_id + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0,
                                        crc_mask);
                ++act_num;
                break;

            case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
            case SAI_NATIVE_HASH_FIELD_DST_IPV6:
            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:

                switch (fields_list[ii].field) {
                case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
                case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
                    src_idx = ii;
                    dst_idx = ii + 1;
                    break;

                case SAI_NATIVE_HASH_FIELD_DST_IPV6:
                case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
                    src_idx = ii + 1;
                    dst_idx = ii;
                    break;

                default:
                    break;
                }
                for (int jj = 0; jj < 16; jj += 2) {
                    mask = (fields_list[ii].ip_mask.ip6[jj] << 8) | fields_list[ii].ip_mask.ip6[jj + 1];
                    if (mask) {
                        pbhash_offset_and_size_calculate(mask, &offset, &size);
                        mlnx_create_alu_reg_action(&action_list[act_num],
                                                   fields_list[src_idx].reg_id[jj / 2].key.gp_reg.reg_id,
                                                   fields_list[dst_idx].reg_id[jj / 2].key.gp_reg.reg_id,
                                                   offset,
                                                   size);
                        ++act_num;
                    }
                }
                for (int jj = 15; jj > 0; jj -= 2) {
                    if ((0 != (fields_list[ii].ip_mask.ip6[jj] & 0xFF)) ||
                        (0 != (fields_list[ii].ip_mask.ip6[jj - 1] & 0xFF))) {
                        mlnx_create_hash_action(&action_list[act_num],
                                                action_type,
                                                fields_list[dst_idx].reg_id[jj / 2].key.gp_reg.reg_id + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0,
                                                crc_mask);
                        ++act_num;
                    }
                }
                break;

            case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
            case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
                mlnx_create_alu_reg_action(&action_list[act_num],
                                           fields_list[ii].reg_id[0].key.gp_reg.reg_id,
                                           fields_list[ii + 1].reg_id[0].key.gp_reg.reg_id,
                                           0,
                                           16);
                ++act_num;
                mlnx_create_hash_action(&action_list[act_num],
                                        action_type,
                                        fields_list[ii + 1].reg_id[0].key.gp_reg.reg_id + SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0,
                                        crc_mask);
                ++act_num;
                break;

            default:
                break;
            }
            ++ii;
        } else {
            sx_flex_acl_action_hash_crc_mask_t  mask;
            sx_flex_acl_action_hash_crc_field_t field;
            switch (fields_list[ii].field) {
            case SAI_NATIVE_HASH_FIELD_DST_IPV4:
                field = SX_ACL_ACTION_HASH_FIELD_DIP;
                mask.dip.s_addr = fields_list[ii].ip_mask.ip4;
                break;

            case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
                field = SX_ACL_ACTION_HASH_FIELD_SIP;
                mask.sip.s_addr = fields_list[ii].ip_mask.ip4;
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
                field = SX_ACL_ACTION_HASH_FIELD_INNER_DIP;
                mask.inner_dip.s_addr = fields_list[ii].ip_mask.ip4;
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
                field = SX_ACL_ACTION_HASH_FIELD_INNER_SIP;
                mask.inner_sip.s_addr = fields_list[ii].ip_mask.ip4;
                break;

            case SAI_NATIVE_HASH_FIELD_DST_IPV6:
                field = SX_ACL_ACTION_HASH_FIELD_DIPV6;
                memcpy(&mask.dipv6, fields_list[ii].ip_mask.ip6, sizeof(mask.dipv6));
                break;

            case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
                field = SX_ACL_ACTION_HASH_FIELD_SIPV6;
                memcpy(&mask.sipv6, fields_list[ii].ip_mask.ip6, sizeof(mask.sipv6));
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
                field = SX_ACL_ACTION_HASH_FIELD_INNER_DIPV6;
                memcpy(&mask.inner_dipv6, fields_list[ii].ip_mask.ip6, sizeof(mask.dipv6));
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
                field = SX_ACL_ACTION_HASH_FIELD_INNER_SIPV6;
                memcpy(&mask.inner_sipv6, fields_list[ii].ip_mask.ip6, sizeof(mask.sipv6));
                break;

            case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
                field = SX_ACL_ACTION_HASH_FIELD_L4_DESTINATION_PORT;
                mask.l4_destination_port = 0xffff;
                break;

            case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
                field = SX_ACL_ACTION_HASH_FIELD_L4_SOURCE_PORT;
                mask.l4_source_port = 0xffff;
                break;

            case SAI_NATIVE_HASH_FIELD_IP_PROTOCOL:
                field = SX_ACL_ACTION_HASH_FIELD_IP_PROTO;
                mask.ip_proto = 0xff;
                break;

            case SAI_NATIVE_HASH_FIELD_INNER_IP_PROTOCOL:
                field = SX_ACL_ACTION_HASH_FIELD_INNER_IP_PROTO;
                mask.inner_ip_proto = 0xff;
                break;

            default:
                continue;
            }

            mlnx_create_hash_action(&action_list[act_num], action_type, field, mask);
            ++act_num;
        }
    }
    *action_num = act_num;
}


static void mlnx_fg_optimized_hash_action_list_create(_In_ sx_flex_acl_action_hash_type_t action_type,
                                                      _In_ uint32_t                       fields_count,
                                                      _In_ mlnx_sai_fg_hash_field_t      *fields_list,
                                                      _Inout_ sx_flex_acl_flex_action_t * action_list,
                                                      _Inout_ uint32_t                   *action_num)
{
    action_list[0].type = SX_FLEX_ACL_ACTION_HASH;
    action_list[0].fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_SET;
    action_list[0].fields.action_hash.type = action_type;
    if (action_type == SX_ACL_ACTION_HASH_TYPE_ECMP) {
        action_list[0].fields.action_hash.hash_value = g_sai_db_ptr->port_ecmp_hash_params.seed;
    } else {
        action_list[0].fields.action_hash.hash_value = g_sai_db_ptr->lag_hash_params.lag_seed;
    }

    sx_gp_register_e port_dst_reg_id = 0;
    sx_gp_register_e ip_hi_dst_reg_id = 0;
    sx_gp_register_e ip_lo_dst_reg_id = 0;

    for (uint32_t ii = 0; ii < fields_count; ++ii) {
        switch (fields_list[ii].field) {
        case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
            action_list[1].type = SX_FLEX_ACL_ACTION_ALU_REG;
            action_list[1].fields.action_alu_reg.command = SX_ACL_ACTION_ALU_REG_COMMAND_XOR;
            action_list[1].fields.action_alu_reg.src_register = fields_list[ii].reg_id[0].key.gp_reg.reg_id;
            action_list[1].fields.action_alu_reg.src_offset = 0;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
            action_list[1].fields.action_alu_reg.dst_register = fields_list[ii].reg_id[0].key.gp_reg.reg_id;
            action_list[1].fields.action_alu_reg.dst_offset = 0;
            action_list[1].fields.action_alu_reg.size = 16;
            port_dst_reg_id = fields_list[ii].reg_id[0].key.gp_reg.reg_id;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
            action_list[3].type = SX_FLEX_ACL_ACTION_ALU_REG;
            action_list[3].fields.action_alu_reg.command = SX_ACL_ACTION_ALU_REG_COMMAND_XOR;
            action_list[3].fields.action_alu_reg.src_register = fields_list[ii].reg_id[0].key.gp_reg.reg_id;
            action_list[3].fields.action_alu_reg.src_offset = 0;
            action_list[4].type = SX_FLEX_ACL_ACTION_ALU_REG;
            action_list[4].fields.action_alu_reg.command = SX_ACL_ACTION_ALU_REG_COMMAND_XOR;
            action_list[4].fields.action_alu_reg.src_register = fields_list[ii].reg_id[1].key.gp_reg.reg_id;
            action_list[4].fields.action_alu_reg.src_offset = 0;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
            action_list[3].fields.action_alu_reg.dst_register = fields_list[ii].reg_id[0].key.gp_reg.reg_id;
            action_list[3].fields.action_alu_reg.dst_offset = 0;
            action_list[3].fields.action_alu_reg.size = 16;
            ip_hi_dst_reg_id = fields_list[ii].reg_id[0].key.gp_reg.reg_id;
            action_list[4].fields.action_alu_reg.dst_register = fields_list[ii].reg_id[1].key.gp_reg.reg_id;
            action_list[4].fields.action_alu_reg.dst_offset = 0;
            action_list[4].fields.action_alu_reg.size = 16;
            ip_lo_dst_reg_id = fields_list[ii].reg_id[1].key.gp_reg.reg_id;
            break;

        default:
            break;
        }
    }

    action_list[2].type = SX_FLEX_ACL_ACTION_HASH;
    action_list[2].fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_CRC;
    action_list[2].fields.action_hash.type = action_type;
    action_list[2].fields.action_hash.hash_crc.field = SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0 + port_dst_reg_id;
    action_list[2].fields.action_hash.hash_crc.mask.gp_register = 0xffff;

    action_list[5].type = SX_FLEX_ACL_ACTION_HASH;
    action_list[5].fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_CRC;
    action_list[5].fields.action_hash.type = action_type;
    action_list[5].fields.action_hash.hash_crc.field = SX_ACL_ACTION_HASH_FIELD_INNER_IP_PROTO;
    action_list[5].fields.action_hash.hash_crc.mask.inner_ip_proto = 0xff;

    action_list[6].type = SX_FLEX_ACL_ACTION_HASH;
    action_list[6].fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_CRC;
    action_list[6].fields.action_hash.type = action_type;
    action_list[6].fields.action_hash.hash_crc.field = SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0 + ip_hi_dst_reg_id;
    action_list[6].fields.action_hash.hash_crc.mask.gp_register = 0xffff;

    action_list[7].type = SX_FLEX_ACL_ACTION_HASH;
    action_list[7].fields.action_hash.command = SX_ACL_ACTION_HASH_COMMAND_CRC;
    action_list[7].fields.action_hash.type = action_type;
    action_list[7].fields.action_hash.hash_crc.field = SX_ACL_ACTION_HASH_FIELD_GP_REGISTER_0 + ip_lo_dst_reg_id;
    action_list[7].fields.action_hash.hash_crc.mask.gp_register = 0xffff;

    *action_num = 8;
}

sai_status_t mlnx_hash_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_hash_api_t mlnx_hash_api = {
    mlnx_create_hash,
    mlnx_remove_hash,
    mlnx_set_hash_attribute,
    mlnx_get_hash_attribute,
    mlnx_create_fine_grained_hash_field,
    mlnx_remove_fine_grained_hash_field,
    mlnx_set_fine_grained_hash_field_attribute,
    mlnx_get_fine_grained_hash_field_attribute,
};
