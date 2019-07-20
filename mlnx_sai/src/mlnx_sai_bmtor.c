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
#include "assert.h"
#include <fx_base_api.h>
#include <flextrum_types.h>

#undef  __MODULE__
#define __MODULE__ BMTOR

#define MLNX_FX_KEY_LIST_MAX_LEN    (2)
#define MLNX_FX_PARAMS_LIST_MAX_LEN (3)
#define MLNX_FX_BYTE_ARRAY_MAX_LEN  (6)
#define MLNX_FX_KEY_LIST_EMPTY      (fx_key_list_t) {.keys = NULL, .len = 0}
#define MLNX_FX_PARAMS_LIST_EMPTY   (fx_param_list_t) {.params = NULL, .len = 0}

#define MLNX_FX_KEY_LIST_IS_EMPTY(key_list)       (((key_list).keys == NULL) && (((key_list).len == 0)))
#define MLNX_FX_PARAMS_LIST_IS_EMPTY(params_list) (((params_list).params == NULL) && (((params_list).len == 0)))

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static fx_handle_t g_fx_handle;
static bool        g_fx_handle_initialized = false;
static bool        g_fx_handle_is_extern   = false;
static sai_status_t sai_fx_initialize(void);
static sai_status_t mlnx_bmtor_fx_handle_init(void);
static sai_status_t get_bitmap_classification_fx_action(_In_ sai_table_bitmap_classification_entry_action_t action,
                                                        _Out_ fx_action_id_t                               *action_id,
                                                        _In_ uint32_t                                       param_index)
{
    if (NULL == action_id) {
        SX_LOG_ERR("NULL action id value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_SET_METADATA:
        *action_id = CONTROL_IN_RIF_SET_METADATA_ID;
        break;

    case SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_NOACTION:
        *action_id = NOACTION_ID;
        break;

    default:
        SX_LOG_ERR("Invalid router entry action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bmort_fx_action_to_classf_entry_action(
    _In_ fx_action_id_t                                   fx_action,
    _Out_ sai_table_bitmap_classification_entry_action_t *sai_action)
{
    assert(sai_action);

    switch (fx_action) {
    case CONTROL_IN_RIF_SET_METADATA_ID:
        *sai_action = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_SET_METADATA;
        break;

    case NOACTION_ID:
        *sai_action = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_NOACTION;
        break;

    default:
        SX_LOG_ERR("Unexpected fx action %d\n", fx_action);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static void table_bitmap_classification_entry_key_to_str(_In_ sai_object_id_t entry_id, _Out_ char *key_str)
{
    uint32_t bitmap_classification_offset;

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY, &bitmap_classification_offset,
                            NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid table bitmap classification entry");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "Bitmap classification entry %d", bitmap_classification_offset);
    }
}

static sai_status_t mlnx_bmtor_table_bitmap_classification_attr_get(_In_ const sai_object_key_t   *key,
                                                                    _Inout_ sai_attribute_value_t *value,
                                                                    _In_ uint32_t                  attr_index,
                                                                    _Inout_ vendor_cache_t        *cache,
                                                                    void                          *arg);
static const sai_vendor_attribute_entry_t table_bitmap_classification_entry_vendor_attribs[] = {
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_bitmap_classification_attr_get, (void*)SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION,
      NULL, NULL },
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_bitmap_classification_attr_get,
      (void*)SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY,
      NULL, NULL },
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IS_DEFAULT,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_bitmap_classification_attr_get,
      (void*)SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        table_bitmap_classification_entry_enum_info[] = {
    [SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_table_bitmap_classification_entry_obj_type_info =
{ table_bitmap_classification_entry_vendor_attribs,
  OBJ_ATTRS_ENUMS_INFO(table_bitmap_classification_entry_enum_info) };
static sai_status_t mlnx_bmtor_fx_bytearray_init(_Out_ fx_bytearray_t *bytearray)
{
    assert(bytearray);

    bytearray->data = calloc(MLNX_FX_BYTE_ARRAY_MAX_LEN, sizeof(bytearray->data[0]));
    if (!bytearray->data) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    bytearray->len = MLNX_FX_BYTE_ARRAY_MAX_LEN;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bmtor_fx_data_init(_Out_ fx_key_list_t *key_list, _Out_ fx_param_list_t *param_list)
{
    uint32_t     ii;
    sai_status_t status;

    assert(key_list);
    assert(param_list);

    assert(MLNX_FX_KEY_LIST_IS_EMPTY(*key_list));
    assert(MLNX_FX_PARAMS_LIST_IS_EMPTY(*param_list));

    key_list->keys = calloc(MLNX_FX_KEY_LIST_MAX_LEN, sizeof(key_list->keys[0]));
    if (!key_list->keys) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }
    key_list->len = MLNX_FX_KEY_LIST_MAX_LEN;

    for (ii = 0; ii < key_list->len; ii++) {
        status = mlnx_bmtor_fx_bytearray_init(&key_list->keys[ii].key);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_bmtor_fx_bytearray_init(&key_list->keys[ii].mask);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    param_list->params = calloc(MLNX_FX_PARAMS_LIST_MAX_LEN, sizeof(param_list->params[0]));
    if (!param_list->params) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }
    param_list->len = MLNX_FX_PARAMS_LIST_MAX_LEN;

    for (ii = 0; ii < param_list->len; ii++) {
        status = mlnx_bmtor_fx_bytearray_init(&param_list->params[ii]);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static void mlnx_bmtor_fx_data_deinit(_In_ const fx_key_list_t *key_list, _In_ const fx_param_list_t *param_list)
{
    uint32_t ii;

    assert(key_list);
    assert(param_list);

    if (!MLNX_FX_KEY_LIST_IS_EMPTY(*key_list)) {
        for (ii = 0; ii < MLNX_FX_KEY_LIST_MAX_LEN; ii++) {
            free(key_list->keys[ii].key.data);
            free(key_list->keys[ii].mask.data);
        }
        free(key_list->keys);
    }

    if (!MLNX_FX_PARAMS_LIST_IS_EMPTY(*param_list)) {
        for (ii = 0; ii < MLNX_FX_PARAMS_LIST_MAX_LEN; ii++) {
            free(param_list->params[ii].data);
        }
        free(param_list->params);
    }
}

static sai_status_t mlnx_bmtor_fx_entry_to_classf_entry_attr(
    _In_ const fx_key_list_t                             *fx_key_list,
    _In_ const fx_param_list_t                           *fx_param_list,
    _In_ fx_action_id_t                                   fx_action_id,
    _Out_ sai_table_bitmap_classification_entry_action_t *action,
    _Out_ sai_object_id_t                                *irif_oid,
    _Out_ uint32_t                                       *irif_metadata)
{
    sai_status_t          status;
    sx_router_interface_t irif;

    assert(fx_key_list);
    assert(fx_param_list);
    assert(irif_oid);
    assert(action);
    assert(irif_metadata);

    if (fx_key_list->len != 1) {
        SX_LOG_ERR("Fx key_list len %lu != 1\n", fx_key_list->len);
        return SAI_STATUS_FAILURE;
    }

    if (fx_key_list->keys[0].key.len != sizeof(sx_router_interface_t)) {
        SX_LOG_ERR("Fx key[0] len (%lu) != sizeof(sx_router_interface_t) (%lu)\n", fx_key_list->len,
                   sizeof(sx_router_interface_t));
        return SAI_STATUS_FAILURE;
    }

    irif   = *(sx_router_interface_t*)fx_key_list->keys[0].key.data;
    status = mlnx_rif_sx_to_sai_oid(irif, irif_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert SX rif %u to sai OID\n", irif);
        return status;
    }

    status = mlnx_bmort_fx_action_to_classf_entry_action(fx_action_id, action);
    if (SAI_ERR(status)) {
        return status;
    }

    if ((fx_param_list->len == 0) && (fx_action_id != NOACTION_ID)) {
        SX_LOG_ERR("Invalid fx state - param count is 0 but action id is not NOACTION_ID\n");
        return SAI_STATUS_FAILURE;
    }

    if (fx_param_list->len != 0) {
        if (fx_param_list->params[0].len != sizeof(uint32_t)) {
            SX_LOG_ERR("Unexpected param len %lu, expected %lu\n", fx_param_list->params[0].len, sizeof(uint32_t));
            return SAI_STATUS_FAILURE;
        }

        *irif_metadata = *(const uint32_t*)fx_param_list->params[0].data;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bmtor_table_bitmap_classification_attr_get(_In_ const sai_object_key_t   *key,
                                                                    _Inout_ sai_attribute_value_t *value,
                                                                    _In_ uint32_t                  attr_index,
                                                                    _Inout_ vendor_cache_t        *cache,
                                                                    void                          *arg)
{
    sai_status_t                                   status;
    sx_status_t                                    sx_status;
    sai_object_id_t                                entry_id = key->key.object_id;
    sai_attr_id_t                                  attr;
    uint32_t                                       fx_offset;
    fx_action_id_t                                 fx_action_id;
    fx_key_list_t                                  fx_key_list   = MLNX_FX_KEY_LIST_EMPTY;
    fx_param_list_t                                fx_param_list = MLNX_FX_PARAMS_LIST_EMPTY;
    sai_object_id_t                                irif_oid;
    uint32_t                                       irif_metadata = 0;
    sai_table_bitmap_classification_entry_action_t action;

    SX_LOG_ENTER();

    attr = (long)(arg);

    assert((attr == SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION) ||
           (attr == SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY) ||
           (attr == SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA));

    status = mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY,
                                 &fx_offset, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failure in extracting offset from bitmap_classification entry object id 0x%lx " PRIx64 "\n",
                   entry_id);
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_bmtor_fx_data_init(&fx_key_list, &fx_param_list);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();

    sx_status = fx_table_entry_get(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_CLASSIFICATION_ID, fx_offset,
                                   &fx_action_id, &fx_key_list, &fx_param_list);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
        sai_db_unlock();
        goto out;
    }

    status = mlnx_bmtor_fx_entry_to_classf_entry_attr(&fx_key_list,
                                                      &fx_param_list,
                                                      fx_action_id,
                                                      &action,
                                                      &irif_oid,
                                                      &irif_metadata);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        goto out;
    }

    sai_db_unlock();

    switch (attr) {
    case SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION:
        value->s32 = action;
        break;

    case SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY:
        value->oid = irif_oid;
        break;

    case SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA:
        if (action != SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_SET_METADATA) {
            SX_LOG_NTC("IRIF metadata is not set\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        value->u32 = irif_metadata;
        break;

    default:
        SX_LOG_ERR("Unexpected attr - %d\n", attr);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    mlnx_bmtor_fx_data_deinit(&fx_key_list, &fx_param_list);
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_create_table_bitmap_classification_entry(_Out_ sai_object_id_t      *entry_id,
                                                           _In_ sai_object_id_t        switch_id,
                                                           _In_ uint32_t               attr_count,
                                                           _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 sai_status;
    uint32_t                     attr_idx;
    const sai_attribute_value_t *attr;
    fx_key_t                     bitmap_classification_keys[1];
    fx_param_t                   bitmap_classification_params[1];
    fx_key_list_t                bitmap_classification_key_list;
    fx_param_list_t              bitmap_classification_param_list;
    int                          keys_idx                       = 0;
    int                          params_idx                     = 0;
    fx_action_id_t               flextrum_action                = FX_ACTION_INVALID_ID;
    sx_acl_rule_offset_t         bitmap_classification_priority = 0;
    sx_router_interface_t        bitmap_classification_router_interface_key;
    uint32_t                     bitmap_classification_in_rif_metadata;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == entry_id) {
        SX_LOG_ERR("NULL entry id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY,
                                    table_bitmap_classification_entry_vendor_attribs, SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_attr_list_to_str(attr_count,
                         attr_list,
                         SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY,
                         MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create table bitmap classification entry, %s\n", list_str);

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION,
                                     &attr,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    sai_status = get_bitmap_classification_fx_action(attr->s32, &flextrum_action, attr_idx);
    if (SAI_ERR(sai_status)) {
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_db_write_lock();

    /* Lazy initialization */
    if (SAI_STATUS_SUCCESS != (sai_status = sai_fx_initialize())) {
        SX_LOG_ERR("Failure in call to sai_fx_initialize\n");
        goto out;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY,
                                     &attr,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_rif_oid_to_sdk_rif_id(attr->oid, &bitmap_classification_router_interface_key))) {
        SX_LOG_ERR("Invalid bitmap classification entry rif\n");
        sai_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        goto out;
    }
    bitmap_classification_keys[keys_idx].key.data = (uint8_t*)&bitmap_classification_router_interface_key;
    bitmap_classification_keys[keys_idx].key.len  = sizeof(bitmap_classification_router_interface_key);
    keys_idx++;

    if (flextrum_action == CONTROL_IN_RIF_SET_METADATA_ID) {
        sai_status = find_attrib_in_list(attr_count,
                                         attr_list,
                                         SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA,
                                         &attr,
                                         &attr_idx);
        assert(SAI_STATUS_SUCCESS == sai_status);
        bitmap_classification_in_rif_metadata         = attr->u32;
        bitmap_classification_params[params_idx].data = (uint8_t*)&bitmap_classification_in_rif_metadata;
        bitmap_classification_params[params_idx].len  = sizeof(bitmap_classification_in_rif_metadata);
        params_idx++;
    }

    bitmap_classification_key_list.len      = keys_idx;
    bitmap_classification_param_list.len    = params_idx;
    bitmap_classification_key_list.keys     = bitmap_classification_keys;
    bitmap_classification_param_list.params = bitmap_classification_params;
    if (fx_table_entry_add(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_CLASSIFICATION_ID, flextrum_action,
                           bitmap_classification_key_list, bitmap_classification_param_list,
                           &bitmap_classification_priority)) {
        SX_LOG_ERR("Failure in insertion of bitmap_classification entry %u\n", flextrum_action);
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY, bitmap_classification_priority,
                                NULL,
                                entry_id))) {
        goto out;
    }

    table_bitmap_classification_entry_key_to_str(*entry_id, key_str);
    SX_LOG_NTC("Created table bitmap classification entry %s\n", key_str);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_remove_table_bitmap_classification_entry(_In_ sai_object_id_t entry_id)
{
    sai_status_t status;
    uint32_t     bitmap_classification_offset;
    char         key_str[MAX_KEY_STR_LEN];

    table_bitmap_classification_entry_key_to_str(entry_id, key_str);
    SX_LOG_NTC("Remove table bitmap classification entry %s\n", key_str);

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY,
                                 &bitmap_classification_offset,
                                 NULL))) {
        SX_LOG_ERR("Failure in extracting offset from bitmap_classification entry object id 0x%lx " PRIx64 "\n",
                   entry_id);
        return status;
    }

    sai_db_write_lock();

    if (fx_table_entry_remove(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_CLASSIFICATION_ID,
                              bitmap_classification_offset)) {
        SX_LOG_ERR("Failure in removal of table_bitmap_classification entry at offset %d\n",
                   bitmap_classification_offset);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

sai_status_t mlnx_set_table_bitmap_classification_entry_attribute(_In_ sai_object_id_t        entry_id,
                                                                  _In_ const sai_attribute_t *attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t mlnx_get_table_bitmap_classification_entry_attribute(_In_ sai_object_id_t     entry_id,
                                                                  _In_ uint32_t            attr_count,
                                                                  _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = entry_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    table_bitmap_classification_entry_key_to_str(entry_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY,
                              table_bitmap_classification_entry_vendor_attribs,
                              attr_count,
                              attr_list);
}

static sai_status_t get_bitmap_router_fx_action(_In_ sai_table_bitmap_router_entry_action_t action,
                                                _Out_ fx_action_id_t                       *action_id,
                                                _In_ uint32_t                               param_index)
{
    if (NULL == action_id) {
        SX_LOG_ERR("NULL action id value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP:
        *action_id = CONTROL_IN_RIF_TO_NEXTHOP_ID;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_LOCAL:
        *action_id = CONTROL_IN_RIF_TO_LOCAL_ID;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_CPU:
        *action_id = CONTROL_IN_RIF_TO_CPU_ID;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_DROP:
        *action_id = CONTROL_IN_RIF_DROP_ID;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_NOACTION:
        *action_id = NOACTION_ID;
        break;

    default:
        SX_LOG_ERR("Invalid router entry action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bmtor_fx_action_to_router_entry_action(
    _In_ fx_action_id_t                           fx_action,
    _Out_ sai_table_bitmap_router_entry_action_t *sai_action)
{
    assert(sai_action);

    switch (fx_action) {
    case CONTROL_IN_RIF_TO_NEXTHOP_ID:
        *sai_action = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP;
        break;

    case CONTROL_IN_RIF_TO_LOCAL_ID:
        *sai_action = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_LOCAL;
        break;

    case CONTROL_IN_RIF_TO_CPU_ID:
        *sai_action = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_CPU;
        break;

    case CONTROL_IN_RIF_DROP_ID:
        *sai_action = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_DROP;
        break;

    case NOACTION_ID:
        *sai_action = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_NOACTION;
        break;

    default:
        SX_LOG_ERR("Unexpected fx action %d\n", fx_action);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static void table_bitmap_router_entry_key_to_str(_In_ sai_object_id_t entry_id, _Out_ char *key_str)
{
    uint32_t bitmap_router_offset;

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY, &bitmap_router_offset, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid table bitmap router entry");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "Bitmap router entry %d", bitmap_router_offset);
    }
}

static sai_status_t mlnx_bmtor_table_router_entry_attr_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg);
static const sai_vendor_attribute_entry_t table_bitmap_router_entry_vendor_attribs[] = {
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TRAP_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TRAP_ID,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TUNNEL_INDEX,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_router_entry_attr_get, (void*)SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TUNNEL_INDEX,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        table_bitmap_router_entry_enum_info[] = {
    [SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_table_bitmap_router_entry_obj_type_info =
{ table_bitmap_router_entry_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(table_bitmap_router_entry_enum_info) };
static sai_status_t mlnx_bmtor_fx_entry_to_router_entry_attr(_In_ const fx_key_list_t                     *fx_key_list,
                                                             _In_ const fx_param_list_t                   *fx_param_list,
                                                             _In_ fx_action_id_t                           fx_action_id,
                                                             _Out_ sai_table_bitmap_router_entry_action_t *action,
                                                             _Out_ uint32_t                               *irif_key,
                                                             _Out_ uint32_t                               *irif_mask,
                                                             _Out_ sai_ip_prefix_t                        *dst_ip_prefix,
                                                             _Out_ sai_object_id_t                        *next_hop,
                                                             _Out_ sai_object_id_t                        *rif,
                                                             _Out_ sai_object_id_t                        *trap,
                                                             _Out_ uint16_t                               *tunnel_idx)
{
    sai_status_t           status;
    sx_ecmp_id_t           sx_ecmp_id;
    sx_router_interface_t  sx_router_interface;
    sx_trap_id_t           sx_trap_id;
    sai_hostif_trap_type_t trap_id;
    const char            *trap_name;
    mlnx_trap_type_t       trap_type;

    assert(fx_key_list);
    assert(fx_param_list);
    assert(action);
    assert(irif_key);
    assert(irif_mask);
    assert(dst_ip_prefix);
    assert(next_hop);
    assert(rif);
    assert(trap);
    assert(tunnel_idx);

    if (fx_key_list->len != 2) {
        SX_LOG_ERR("Fx key_list len %lu != 2\n", fx_key_list->len);
        return SAI_STATUS_FAILURE;
    }

    if (fx_key_list->keys[0].key.len != sizeof(*irif_key)) {
        SX_LOG_ERR("fx_key_list->keys[0].key.len (%lu) != sizeof(irif_key) (%lu)\n",
                   fx_key_list->keys[0].key.len, sizeof(*irif_key));
        return SAI_STATUS_FAILURE;
    }

    if (fx_key_list->keys[0].mask.len != sizeof(*irif_mask)) {
        SX_LOG_ERR("fx_key_list->keys[0].mask.len (%lu) != sizeof(irif_mask) (%lu)\n",
                   fx_key_list->keys[0].mask.len, sizeof(*irif_mask));
        return SAI_STATUS_FAILURE;
    }

    if (fx_key_list->keys[1].key.len != sizeof(dst_ip_prefix->addr.ip4)) {
        SX_LOG_ERR("fx_key_list->keys[1].key.len (%lu) != sizeof(dst_ip_prefix->addr.ip4) (%lu)\n",
                   fx_key_list->keys[1].key.len, sizeof(dst_ip_prefix->addr.ip4));
        return SAI_STATUS_FAILURE;
    }

    if (fx_key_list->keys[1].mask.len != sizeof(dst_ip_prefix->mask.ip4)) {
        SX_LOG_ERR("fx_key_list->keys[1].mask.len (%lu) != sizeof(dst_ip_prefix->mask.ip4) (%lu)\n",
                   fx_key_list->keys[1].mask.len, sizeof(dst_ip_prefix->mask.ip4));
        return SAI_STATUS_FAILURE;
    }

    *irif_key  = *(uint32_t*)fx_key_list->keys[0].key.data;
    *irif_mask = *(uint32_t*)fx_key_list->keys[0].mask.data;

    dst_ip_prefix->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    dst_ip_prefix->addr.ip4    = ntohl(*(uint32_t*)fx_key_list->keys[1].key.data);
    dst_ip_prefix->mask.ip4    = ntohl(*(uint32_t*)fx_key_list->keys[1].mask.data);

    status = mlnx_bmtor_fx_action_to_router_entry_action(fx_action_id, action);
    if (SAI_ERR(status)) {
        return status;
    }

    switch (fx_action_id) {
    case CONTROL_IN_RIF_TO_NEXTHOP_ID:
        *tunnel_idx = *(const uint16_t*)fx_param_list->params[0].data;

        sx_ecmp_id = *(const sx_ecmp_id_t*)fx_param_list->params[1].data;
        status     = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP, sx_ecmp_id, NULL, next_hop);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case CONTROL_IN_RIF_TO_LOCAL_ID:
        sx_router_interface = *(const sx_router_interface_t*)fx_param_list->params[0].data;
        status              = mlnx_rif_sx_to_sai_oid(sx_router_interface, rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert SX rif %u to sai OID\n", sx_router_interface);
            return status;
        }
        break;

    case CONTROL_IN_RIF_TO_CPU_ID:
        sx_trap_id = *(const sx_trap_id_t*)fx_param_list->params[0].data;

        status = mlnx_translate_sdk_trap_to_sai(sx_trap_id, &trap_id, &trap_name, &trap_type);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("unknown sdk trap %u\n", sx_trap_id);
            return status;
        }

        status = mlnx_create_object((trap_type == MLNX_TRAP_TYPE_REGULAR) ? SAI_OBJECT_TYPE_HOSTIF_TRAP :
                                    SAI_OBJECT_TYPE_HOSTIF_USER_DEFINED_TRAP,
                                    trap_id, NULL, trap);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case NOACTION_ID:
        break;

    default:
        SX_LOG_ERR("Unexpected fx action %d\n", fx_action_id);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bmtor_table_router_entry_attr_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg)
{
    sai_status_t                           status;
    sx_status_t                            sx_status;
    sai_object_id_t                        entry_id = key->key.object_id;
    sai_attr_id_t                          attr;
    uint32_t                               fx_offset;
    fx_action_id_t                         fx_action_id;
    fx_key_list_t                          fx_key_list   = MLNX_FX_KEY_LIST_EMPTY;
    fx_param_list_t                        fx_param_list = MLNX_FX_PARAMS_LIST_EMPTY;
    uint32_t                               irif_key, irif_mask;
    uint16_t                               tunnel_idx = 0;
    sai_ip_prefix_t                        ip_prefix;
    sai_object_id_t                        next_hop = SAI_NULL_OBJECT_ID;
    sai_object_id_t                        rif      = SAI_NULL_OBJECT_ID;
    sai_object_id_t                        trap     = SAI_NULL_OBJECT_ID;
    sai_table_bitmap_router_entry_action_t action;

    SX_LOG_ENTER();

    attr = (long)(arg);

    assert((attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TRAP_ID) ||
           (attr == SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TUNNEL_INDEX));

    status = mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY,
                                 &fx_offset, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failure in extracting offset from bitmap_classification entry object id 0x%lx " PRIx64 "\n",
                   entry_id);
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_bmtor_fx_data_init(&fx_key_list, &fx_param_list);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();

    sx_status = fx_table_entry_get(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_ROUTER_ID, fx_offset,
                                   &fx_action_id, &fx_key_list, &fx_param_list);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
        sai_db_unlock();
        goto out;
    }

    status = mlnx_bmtor_fx_entry_to_router_entry_attr(&fx_key_list,
                                                      &fx_param_list,
                                                      fx_action_id,
                                                      &action,
                                                      &irif_key,
                                                      &irif_mask,
                                                      &ip_prefix,
                                                      &next_hop,
                                                      &rif,
                                                      &trap,
                                                      &tunnel_idx);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        goto out;
    }

    sai_db_unlock();

    switch (attr) {
    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION:
        value->s32 = action;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY:
        value->s32 = fx_offset;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY:
        value->u32 = irif_key;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK:
        value->u32 = irif_mask;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY:
        value->ipprefix = ip_prefix;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP:
        if (action != SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP) {
            SX_LOG_NTC("action is not SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        value->oid = next_hop;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE:
        if (action != SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_LOCAL) {
            SX_LOG_NTC("action is not SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_LOCAL\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        value->oid = rif;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TRAP_ID:
        if (action != SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_CPU) {
            SX_LOG_NTC("action is not SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_CPU\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        value->oid = trap;
        break;

    case SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TUNNEL_INDEX:
        if (action != SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP) {
            SX_LOG_NTC("action is not SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        value->u16 = tunnel_idx;
        break;

    default:
        SX_LOG_ERR("Unexpected attr - %d\n", attr);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    mlnx_bmtor_fx_data_deinit(&fx_key_list, &fx_param_list);
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_create_table_bitmap_router_entry(_Out_ sai_object_id_t      *entry_id,
                                                   _In_ sai_object_id_t        switch_id,
                                                   _In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 sai_status;
    uint32_t                     attr_idx;
    const sai_attribute_value_t *attr;
    fx_key_t                     bitmap_router_keys[2];
    fx_param_t                   bitmap_router_params[2];
    fx_key_list_t                bitmap_router_key_list;
    fx_param_list_t              bitmap_router_param_list;
    int                          keys_idx        = 0;
    int                          params_idx      = 0;
    fx_action_id_t               flextrum_action = FX_ACTION_INVALID_ID;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_acl_rule_offset_t         bitmap_router_priority;
    uint32_t                     bitmap_router_in_rif_metadata_key, bitmap_router_in_rif_metadata_mask;
    uint32_t                     bitmap_router_dst_ip_key, bitmap_router_dst_ip_key_mask;
    sx_ecmp_id_t                 bitmap_router_next_hop;
    uint16_t                     bitmap_tunnel_index;
    sx_router_interface_t        bitmap_router_router_interface;
    sx_trap_id_t                 bitmap_router_trap_id;

    SX_LOG_ENTER();

    if (NULL == entry_id) {
        SX_LOG_ERR("NULL entry id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY,
                                    table_bitmap_router_entry_vendor_attribs, SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_attr_list_to_str(attr_count,
                         attr_list,
                         SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY,
                         MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create table bitmap route entry, %s\n", list_str);

    sai_status =
        find_attrib_in_list(attr_count, attr_list, SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION, &attr, &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    sai_status = get_bitmap_router_fx_action(attr->s32, &flextrum_action, attr_idx);
    if (SAI_ERR(sai_status)) {
        return sai_status;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY,
                                     &attr,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    bitmap_router_priority = (sx_acl_rule_offset_t)attr->u32;

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY,
                                     &attr,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    bitmap_router_in_rif_metadata_key     = attr->u32;
    bitmap_router_keys[keys_idx].key.data = (uint8_t*)&bitmap_router_in_rif_metadata_key;
    bitmap_router_keys[keys_idx].key.len  = sizeof(bitmap_router_in_rif_metadata_key);

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK,
                                     &attr,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    bitmap_router_in_rif_metadata_mask     = attr->u32;
    bitmap_router_keys[keys_idx].mask.data = (uint8_t*)&bitmap_router_in_rif_metadata_mask;
    bitmap_router_keys[keys_idx].mask.len  = sizeof(bitmap_router_in_rif_metadata_mask);
    keys_idx++;

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY,
                                     &attr,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    if (SAI_IP_ADDR_FAMILY_IPV6 == attr->ipprefix.addr_family) {
        SX_LOG_ERR("IPv6 router entry DST IP not supported\n");
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
    }
    memcpy(&bitmap_router_dst_ip_key, &attr->ipprefix.addr.ip4, sizeof(uint32_t));
    bitmap_router_dst_ip_key = htonl(bitmap_router_dst_ip_key);
    memcpy(&bitmap_router_dst_ip_key_mask, &attr->ipprefix.mask.ip4, sizeof(uint32_t));
    bitmap_router_dst_ip_key_mask          = htonl(bitmap_router_dst_ip_key_mask);
    bitmap_router_keys[keys_idx].key.data  = (uint8_t*)&bitmap_router_dst_ip_key;
    bitmap_router_keys[keys_idx].key.len   = sizeof(bitmap_router_dst_ip_key);
    bitmap_router_keys[keys_idx].mask.data = (uint8_t*)&bitmap_router_dst_ip_key_mask;
    bitmap_router_keys[keys_idx].mask.len  = sizeof(bitmap_router_dst_ip_key_mask);
    keys_idx++;

    sai_db_write_lock();

    /* Lazy initialization */
    if (SAI_STATUS_SUCCESS != (sai_status = sai_fx_initialize())) {
        SX_LOG_ERR("Failure in call to sai_fx_initialize\n");
        goto out;
    }

    if (CONTROL_IN_RIF_TO_NEXTHOP_ID == flextrum_action) {
        sai_status = find_attrib_in_list(attr_count,
                                         attr_list,
                                         SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TUNNEL_INDEX,
                                         &attr,
                                         &attr_idx);
        assert(SAI_STATUS_SUCCESS == sai_status);

        bitmap_tunnel_index                   = attr->u16;
        bitmap_router_params[params_idx].data = (uint8_t*)&bitmap_tunnel_index;
        bitmap_router_params[params_idx].len  = sizeof(bitmap_tunnel_index);
        params_idx++;

        sai_status = find_attrib_in_list(attr_count,
                                         attr_list,
                                         SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP,
                                         &attr,
                                         &attr_idx);
        assert(SAI_STATUS_SUCCESS == sai_status);
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_object_to_type(attr->oid, SAI_OBJECT_TYPE_NEXT_HOP, (uint32_t*)&bitmap_router_next_hop, NULL))) {
            SX_LOG_ERR("Invalid bitmap router entry next hop\n");
            sai_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
            goto out;
        }
        bitmap_router_params[params_idx].data = (uint8_t*)&bitmap_router_next_hop;
        bitmap_router_params[params_idx].len  = sizeof(bitmap_router_next_hop);
        params_idx++;
    } else if (CONTROL_IN_RIF_TO_LOCAL_ID == flextrum_action) {
        sai_status = find_attrib_in_list(attr_count,
                                         attr_list,
                                         SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE,
                                         &attr,
                                         &attr_idx);
        assert(SAI_STATUS_SUCCESS == sai_status);
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_rif_oid_to_sdk_rif_id(attr->oid, &bitmap_router_router_interface))) {
            SX_LOG_ERR("Invalid bitmap router entry rif\n");
            sai_status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
            goto out;
        }
        bitmap_router_params[params_idx].data = (uint8_t*)&bitmap_router_router_interface;
        bitmap_router_params[params_idx].len  = sizeof(bitmap_router_router_interface);
        params_idx++;
    } else if (CONTROL_IN_RIF_TO_CPU_ID == flextrum_action) {
        sai_status = find_attrib_in_list(attr_count,
                                         attr_list,
                                         SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TRAP_ID,
                                         &attr,
                                         &attr_idx);
        assert(SAI_STATUS_SUCCESS == sai_status);

        sai_status = mlnx_translate_sai_trap_to_sdk(attr->oid, &bitmap_router_trap_id);
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        bitmap_router_params[params_idx].data = (uint8_t*)&bitmap_router_trap_id;
        bitmap_router_params[params_idx].len  = sizeof(bitmap_router_trap_id);
        params_idx++;
    }

    bitmap_router_key_list.len      = keys_idx;
    bitmap_router_param_list.len    = params_idx;
    bitmap_router_key_list.keys     = bitmap_router_keys;
    bitmap_router_param_list.params = bitmap_router_params;
    if (fx_table_entry_add(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_ROUTER_ID, flextrum_action, bitmap_router_key_list,
                           bitmap_router_param_list, &bitmap_router_priority)) {
        SX_LOG_ERR("Failure in insertion of bitmap_router entry\n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY, bitmap_router_priority, NULL, entry_id))) {
        goto out;
    }

    table_bitmap_router_entry_key_to_str(*entry_id, key_str);
    SX_LOG_NTC("Created table bitmap router entry %s\n", key_str);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_remove_table_bitmap_router_entry(_In_ sai_object_id_t entry_id)
{
    sai_status_t status;
    uint32_t     bitmap_router_offset;
    char         key_str[MAX_KEY_STR_LEN];

    table_bitmap_router_entry_key_to_str(entry_id, key_str);
    SX_LOG_NTC("Remove table bitmap router entry %s\n", key_str);

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY, &bitmap_router_offset, NULL))) {
        SX_LOG_ERR("Failure in extracting offset from bitmap_router entry object id 0x%lx " PRIx64 "\n", entry_id);
        return status;
    }

    sai_db_write_lock();

    if (fx_table_entry_remove(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_ROUTER_ID, bitmap_router_offset)) {
        SX_LOG_ERR("Failure in removal of table_bitmap_router entry at offset %d\n", bitmap_router_offset);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_set_table_bitmap_router_entry_attribute(_In_ sai_object_id_t        entry_id,
                                                          _In_ const sai_attribute_t *attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t mlnx_get_table_bitmap_router_entry_attribute(_In_ sai_object_id_t     entry_id,
                                                          _In_ uint32_t            attr_count,
                                                          _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = entry_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    table_bitmap_router_entry_key_to_str(entry_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY,
                              table_bitmap_router_entry_vendor_attribs,
                              attr_count,
                              attr_list);
}

#define BMFLOOD
#ifdef BMFLOOD
#define SX_BRIDGE_ARRAY_SIZE 20
static sx_status_t bmflood(void)
{
    sx_vlan_attrib_t    vlan_attrib_p;
    uint32_t            ii;
    uint32_t            total_bridge_cnt = 0;
    uint32_t            curr_bridge_cnt  = 0;
    sx_bridge_filter_t *filter_p         = NULL;
    sx_status_t         sx_status        = SX_STATUS_ERROR;
    sx_bridge_id_t      sx_bridge_id[SX_BRIDGE_ARRAY_SIZE];

    SX_LOG_ENTER();

    memset(&vlan_attrib_p, 0, sizeof(vlan_attrib_p));
    vlan_attrib_p.flood_to_router = true;

    sx_status = sx_api_bridge_iter_get(gh_sdk, SX_ACCESS_CMD_GET, SX_BRIDGE_ID_INVALID, filter_p,
                                       NULL, &total_bridge_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error getting bridge count: %s\n",
                   SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sx_status;
    }

    if (0 == total_bridge_cnt) {
        SX_LOG_EXIT();
        return sx_status;
    }

    curr_bridge_cnt = SX_BRIDGE_ARRAY_SIZE;
    sx_status       = sx_api_bridge_iter_get(gh_sdk, SX_ACCESS_CMD_GET_FIRST, SX_BRIDGE_ID_INVALID, filter_p,
                                             sx_bridge_id, &curr_bridge_cnt);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error getting first %d bridges: %s\n",
                   curr_bridge_cnt, SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sx_status;
    }

    while (curr_bridge_cnt > 0) {
        for (ii = 0; ii < curr_bridge_cnt; ii++) {
            sx_status = sx_api_vlan_attrib_set(gh_sdk, sx_bridge_id[ii], &vlan_attrib_p);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Error setting vlan attribute for #%d bridge id %d: %s\n",
                           ii, sx_bridge_id[ii], SX_STATUS_MSG(sx_status));
                SX_LOG_EXIT();
                return sx_status;
            }
        }

        sx_status = sx_api_bridge_iter_get(gh_sdk, SX_ACCESS_CMD_GETNEXT, sx_bridge_id[curr_bridge_cnt - 1], filter_p,
                                           sx_bridge_id, &curr_bridge_cnt);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Error getting next bridge of %d: %s\n",
                       sx_bridge_id[curr_bridge_cnt - 1], SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sx_status;
        }
    }

    SX_LOG_EXIT();
    return SX_STATUS_SUCCESS;
}
#endif /* ifdef BMFLOOD */

static sai_status_t mlnx_bmtor_rif_event(_In_ sx_router_interface_t sx_rif, bool is_add)
{
    sai_status_t status;
    sx_status_t  sx_status;

    if (!g_sai_db_ptr->fx_pipe_created) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_bmtor_fx_handle_init();
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_DBG("bmtor event: %s rif %d\n", is_add ? "adding" : "removing", sx_rif);

    sx_status = fx_pipe_binding_update(g_fx_handle, FX_CONTROL_IN_RIF, &sx_rif, is_add);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to update fx mapping\n");
        return sdk_to_sai(sx_status);
    }

    sx_status = fx_pipe_binding_update(g_fx_handle, FX_CONTROL_OUT_RIF, &sx_rif, is_add);
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


static void* mlnx_bmtor_fx_handle_alloc(size_t size)
{
    if (size != MLNX_SHM_POOL_ELEM_FX_HANDLE_SIZE) {
        SX_LOG_ERR("Unexpected size requested from fx lib - %lu, expected %u\n", size, MLNX_SHM_POOL_ELEM_FX_HANDLE_SIZE);
        return NULL;
    }

    return g_sai_db_ptr->shm_pool.fx_handle_mem;
}

static void mlnx_bmtor_fx_handle_free(void* ptr)
{
    SX_LOG_DBG("fx handle (%p) is freed\n", ptr);
}

static fx_init_params_t g_fx_init_params =  {
        .memory_manager = {
            .alloc = mlnx_bmtor_fx_handle_alloc,
            .free =  mlnx_bmtor_fx_handle_free
            },
        .log_cb = NULL
        };

static sai_status_t mlnx_bmtor_fx_handle_init(void)
{
    sx_status_t sx_status;

    if (!g_fx_handle_initialized) {
        if (!g_sai_db_ptr->fx_initialized) {
            g_fx_init_params.log_cb = sai_log_cb;

            sx_status = fx_init(&g_fx_handle, &g_fx_init_params);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Fx init error %s\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }

            g_fx_handle_is_extern = false;

    #ifdef BMFLOOD
            sx_status = bmflood();
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("bmflood error %s\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
    #endif
            g_sai_db_ptr->fx_initialized = true;
        } else {
            g_fx_handle = mlnx_bmtor_fx_handle_alloc(MLNX_SHM_POOL_ELEM_FX_HANDLE_SIZE);
            if (!g_fx_handle) {
                return SAI_STATUS_FAILURE;
            }

            sx_status = fx_connect(g_fx_handle, sai_log_cb);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Fx extern init error %s\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }

            g_fx_handle_is_extern = true;
        }

        g_fx_handle_initialized = true;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bmtor_fx_handle_deinit(void)
{
    sx_status_t sx_status;

    if (g_fx_handle_initialized) {
        if (g_fx_handle_is_extern) {
            sx_status = fx_disconnect(g_fx_handle);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Fx extern deinit error %s\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        } else {
            sx_status = fx_deinit(g_fx_handle);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Fx deinit error %s\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }

        g_fx_handle_initialized = false;
    }

    return SAI_STATUS_SUCCESS;
}

/* locks are taken from outside */
static sai_status_t sai_fx_initialize(void)
{
    sai_status_t           status;
    sx_router_interface_t *rif_list = NULL;
    uint32_t               num_of_rifs = 0;
    sx_status_t            sx_status   = SX_STATUS_SUCCESS;

    status = mlnx_bmtor_fx_handle_init();
    if (SAI_ERR(status)) {
        return status;
    }

    if (!g_sai_db_ptr->fx_pipe_created) {
        rif_list = calloc(g_resource_limits.router_rifs_max, sizeof(*rif_list));
        if (!rif_list) {
            SX_LOG_ERR("Failed to allocated rif_list\n");
            return SAI_STATUS_NO_MEMORY;
        }

        sx_status = fx_get_bindable_rif_list(g_fx_handle, rif_list, &num_of_rifs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Fx get bindable rif list error %s\n", SX_STATUS_MSG(sx_status));
            goto out;
        }

        sx_status = fx_pipe_create(g_fx_handle, FX_CONTROL_IN_RIF, (void*)rif_list, num_of_rifs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Fx pipe create error %s\n", SX_STATUS_MSG(sx_status));
            goto out;
        }

        sx_status = fx_pipe_create(g_fx_handle, FX_CONTROL_OUT_RIF, (void*)rif_list, num_of_rifs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Fx pipe create error %s\n", SX_STATUS_MSG(sx_status));
            goto out;
        }

        g_sai_db_ptr->fx_pipe_created = true;
    }

out:
    free(rif_list);
    return sdk_to_sai(sx_status);
}

sai_status_t sai_fx_uninitialize(void)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    sx_status_t  sx_status;

    SX_LOG_ENTER();

    sai_db_write_lock();

    if (g_sai_db_ptr->fx_pipe_created) {
        sx_status = fx_pipe_destroy(g_fx_handle, FX_CONTROL_IN_RIF, NULL, 0);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Fx pipe destroy error %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        sx_status = fx_pipe_destroy(g_fx_handle, FX_CONTROL_OUT_RIF, NULL, 0);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Fx pipe destroy error %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        g_sai_db_ptr->fx_pipe_created = false;
    }

    status = mlnx_bmtor_fx_handle_deinit();
    if (SAI_ERR(status)) {
        goto out;
    }

    g_sai_db_ptr->fx_initialized = false;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_bmtor_table_meta_tunnel_entry_attr_get(_In_ const sai_object_key_t   *key,
                                                                _Inout_ sai_attribute_value_t *value,
                                                                _In_ uint32_t                  attr_index,
                                                                _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg);
static const sai_vendor_attribute_entry_t table_meta_tunnel_entry_vendor_attribs[] = {
    { SAI_TABLE_META_TUNNEL_ENTRY_ATTR_ACTION,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_meta_tunnel_entry_attr_get, (void*)SAI_TABLE_META_TUNNEL_ENTRY_ATTR_ACTION,
      NULL, NULL },
    { SAI_TABLE_META_TUNNEL_ENTRY_ATTR_METADATA_KEY,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_meta_tunnel_entry_attr_get, (void*)SAI_TABLE_META_TUNNEL_ENTRY_ATTR_METADATA_KEY,
      NULL, NULL },
    { SAI_TABLE_META_TUNNEL_ENTRY_ATTR_IS_DEFAULT,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_META_TUNNEL_ENTRY_ATTR_TUNNEL_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_meta_tunnel_entry_attr_get, (void*)SAI_TABLE_META_TUNNEL_ENTRY_ATTR_TUNNEL_ID,
      NULL, NULL },
    { SAI_TABLE_META_TUNNEL_ENTRY_ATTR_UNDERLAY_DIP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bmtor_table_meta_tunnel_entry_attr_get, (void*)SAI_TABLE_META_TUNNEL_ENTRY_ATTR_TUNNEL_ID,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        table_meta_tunnel_entry_enum_info[] = {
    [SAI_TABLE_META_TUNNEL_ENTRY_ATTR_ACTION] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_table_meta_tunnel_entry_obj_type_info =
{ table_meta_tunnel_entry_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(table_meta_tunnel_entry_enum_info) };
static void table_meta_tunnel_entry_key_to_str(_In_ sai_object_id_t entry_id, _Out_ char *key_str)
{
    uint32_t priority;

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_META_TUNNEL_ENTRY, &priority, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid L3 VXLAN table entry");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "Table L3 VXLAN entry %d", priority);
    }
}

static sai_status_t mlnx_bmort_fx_action_to_meta_tunnel_entry_action(
    _In_ fx_action_id_t                         fx_action,
    _Out_ sai_table_meta_tunnel_entry_action_t *sai_action)
{
    assert(sai_action);

    switch (fx_action) {
    case CONTROL_OUT_RIF_TUNNEL_ENCAP_ID:
        *sai_action = SAI_TABLE_META_TUNNEL_ENTRY_ACTION_TUNNEL_ENCAP;
        break;

    case NOACTION_ID:
        *sai_action = SAI_TABLE_META_TUNNEL_ENTRY_ACTION_NOACTION;
        break;

    default:
        SX_LOG_ERR("Unexpected fx action %d\n", fx_action);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bmtor_fx_entry_to_meta_tunnel_entry_attr(
    _In_ const fx_key_list_t                   *fx_key_list,
    _In_ const fx_param_list_t                 *fx_param_list,
    _In_ fx_action_id_t                         fx_action_id,
    _Out_ sai_table_meta_tunnel_entry_action_t *action,
    _Out_ uint16_t                             *metadata_key,
    _Out_ sai_object_id_t                      *tunnel_oid,
    _Out_ sai_ip_address_t                     *underlay_dip)
{
    sai_status_t   status;
    sx_tunnel_id_t tunnel_id;

    assert(fx_key_list);
    assert(fx_param_list);
    assert(action);
    assert(metadata_key);
    assert(tunnel_oid);
    assert(underlay_dip);

    if (fx_key_list->len != 1) {
        SX_LOG_ERR("Fx key_list len %lu != 1\n", fx_key_list->len);
        return SAI_STATUS_FAILURE;
    }

    if (fx_key_list->keys[0].key.len != sizeof(sx_user_token_t)) {
        SX_LOG_ERR("Fx key[0] len (%lu) != sizeof(sx_user_token_t) (%lu)\n", fx_key_list->len,
                   sizeof(sx_user_token_t));
        return SAI_STATUS_FAILURE;
    }

    *metadata_key = *(const sx_user_token_t*)fx_key_list->keys[0].key.data;

    status = mlnx_bmort_fx_action_to_meta_tunnel_entry_action(fx_action_id, action);
    if (SAI_ERR(status)) {
        return status;
    }

    if ((fx_param_list->len == 0) && (fx_action_id != NOACTION_ID)) {
        SX_LOG_ERR("Invalid fx state - param count is 0 but action id is not NOACTION_ID\n");
        return SAI_STATUS_FAILURE;
    }

    if (fx_param_list->len != 0) {
        if (fx_param_list->params[0].len != sizeof(sx_tunnel_id_t)) {
            SX_LOG_ERR("Unexpected param len %lu, expected %lu\n", fx_param_list->params[0].len,
                       sizeof(sx_tunnel_id_t));
            return SAI_STATUS_FAILURE;
        }

        if (fx_param_list->params[1].len != sizeof(sai_ip4_t)) {
            SX_LOG_ERR("Unexpected param len %lu, expected %lu\n", fx_param_list->params[1].len, sizeof(sai_ip4_t));
            return SAI_STATUS_FAILURE;
        }

        tunnel_id = *(const sx_tunnel_id_t*)fx_param_list->params[0].data;
        status    = mlnx_translate_sdk_tunnel_id_to_sai_tunnel_id(tunnel_id, tunnel_oid);
        if (SAI_ERR(status)) {
            return status;
        }

        underlay_dip->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        underlay_dip->addr.ip4    = *(const sai_ip4_t*)fx_param_list->params[1].data;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bmtor_table_meta_tunnel_entry_attr_get(_In_ const sai_object_key_t   *key,
                                                                _Inout_ sai_attribute_value_t *value,
                                                                _In_ uint32_t                  attr_index,
                                                                _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg)
{
    sai_status_t                         status;
    sx_status_t                          sx_status;
    sai_object_id_t                      entry_id = key->key.object_id;
    sai_attr_id_t                        attr;
    uint32_t                             fx_offset;
    fx_action_id_t                       fx_action_id;
    fx_key_list_t                        fx_key_list   = MLNX_FX_KEY_LIST_EMPTY;
    fx_param_list_t                      fx_param_list = MLNX_FX_PARAMS_LIST_EMPTY;
    uint16_t                             metadata_key;
    sai_object_id_t                      tunnel_oid;
    sai_ip_address_t                     underlay_dip;
    sai_table_meta_tunnel_entry_action_t action;

    SX_LOG_ENTER();

    attr = (long)(arg);

    assert((attr == SAI_TABLE_META_TUNNEL_ENTRY_ATTR_ACTION) ||
           (attr == SAI_TABLE_META_TUNNEL_ENTRY_ATTR_METADATA_KEY) ||
           (attr == SAI_TABLE_META_TUNNEL_ENTRY_ATTR_TUNNEL_ID) ||
           (attr == SAI_TABLE_META_TUNNEL_ENTRY_ATTR_UNDERLAY_DIP));

    status = mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_META_TUNNEL_ENTRY,
                                 &fx_offset, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failure in extracting offset from L3 VXLAN table entry object id 0x%lx " PRIx64 "\n",
                   entry_id);
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_bmtor_fx_data_init(&fx_key_list, &fx_param_list);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();

    sx_status = fx_table_entry_get(g_fx_handle, CONTROL_OUT_RIF_TABLE_L3_VXLAN_ID, fx_offset,
                                   &fx_action_id, &fx_key_list, &fx_param_list);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
        sai_db_unlock();
        goto out;
    }

    status = mlnx_bmtor_fx_entry_to_meta_tunnel_entry_attr(&fx_key_list, &fx_param_list, fx_action_id,
                                                           &action, &metadata_key, &tunnel_oid, &underlay_dip);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        goto out;
    }

    sai_db_unlock();

    switch (attr) {
    case SAI_TABLE_META_TUNNEL_ENTRY_ATTR_ACTION:
        value->s32 = action;
        break;

    case SAI_TABLE_META_TUNNEL_ENTRY_ATTR_METADATA_KEY:
        value->u16 = metadata_key;
        break;

    case SAI_TABLE_META_TUNNEL_ENTRY_ATTR_TUNNEL_ID:
        if (action != SAI_TABLE_META_TUNNEL_ENTRY_ACTION_TUNNEL_ENCAP) {
            SX_LOG_NTC("Tunnel id is not set\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        value->oid = tunnel_oid;
        break;

    case SAI_TABLE_META_TUNNEL_ENTRY_ATTR_UNDERLAY_DIP:
        if (action != SAI_TABLE_META_TUNNEL_ENTRY_ACTION_TUNNEL_ENCAP) {
            SX_LOG_NTC("Underlay dip id is not set\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
            goto out;
        }

        value->ipaddr = underlay_dip;
        break;

    default:
        SX_LOG_ERR("Unexpected attr - %d\n", attr);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    mlnx_bmtor_fx_data_deinit(&fx_key_list, &fx_param_list);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t get_meta_tunnel_fx_action(_In_ sai_table_meta_tunnel_entry_action_t action,
                                              _Out_ fx_action_id_t                     *action_id,
                                              _In_ uint32_t                             param_index)
{
    if (NULL == action_id) {
        SX_LOG_ERR("NULL action id value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_TABLE_META_TUNNEL_ENTRY_ACTION_TUNNEL_ENCAP:
        *action_id = CONTROL_OUT_RIF_TUNNEL_ENCAP_ID;
        break;

    case SAI_TABLE_META_TUNNEL_ENTRY_ACTION_NOACTION:
        *action_id = NOACTION_ID;
        break;

    default:
        SX_LOG_ERR("Invalid L3 VXLAN table entry action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_table_meta_tunnel_entry(_Out_ sai_object_id_t      *entry_id,
                                                        _In_ sai_object_id_t        switch_id,
                                                        _In_ uint32_t               attr_count,
                                                        _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 sai_status;
    const sai_attribute_value_t *attr = NULL;
    uint32_t                     attr_idx;
    fx_key_t                     meta_tunnel_keys[1];
    fx_param_t                   meta_tunnel_params[2];
    fx_key_list_t                meta_tunnel_key_list;
    fx_param_list_t              meta_tunnel_param_list;
    fx_action_id_t               flextrum_action = FX_ACTION_INVALID_ID;
    sai_ip4_t                    meta_tunnel_underlay_dip;
    uint16_t                     meta_tunnel_metadata_key;
    sx_tunnel_id_t               meta_tunnel_tunnel_id;
    sx_acl_rule_offset_t         meta_tunnel_priority = 0;
    size_t                       keys_idx             = 0, params_idx = 0;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == entry_id) {
        SX_LOG_ERR("NULL entry id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_TABLE_META_TUNNEL_ENTRY,
                                    table_bitmap_router_entry_vendor_attribs, SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_attr_list_to_str(attr_count,
                         attr_list,
                         SAI_OBJECT_TYPE_TABLE_META_TUNNEL_ENTRY,
                         MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create table L3 VXLAN entry, %s\n", list_str);

    meta_tunnel_key_list.keys     = meta_tunnel_keys;
    meta_tunnel_param_list.params = meta_tunnel_params;

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_TABLE_META_TUNNEL_ENTRY_ATTR_ACTION, &attr, &attr_idx);
    assert(sai_status == SAI_STATUS_SUCCESS);

    sai_status = get_meta_tunnel_fx_action(attr->s32, &flextrum_action, attr_idx);
    if (SAI_ERR(sai_status)) {
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_META_TUNNEL_ENTRY_ATTR_METADATA_KEY,
                                     &attr,
                                     &attr_idx);
    assert(sai_status == SAI_STATUS_SUCCESS);

    meta_tunnel_metadata_key = attr->u16;
    if (meta_tunnel_metadata_key & 0xF000) {
        SX_LOG_ERR("METADATA_KEY is out of range (0, 0x0FFF)\n");
        SX_LOG_EXIT();
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + attr_idx;
    }

    meta_tunnel_keys[keys_idx].key.data = (uint8_t*)&meta_tunnel_metadata_key;
    meta_tunnel_keys[keys_idx].key.len  = sizeof(meta_tunnel_metadata_key);
    keys_idx++;

    sai_db_write_lock();

    if (flextrum_action == CONTROL_OUT_RIF_TUNNEL_ENCAP_ID) {
        sai_status = find_attrib_in_list(attr_count,
                                         attr_list,
                                         SAI_TABLE_META_TUNNEL_ENTRY_ATTR_TUNNEL_ID,
                                         &attr,
                                         &attr_idx);
        assert(sai_status == SAI_STATUS_SUCCESS);

        sai_status = mlnx_sai_tunnel_to_sx_tunnel_id(attr->oid, &meta_tunnel_tunnel_id);
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        meta_tunnel_params[params_idx].data = (uint8_t*)&meta_tunnel_tunnel_id;
        meta_tunnel_params[params_idx].len  = sizeof(meta_tunnel_tunnel_id);
        params_idx++;

        sai_status = find_attrib_in_list(attr_count,
                                         attr_list,
                                         SAI_TABLE_META_TUNNEL_ENTRY_ATTR_UNDERLAY_DIP,
                                         &attr,
                                         &attr_idx);
        assert(sai_status == SAI_STATUS_SUCCESS);

        meta_tunnel_underlay_dip = htonl(attr->ipaddr.addr.ip4);

        meta_tunnel_params[params_idx].data = (uint8_t*)&meta_tunnel_underlay_dip;
        meta_tunnel_params[params_idx].len  = sizeof(meta_tunnel_underlay_dip);
        params_idx++;
    }

    /* Lazy initialization */
    sai_status = sai_fx_initialize();
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failure in call to sai_fx_initialize\n");
        goto out;
    }

    meta_tunnel_key_list.len   = keys_idx;
    meta_tunnel_param_list.len = params_idx;

    SX_LOG_DBG("Creating l3_vxlan entry %u tunnel_id %u\n", flextrum_action,  meta_tunnel_tunnel_id);
    if (fx_table_entry_add(g_fx_handle, CONTROL_OUT_RIF_TABLE_L3_VXLAN_ID, flextrum_action, meta_tunnel_key_list,
                           meta_tunnel_param_list, &meta_tunnel_priority)) {
        SX_LOG_ERR("Failure in insertion of l3_vxlan entry\n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    sai_status = mlnx_create_object(SAI_OBJECT_TYPE_TABLE_META_TUNNEL_ENTRY, meta_tunnel_priority, NULL, entry_id);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    table_meta_tunnel_entry_key_to_str(*entry_id, key_str);
    SX_LOG_NTC("Created table L3 VXLAN entry %s\n", key_str);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_remove_table_meta_tunnel_entry(_In_ sai_object_id_t entry_id)
{
    sai_status_t status;
    uint32_t     meta_tunnel_offset;
    char         key_str[MAX_KEY_STR_LEN];

    table_meta_tunnel_entry_key_to_str(entry_id, key_str);
    SX_LOG_NTC("Remove table L3 VXLAN entry %s\n", key_str);

    status = mlnx_object_to_type(entry_id, SAI_OBJECT_TYPE_TABLE_META_TUNNEL_ENTRY, &meta_tunnel_offset, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failure in extracting offset from l3_vxlan entry object id 0x%lx " PRIx64 "\n", entry_id);
        SX_LOG_EXIT();
        return status;
    }

    sai_db_write_lock();

    if (fx_table_entry_remove(g_fx_handle, CONTROL_OUT_RIF_TABLE_L3_VXLAN_ID, meta_tunnel_offset)) {
        SX_LOG_ERR("Failure in removal of table_l3_vxlan entry at offset %d\n", meta_tunnel_offset);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_set_table_meta_tunnel_entry_attribute(_In_ sai_object_id_t        entry_id,
                                                               _In_ const sai_attribute_t *attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t mlnx_get_table_meta_tunnel_entry_attribute(_In_ sai_object_id_t     entry_id,
                                                               _In_ uint32_t            attr_count,
                                                               _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = entry_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    table_meta_tunnel_entry_key_to_str(entry_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_TABLE_META_TUNNEL_ENTRY,
                              table_meta_tunnel_entry_vendor_attribs,
                              attr_count,
                              attr_list);
}

sai_status_t mlnx_bmtor_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return fx_log_set(level);
}

const sai_bmtor_api_t mlnx_bmtor_api = {
    mlnx_create_table_bitmap_classification_entry,
    mlnx_remove_table_bitmap_classification_entry,
    mlnx_set_table_bitmap_classification_entry_attribute,
    mlnx_get_table_bitmap_classification_entry_attribute,
    NULL,
    NULL,
    NULL,
    mlnx_create_table_bitmap_router_entry,
    mlnx_remove_table_bitmap_router_entry,
    mlnx_set_table_bitmap_router_entry_attribute,
    mlnx_get_table_bitmap_router_entry_attribute,
    NULL,
    NULL,
    NULL,
    mlnx_create_table_meta_tunnel_entry,
    mlnx_remove_table_meta_tunnel_entry,
    mlnx_set_table_meta_tunnel_entry_attribute,
    mlnx_get_table_meta_tunnel_entry_attribute,
    NULL,
    NULL,
    NULL,
};
