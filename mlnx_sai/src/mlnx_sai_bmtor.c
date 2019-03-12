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

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static bool        g_fx_initialized = false;
static fx_handle_t g_fx_handle;
static sai_status_t sai_fx_initialize();
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

static const sai_vendor_attribute_entry_t table_bitmap_classification_entry_vendor_attribs[] = {
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IS_DEFAULT,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
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
    int                          keys_idx        = 0;
    int                          params_idx      = 0;
    fx_action_id_t               flextrum_action =
        SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_NOACTION;
    sx_acl_rule_offset_t  bitmap_classification_priority = 0;
    sx_router_interface_t bitmap_classification_router_interface_key;
    uint32_t              bitmap_classification_in_rif_metadata;
    char                  list_str[MAX_LIST_VALUE_STR_LEN];
    char                  key_str[MAX_KEY_STR_LEN];

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

    /* Lazy initialization */
    if (SAI_STATUS_SUCCESS != (sai_status = sai_fx_initialize())) {
        SX_LOG_ERR("Failure in call to sai_fx_initialize\n");
        return sai_status;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION,
                                     &attr,
                                     &attr_idx);
    assert(SAI_STATUS_SUCCESS == sai_status);
    sai_status = get_bitmap_classification_fx_action(attr->s32, &flextrum_action, attr_idx);
    if (SAI_ERR(sai_status)) {
        return sai_status;
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
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
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
        SX_LOG_ERR("Failure in insertion of bitmap_classification entry\n");
        return SAI_STATUS_FAILURE;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TABLE_BITMAP_CLASSIFICATION_ENTRY, bitmap_classification_priority,
                                NULL,
                                entry_id))) {
        return sai_status;
    }

    table_bitmap_classification_entry_key_to_str(*entry_id, key_str);
    SX_LOG_NTC("Created table bitmap classification entry %s\n", key_str);

    return SAI_STATUS_SUCCESS;
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
        SX_LOG_ERR("Failure in extracting offest from bitmap_classification entry object id 0x%lx " PRIx64 "\n",
                   entry_id);
        return status;
    }
    if (fx_table_entry_remove(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_CLASSIFICATION_ID,
                              bitmap_classification_offset)) {
        SX_LOG_ERR("Failure in removal of table_bitmap_classification entry at offset %d\n",
                   bitmap_classification_offset);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
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
    return SAI_STATUS_NOT_IMPLEMENTED;
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

static const sai_vendor_attribute_entry_t table_bitmap_router_entry_vendor_attribs[] = {
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_TRAP_ID,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
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

sai_status_t mlnx_create_table_bitmap_router_entry(_Out_ sai_object_id_t      *entry_id,
                                                   _In_ sai_object_id_t        switch_id,
                                                   _In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 sai_status;
    uint32_t                     attr_idx;
    const sai_attribute_value_t *attr;
    fx_key_t                     bitmap_router_keys[2];
    fx_param_t                   bitmap_router_params[1];
    fx_key_list_t                bitmap_router_key_list;
    fx_param_list_t              bitmap_router_param_list;
    int                          keys_idx        = 0;
    int                          params_idx      = 0;
    fx_action_id_t               flextrum_action = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_NOACTION;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_acl_rule_offset_t         bitmap_router_priority;
    uint32_t                     bitmap_router_in_rif_metadata_key, bitmap_router_in_rif_metadata_mask;
    uint32_t                     bitmap_router_dst_ip_key, bitmap_router_dst_ip_key_mask;
    sx_ecmp_id_t                 bitmap_router_next_hop;
    sx_router_interface_t        bitmap_router_router_interface;
    sx_flex_acl_trap_action_t    bitmap_router_trap_id;

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

    /* Lazy initialization */
    if (SAI_STATUS_SUCCESS != (sai_status = sai_fx_initialize())) {
        SX_LOG_ERR("Failure in call to sai_fx_initialize\n");
        return sai_status;
    }

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

    if (CONTROL_IN_RIF_TO_NEXTHOP_ID == flextrum_action) {
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
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
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
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
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
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_object_to_type(attr->oid, SAI_OBJECT_TYPE_HOSTIF_TRAP, (uint32_t*)&bitmap_router_trap_id,
                                     NULL))) {
            SX_LOG_ERR("Invalid bitmap router entry trap id\n");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
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
        return SAI_STATUS_FAILURE;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             mlnx_create_object(SAI_OBJECT_TYPE_TABLE_BITMAP_ROUTER_ENTRY, bitmap_router_priority, NULL, entry_id))) {
        return sai_status;
    }

    table_bitmap_router_entry_key_to_str(*entry_id, key_str);
    SX_LOG_NTC("Created table bitmap router entry %s\n", key_str);

    return SAI_STATUS_SUCCESS;
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
        SX_LOG_ERR("Failure in extracting offest from bitmap_router entry object id 0x%lx " PRIx64 "\n", entry_id);
        return status;
    }
    if (fx_table_entry_remove(g_fx_handle, CONTROL_IN_RIF_TABLE_BITMAP_ROUTER_ID, bitmap_router_offset)) {
        SX_LOG_ERR("Failure in removal of table_bitmap_router entry at offset %d\n", bitmap_router_offset);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
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
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t sai_fx_rebind()
{
    sx_router_interface_t rif_list[RIF_NUM];
    uint32_t              num_of_rifs = 0;
    sx_status_t           sx_status;

    sx_status = fx_get_bindable_rif_list(g_fx_handle, rif_list, &num_of_rifs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx get bindable rif list error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    sx_status = fx_pipe_rebind(g_fx_handle, FX_CONTROL_IN_RIF, (void*)rif_list, num_of_rifs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx pipe rebind error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

#define BMFLOOD
#ifdef BMFLOOD
#include <sx/sxd/sxd_access_register_init.h>
#include <sx/sxd/sxd_access_register.h>

#define BRIDGE_START              (MIN_SX_BRIDGE_ID + 1)
#define NUM_BRIDGES               900
#define SPECTRUM_PORT_EXT_NUM_MAX (64)
#define SX_ROUTER_PHY_PORT        (SPECTRUM_PORT_EXT_NUM_MAX + 2)

static sx_status_t bmflood(void)
{
    sxd_status_t       sxd_ret    = SXD_STATUS_SUCCESS;
    sxd_handle         sxd_handle = 0;
    uint32_t           dev_num    = 1;
    char               dev_name[MAX_NAME_LEN];
    char              *dev_names[1] = { dev_name };
    struct ku_sftr_reg sftr_reg_data;
    sxd_reg_meta_t     sftr_reg_meta;
    int                ii;

    memset(&sftr_reg_meta, 0, sizeof(sftr_reg_meta));
    memset(&sftr_reg_data, 0, sizeof(sftr_reg_data));

    sxd_ret = sxd_access_reg_init(0, sai_log_cb, 0);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        SX_LOG_ERR("Failed to init access reg - %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SX_STATUS_ERROR;
    }

    /* get device list from the devices directory */
    sxd_ret = sxd_get_dev_list(dev_names, &dev_num);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        SX_LOG_ERR("sxd_get_dev_list error %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SX_STATUS_ERROR;
    }

    /* open the first device */
    sxd_ret = sxd_open_device(dev_name, &sxd_handle);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        SX_LOG_ERR("sxd_open_device error %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SX_STATUS_ERROR;
    }

    sftr_reg_meta.swid       = 0;
    sftr_reg_meta.dev_id     = 1;
    sftr_reg_meta.access_cmd = SXD_ACCESS_CMD_ADD;

    for (ii = BRIDGE_START; ii < BRIDGE_START + NUM_BRIDGES; ii++) {
        sftr_reg_data.swid                             = 0;
        sftr_reg_data.index                            = ii - MIN_SX_BRIDGE_ID;
        sftr_reg_data.range                            = 0;
        sftr_reg_data.flood_table                      = 1;
        sftr_reg_data.table_type                       = SFGC_TABLE_TYPE_FID;
        sftr_reg_data.mask_bitmap[SX_ROUTER_PHY_PORT]  = 1;
        sftr_reg_data.ports_bitmap[SX_ROUTER_PHY_PORT] = 1;

        sxd_ret = sxd_access_reg_sftr(&sftr_reg_data, &sftr_reg_meta, 1, NULL, NULL);
        if (SXD_CHECK_FAIL(sxd_ret)) {
            SX_LOG_ERR("sxd_access_reg_sftr bridge %ii error %s.\n", ii, SXD_STATUS_MSG(sxd_ret));
            return SX_STATUS_ERROR;
        }
    }

    sxd_ret = sxd_close_device(sxd_handle);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        SX_LOG_ERR("sxd_close_device error: %s\n", SXD_STATUS_MSG(sxd_ret));
        return SX_STATUS_ERROR;
    }

    return SX_STATUS_SUCCESS;
}
#endif /* ifdef BMFLOOD */

static sai_status_t sai_fx_initialize()
{
    sx_router_interface_t rif_list[RIF_NUM];
    uint32_t              num_of_rifs = 0;
    sx_status_t           sx_status;

#ifdef BMFLOOD
    sx_status = bmflood();
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("bmflood error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
#endif

    if (g_fx_initialized) {
        return sai_fx_rebind();
    }
    sx_status = fx_init(&g_fx_handle);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx init error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    sx_status = fx_extern_init(g_fx_handle);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx extern init error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    sx_status = fx_get_bindable_rif_list(g_fx_handle, rif_list, &num_of_rifs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx get bindable rif list error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    sx_status = fx_pipe_create(g_fx_handle, FX_CONTROL_IN_RIF, (void*)rif_list, num_of_rifs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx pipe create error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    g_fx_initialized = true;
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_fx_uninitialize()
{
    sx_router_interface_t rif_list[RIF_NUM];
    uint32_t              num_of_rifs = 0;
    sx_status_t           sx_status;

    if (!g_fx_initialized) {
        return SAI_STATUS_SUCCESS;
    }

    g_fx_initialized = false;
    sx_status        = fx_get_bindable_rif_list(g_fx_handle, rif_list, &num_of_rifs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx get bindable rif list error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    sx_status = fx_pipe_destroy(g_fx_handle, FX_CONTROL_IN_RIF, (void*)rif_list, num_of_rifs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx pipe destroy error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    sx_status = fx_extern_deinit(g_fx_handle);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx extern deinit error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    sx_status = fx_deinit(g_fx_handle);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Fx deinit error %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bmtor_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
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
};
