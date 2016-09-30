/*
 *  Copyright (C) 2014. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
#define __MODULE__ SAI_ROUTER

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t router_attribs[] = {
    { SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE, false, true, true, true,
      "Router admin V4 state", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE, false, true, true, true,
      "Router admin V6 state", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, false, true, true, true,
      "Router source MAC address", SAI_ATTR_VAL_TYPE_MAC },
    { SAI_VIRTUAL_ROUTER_ATTR_VIOLATION_TTL1_ACTION, false, true, true, true,
      "Router action for TTL0/1", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_VIRTUAL_ROUTER_ATTR_VIOLATION_IP_OPTIONS, false, true, true, true,
      "Router action for IP options", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_router_admin_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static const sai_vendor_attribute_entry_t router_vendor_attribs[] = {
    { SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE,
      { true, false, false, true },
      { true, false, true, true },
      mlnx_router_admin_get, (void*)SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE,
      NULL, NULL },
    { SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE,
      { true, false, false, true },
      { true, false, true, true },
      mlnx_router_admin_get, (void*)SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE,
      NULL, NULL },
    { SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_VIRTUAL_ROUTER_ATTR_VIOLATION_TTL1_ACTION,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_VIRTUAL_ROUTER_ATTR_VIOLATION_IP_OPTIONS,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static void router_key_to_str(_In_ sai_object_id_t vr_id, _Out_ char *key_str)
{
    uint32_t vrid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(vr_id, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &vrid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid vr ID");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "vr ID %u", vrid);
    }
}

/*
 * Routine Description:
 *    Set virtual router attribute Value
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_virtual_router_attribute(_In_ sai_object_id_t vr_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = vr_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    router_key_to_str(vr_id, key_str);
    return sai_set_attribute(&key, key_str, router_attribs, router_vendor_attribs, attr);
}

/*
 * Routine Description:
 *    Get virtual router attribute Value
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_virtual_router_attribute(_In_ sai_object_id_t     vr_id,
                                                      _In_ uint32_t            attr_count,
                                                      _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = vr_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    router_key_to_str(vr_id, key_str);
    return sai_get_attributes(&key, key_str, router_attribs, router_vendor_attribs, attr_count, attr_list);
}

/* Admin V4, V6 State [bool] */
static sai_status_t mlnx_router_admin_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t           status;
    sx_router_id_t         vrid;
    uint32_t               data;
    sx_router_attributes_t router_attr;

    SX_LOG_ENTER();

    assert((SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE == (long)arg) ||
           (SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &data, NULL))) {
        return status;
    }
    vrid = (sx_router_id_t)data;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_get(gh_sdk, vrid, &router_attr))) {
        SX_LOG_ERR("Failed to get router - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    if (SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE == (long)arg) {
        value->booldata = router_attr.ipv4_enable;
    } else {
        value->booldata = router_attr.ipv6_enable;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Create virtual router
 *
 * Arguments:
 *    [out] vr_id - virtual router id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_virtual_router(_Out_ sai_object_id_t      *vr_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list)
{
    sx_status_t                  status;
    sx_router_attributes_t       router_attr;
    sx_router_id_t               vrid;
    const sai_attribute_value_t *adminv4, *adminv6;
    uint32_t                     adminv4_index, adminv6_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == vr_id) {
        SX_LOG_ERR("NULL vr_id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, router_attribs, router_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, router_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create router, %s\n", list_str);

    memset(&router_attr, 0, sizeof(router_attr));

    router_attr.ipv4_enable            = 1;
    router_attr.ipv6_enable            = 1;
    router_attr.ipv4_mc_enable         = 0;
    router_attr.ipv6_mc_enable         = 0;
    router_attr.uc_default_rule_action = SX_ROUTER_ACTION_DROP;
    router_attr.mc_default_rule_action = SX_ROUTER_ACTION_DROP;

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE, &adminv4,
                                 &adminv4_index))) {
        router_attr.ipv4_enable = adminv4->booldata;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE, &adminv6,
                                 &adminv6_index))) {
        router_attr.ipv6_enable = adminv6->booldata;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_set(gh_sdk, SX_ACCESS_CMD_ADD, &router_attr, &vrid))) {
        SX_LOG_ERR("Failed to add router - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, vrid, NULL, vr_id))) {
        return status;
    }
    router_key_to_str(*vr_id, key_str);
    SX_LOG_NTC("Created router %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove virtual router
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_virtual_router(_In_ sai_object_id_t vr_id)
{
    sx_status_t    status;
    sx_router_id_t vrid;
    uint32_t       data;
    char           key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    router_key_to_str(vr_id, key_str);
    SX_LOG_NTC("Remove router %s\n", key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(vr_id, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &data, NULL))) {
        return status;
    }
    vrid = (sx_router_id_t)data;

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    if (vr_id == g_sai_db_ptr->default_vrid) {
        cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_ERR("Can't delete the default router\n");
        return SAI_STATUS_OBJECT_IN_USE;
    }
    cl_plock_release(&g_sai_db_ptr->p_lock);

    if (SX_STATUS_SUCCESS != (status = sx_api_router_set(gh_sdk, SX_ACCESS_CMD_DELETE, NULL, &vrid))) {
        SX_LOG_ERR("Failed to delete router - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_router_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_router_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_virtual_router_api_t mlnx_router_api = {
    mlnx_create_virtual_router,
    mlnx_remove_virtual_router,
    mlnx_set_virtual_router_attribute,
    mlnx_get_virtual_router_attribute
};
