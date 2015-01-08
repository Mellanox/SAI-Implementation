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

#undef  __MODULE__
#define __MODULE__ SAI_ROUTER

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *    Set virtual router attribute value
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *    [in] attribute - virtual router attribute
 *    [in] value - virtual router attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_vr_attribute(_In_ sai_vr_id_t vr_id, _In_ sai_vr_attr_t attribute, _In_ uint64_t value)
{
    /* sx_router_id_t vrid = (sx_router_id_t)vr_id; */

    SX_LOG_ENTER();

    switch (attribute) {
    case SAI_VR_ATTR_ADMIN_V4_STATE:
        /* TODO : implement edit router admin state */
        return SAI_STATUS_FAILURE;

    case SAI_VR_ATTR_ADMIN_V6_STATE:
        /* TODO : implement edit router admin state */
        return SAI_STATUS_FAILURE;

    case SAI_VR_ATTR_MAC_ADDRESS:
    case SAI_VR_ATTR_VIOLATION_TTL1_ACTION:
    case SAI_VR_ATTR_VIOLATION_TTL2_ACTION:
    case SAI_VR_ATTR_VIOLATION_IP_OPTIONS:
    default:
        SX_LOG_ERR("Invalid router attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *    Get virtual router attribute Value
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *    [in] attribute - virtual router attribute
 *    [out] value - virtual router attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_vr_attribute(_In_ sai_vr_id_t vr_id, _In_ sai_vr_attr_t attribute, _Out_ uint64_t* value)
{
    sx_router_id_t         vrid = (sx_router_id_t)vr_id;
    sx_router_attributes_t router_attr;
    sx_status_t            status;

    if (NULL == value) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attribute) {
    case SAI_VR_ATTR_ADMIN_V4_STATE:
        if (SX_STATUS_SUCCESS != (status = sx_api_router_get(gh_sdk, vrid, &router_attr))) {
            SX_LOG_ERR("Failed to get router - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = router_attr.ipv4_enable;
        return SAI_STATUS_SUCCESS;

    case SAI_VR_ATTR_ADMIN_V6_STATE:
        if (SX_STATUS_SUCCESS != (status = sx_api_router_get(gh_sdk, vrid, &router_attr))) {
            SX_LOG_ERR("Failed to get router - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        *value = router_attr.ipv6_enable;
        return SAI_STATUS_SUCCESS;

    case SAI_VR_ATTR_MAC_ADDRESS:
    case SAI_VR_ATTR_VIOLATION_TTL1_ACTION:
    case SAI_VR_ATTR_VIOLATION_TTL2_ACTION:
    case SAI_VR_ATTR_VIOLATION_IP_OPTIONS:
    default:
        SX_LOG_ERR("Invalid router attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *    Create virtual router
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_vr_create(_Out_ sai_vr_id_t *vr_id)
{
    sx_status_t            status;
    sx_router_attributes_t router_attr;
    sx_router_id_t         vrid;

    SX_LOG_ENTER();

    if (NULL == vr_id) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    router_attr.ipv4_enable = 1;
    router_attr.ipv6_enable = 0;
    router_attr.ipv4_mc_enable = 0;
    router_attr.ipv6_mc_enable = 0;
    router_attr.uc_default_rule_action = SX_ROUTER_ACTION_DROP;
    router_attr.uc_default_rule_action = SX_ROUTER_ACTION_DROP;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_set(gh_sdk, SX_ACCESS_CMD_ADD, &router_attr, &vrid))) {
        SX_LOG_ERR("Failed to set router - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    *vr_id = vrid;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Delete virtual router
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_vr(_In_ sai_vr_id_t vr_id)
{
    sx_status_t            status;
    sx_router_id_t         vrid = (sx_router_id_t)vr_id;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_router_set(gh_sdk, SX_ACCESS_CMD_DELETE, NULL, &vrid))) {
        SX_LOG_ERR("Failed to set router - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_vr_api_t router_api = {
    mlnx_vr_create,
    mlnx_delete_vr,
    mlnx_set_vr_attribute,
    mlnx_get_vr_attribute
};
