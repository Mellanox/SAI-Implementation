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
#define __MODULE__ SAI_NEXT_HOP_GROUP

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t next_hop_group_attribs[] = {
    { SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT, false, false, false, true,
      "Next hop group entries count", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_NEXT_HOP_GROUP_ATTR_TYPE, true, true, false, true,
      "Next hop group type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_LIST, true, true, true, true,
      "Next hop group hop list", SAI_ATTR_VAL_TYPE_OBJLIST },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_next_hop_group_count_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_next_hop_group_type_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_next_hop_group_hop_list_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_next_hop_group_hop_list_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static const sai_vendor_attribute_entry_t next_hop_group_vendor_attribs[] = {
    { SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_next_hop_group_count_get, NULL,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_group_type_get, NULL,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_next_hop_group_hop_list_get, NULL,
      mlnx_next_hop_group_hop_list_set, NULL },
};
static void next_hop_group_key_to_str(_In_ sai_object_id_t next_hop_group_id, _Out_ char *key_str)
{
    uint32_t groupid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(next_hop_group_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &groupid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid next hop group id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "next hop group id %u", groupid);
    }
}

static sai_status_t mlnx_translate_sai_next_hop_object(_In_ uint32_t              index,
                                                       _In_ const sai_object_id_t next_hop_id,
                                                       _Out_ sx_next_hop_t       *sx_next_hop)
{
    sai_status_t status;
    uint32_t     sdk_next_hop_cnt;
    sx_ecmp_id_t sdk_ecmp_id;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(next_hop_id, SAI_OBJECT_TYPE_NEXT_HOP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    sdk_next_hop_cnt = 1;
    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, sx_next_hop, &sdk_next_hop_cnt))) {
        SX_LOG_ERR("Failed to get ecmp - %s index %u\n", SX_STATUS_MSG(status), index);
        return sdk_to_sai(status);
    }

    if (1 != sdk_next_hop_cnt) {
        SX_LOG_ERR("Invalid next hosts count %u index %u\n", sdk_next_hop_cnt, index);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_translate_sai_next_hop_objects(_In_ uint32_t               count,
                                                        _In_ const sai_object_id_t *next_hop_id,
                                                        _Out_ sx_next_hop_t        *sx_next_hop)
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
static sai_status_t mlnx_create_next_hop_group(_Out_ sai_object_id_t     * next_hop_group_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *type, *hop_list;
    uint32_t                     type_index, hop_list_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_next_hop_t                next_hops[ECMP_MAX_PATHS];
    sx_ecmp_id_t                 sdk_ecmp_id;
    uint32_t                     next_hop_cnt;

    SX_LOG_ENTER();

    if (NULL == next_hop_group_id) {
        SX_LOG_ERR("NULL next hop group id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, next_hop_group_attribs, next_hop_group_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, next_hop_group_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create next hop group, %s\n", list_str);

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_TYPE, &type, &type_index));
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count,
                               attr_list,
                               SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_LIST,
                               &hop_list,
                               &hop_list_index));

    if (SAI_NEXT_HOP_GROUP_ECMP != type->s32) {
        SX_LOG_ERR("Invalid next hop group type %d on create\n", type->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    next_hop_cnt = hop_list->objlist.count;
    if (next_hop_cnt > ECMP_MAX_PATHS) {
        SX_LOG_ERR("Next hop count %u bigger than maximum %u\n", next_hop_cnt, ECMP_MAX_PATHS);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + hop_list_index;
    }
    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_next_hop_objects(next_hop_cnt, hop_list->objlist.list,
                                                                            next_hops))) {
        return status;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_CREATE, &sdk_ecmp_id, next_hops,
                                                              &next_hop_cnt))) {
        SX_LOG_ERR("Failed to create ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP, sdk_ecmp_id, NULL, next_hop_group_id))) {
        return status;
    }
    next_hop_group_key_to_str(*next_hop_group_id, key_str);
    SX_LOG_NTC("Created next hop group %s\n", key_str);

    SX_LOG_EXIT();
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
    char         key_str[MAX_KEY_STR_LEN];
    sai_status_t status;
    sx_ecmp_id_t sdk_ecmp_id;
    uint32_t     next_hop_cnt = 0;

    SX_LOG_ENTER();

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    SX_LOG_NTC("Remove next hop group %s\n", key_str);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(next_hop_group_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sdk_ecmp_id, NULL, &next_hop_cnt))) {
        SX_LOG_ERR("Failed to destroy ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    const sai_object_key_t key = { .object_id = next_hop_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    return sai_set_attribute(&key, key_str, next_hop_group_attribs, next_hop_group_vendor_attribs, attr);
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
    const sai_object_key_t key = { .object_id = next_hop_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              next_hop_group_attribs,
                              next_hop_group_vendor_attribs,
                              attr_count,
                              attr_list);
}

/* Next hop group type [sai_next_hop_group_type_t] */
static sai_status_t mlnx_next_hop_group_type_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_NEXT_HOP_GROUP_ECMP;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Number of next hops in the group [uint32_t] */
static sai_status_t mlnx_next_hop_group_count_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t status;
    uint32_t     sdk_next_hop_cnt;
    sx_ecmp_id_t sdk_ecmp_id;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    sdk_next_hop_cnt = 0;
    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, NULL, &sdk_next_hop_cnt))) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    value->u32 = sdk_next_hop_cnt;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Next hop list [sai_object_list_t] */
static sai_status_t mlnx_next_hop_group_hop_list_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t status;
    uint32_t     group_id;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &group_id, NULL))) {
        return status;
    }

    /* TODO : implement next hop to ECMP container lookup */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* Next hop list [sai_object_list_t] */
static sai_status_t mlnx_next_hop_group_hop_list_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t  status;
    sx_next_hop_t next_hops[ECMP_MAX_PATHS];
    sx_ecmp_id_t  sdk_ecmp_id;
    uint32_t      next_hop_cnt;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    next_hop_cnt = value->objlist.count;
    if (next_hop_cnt > ECMP_MAX_PATHS) {
        SX_LOG_ERR("Next hop count %u bigger than maximum %u\n", next_hop_cnt, ECMP_MAX_PATHS);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }
    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_next_hop_objects(next_hop_cnt, value->objlist.list,
                                                                            next_hops))) {
        return status;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &sdk_ecmp_id, next_hops,
                                                              &next_hop_cnt))) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Add next hop to a group
 *
 * Arguments:
 *    [in] next_hop_group_id - next hop group id
 *    [in] next_hop_count - number of next hops
 *    [in] nexthops - array of next hops
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_add_next_hop_to_group(_In_ sai_object_id_t        next_hop_group_id,
                                               _In_ uint32_t               next_hop_count,
                                               _In_ const sai_object_id_t* nexthops)
{
    sai_status_t  status;
    char          value[MAX_LIST_VALUE_STR_LEN];
    char          key_str[MAX_KEY_STR_LEN];
    sx_next_hop_t next_hops[ECMP_MAX_PATHS];
    sx_ecmp_id_t  sdk_ecmp_id;
    uint32_t      existing_next_hop_cnt = ECMP_MAX_PATHS;

    SX_LOG_ENTER();

    if (NULL == nexthops) {
        SX_LOG_ERR("NULL nexthops param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    sai_nexthops_to_str(next_hop_count, nexthops, MAX_LIST_VALUE_STR_LEN, value);
    SX_LOG_NTC("Add next hops {%s} to %s\n", value, key_str);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(next_hop_group_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, next_hops, &existing_next_hop_cnt))) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (existing_next_hop_cnt + next_hop_count > ECMP_MAX_PATHS) {
        SX_LOG_ERR("Next hop count existing %u + added %u bigger than maximum %u\n",
                   existing_next_hop_cnt, next_hop_count, ECMP_MAX_PATHS);
        status = SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_next_hop_objects(next_hop_count, nexthops,
                                                                            &next_hops[existing_next_hop_cnt]))) {
        return status;
    }

    existing_next_hop_cnt += next_hop_count;
    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &sdk_ecmp_id, next_hops,
                                                              &existing_next_hop_cnt))) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove next hop from a group
 *
 * Arguments:
 *    [in] next_hop_group_id - next hop group id
 *    [in] next_hop_count - number of next hops
 *    [in] nexthops - array of next hops
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_next_hop_from_group(_In_ sai_object_id_t        next_hop_group_id,
                                                    _In_ uint32_t               next_hop_count,
                                                    _In_ const sai_object_id_t* nexthops)
{
    sai_status_t  status;
    char          value[MAX_LIST_VALUE_STR_LEN];
    char          key_str[MAX_KEY_STR_LEN];
    sx_next_hop_t next_hops[ECMP_MAX_PATHS], next_hops_to_remove[ECMP_MAX_PATHS];
    sx_ecmp_id_t  sdk_ecmp_id;
    uint32_t      existing_next_hop_cnt = ECMP_MAX_PATHS;
    uint32_t      ii, jj;

    SX_LOG_ENTER();

    if (NULL == nexthops) {
        SX_LOG_ERR("NULL nexthops param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    next_hop_group_key_to_str(next_hop_group_id, key_str);
    sai_nexthops_to_str(next_hop_count, nexthops, MAX_LIST_VALUE_STR_LEN, value);
    SX_LOG_NTC("Remove next hops {%s} from %s\n", value, key_str);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(next_hop_group_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, next_hops, &existing_next_hop_cnt))) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (next_hop_count > ECMP_MAX_PATHS) {
        SX_LOG_ERR("Next hop count %u bigger than maximum %u\n", next_hop_count, ECMP_MAX_PATHS);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS != (status = mlnx_translate_sai_next_hop_objects(next_hop_count, nexthops,
                                                                            next_hops_to_remove))) {
        return status;
    }

    for (ii = 0; ii < next_hop_count; ii++) {
        jj = 0;
        while (jj < existing_next_hop_cnt) {
            if (!memcmp(&next_hops[jj].next_hop_key, &next_hops_to_remove[ii].next_hop_key,
                        sizeof(next_hops[jj].next_hop_key))) {
                existing_next_hop_cnt--;
                next_hops[jj] = next_hops[existing_next_hop_cnt];
                continue;
            }
            jj++;
        }
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &sdk_ecmp_id, next_hops,
                                                              &existing_next_hop_cnt))) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nexthop_group_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_next_hop_group_api_t mlnx_next_hop_group_api = {
    mlnx_create_next_hop_group,
    mlnx_remove_next_hop_group,
    mlnx_set_next_hop_group_attribute,
    mlnx_get_next_hop_group_attribute,
    mlnx_add_next_hop_to_group,
    mlnx_remove_next_hop_from_group
};
