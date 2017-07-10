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

#undef  __MODULE__
#define __MODULE__ SAI_NEXT_HOP_GROUP

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
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
    { SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static sai_status_t mlnx_next_hop_group_member_group_id_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg);
static sai_status_t mlnx_next_hop_group_member_hop_id_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg);
static sai_status_t mlnx_next_hop_group_member_hop_weight_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg);
static sai_status_t mlnx_next_hop_group_member_hop_weight_set(_In_ const sai_object_key_t      *key,
                                                              _In_ const sai_attribute_value_t *value,
                                                              void                             *arg);
static const sai_vendor_attribute_entry_t next_hop_group_member_vendor_attribs[] = {
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_group_member_group_id_get, NULL,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_group_member_hop_id_get, NULL,
      NULL, NULL },
    { SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_next_hop_group_member_hop_weight_get, NULL,
      mlnx_next_hop_group_member_hop_weight_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
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

static int sx_nhop_equal(sx_next_hop_t *nhop1, sx_next_hop_t *nhop2)
{
    return !memcmp(&nhop1->next_hop_key, &nhop2->next_hop_key, sizeof(nhop2->next_hop_key));
}

static sai_status_t mlnx_sdk_nhop_find_in_list(sx_next_hop_t *next_hops,
                                               uint32_t       count,
                                               sx_next_hop_t *match,
                                               uint32_t      *index)
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
                                               _In_ sai_object_id_t        switch_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list)
{
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_next_hop_t                next_hops[1];
    uint32_t                     next_hop_cnt = 0;
    sx_ecmp_id_t                 sdk_ecmp_id;
    uint32_t                     type_index;
    sai_status_t                 status;
    const sai_attribute_value_t *type;

    SX_LOG_ENTER();

    if (NULL == next_hop_group_id) {
        SX_LOG_ERR("NULL next hop group id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                                    next_hop_group_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create next hop group, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_GROUP_ATTR_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_NEXT_HOP_GROUP_TYPE_ECMP != type->s32) {
        SX_LOG_ERR("Invalid next hop group type %d on create\n", type->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_CREATE, &sdk_ecmp_id, next_hops, &next_hop_cnt);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to create ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP, sdk_ecmp_id, NULL, next_hop_group_id);
    if (SAI_ERR(status)) {
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

/* Number of next hops in the group [uint32_t] */
static sai_status_t mlnx_next_hop_group_count_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    uint32_t     sdk_next_hop_cnt;
    sx_ecmp_id_t sdk_ecmp_id;
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &sdk_ecmp_id, NULL))) {
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

/* Next hop group type [sai_next_hop_group_type_t] */
static sai_status_t mlnx_next_hop_group_type_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_NEXT_HOP_GROUP_TYPE_ECMP;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nexthop_group_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t nhop_group_member_to_oid(sx_ecmp_id_t group_id, sx_ecmp_id_t nhop_id, sai_object_id_t *member_id)
{
    mlnx_object_id_t member_obj_id;
    sai_status_t     status;

    member_obj_id.id.nhop_group_member_low.group_id   = group_id & 0xffff;
    member_obj_id.ext.nhop_group_member_high.group_id = group_id >> 24;

    member_obj_id.id.nhop_group_member_low.nhop_id   = nhop_id & 0xffff;
    member_obj_id.ext.nhop_group_member_high.nhop_id = nhop_id >> 24;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, &member_obj_id, member_id);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t nhop_group_member_parse_oid(sai_object_id_t member_id,
                                                sx_ecmp_id_t   *sx_group_id,
                                                sx_ecmp_id_t   *sx_nhop_id)
{
    mlnx_object_id_t member_obj_id;
    uint32_t         group_id;
    uint32_t         nhop_id;
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, member_id, &member_obj_id);
    if (SAI_ERR(status)) {
        return status;
    }

    group_id     = member_obj_id.id.nhop_group_member_low.group_id;
    group_id    |= member_obj_id.ext.nhop_group_member_high.group_id << 24;
    *sx_group_id = group_id;

    nhop_id     = member_obj_id.id.nhop_group_member_low.nhop_id;
    nhop_id    |= member_obj_id.ext.nhop_group_member_high.nhop_id << 24;
    *sx_nhop_id = nhop_id;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_next_hop_group_member_group_id_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg)
{
    sx_ecmp_id_t sx_group_id;
    sx_ecmp_id_t sx_nhop_id;
    sai_status_t status;

    SX_LOG_ENTER();

    status = nhop_group_member_parse_oid(key->key.object_id, &sx_group_id, &sx_nhop_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP_GROUP, sx_group_id, NULL, &value->oid);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_next_hop_group_member_hop_id_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg)
{
    sx_ecmp_id_t sx_group_id;
    sx_ecmp_id_t sx_nhop_id;
    sai_status_t status;

    SX_LOG_ENTER();

    status = nhop_group_member_parse_oid(key->key.object_id, &sx_group_id, &sx_nhop_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP, sx_nhop_id, NULL, &value->oid);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_next_hop_group_member_hop_weight_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg)
{
    uint32_t      next_hop_count = ECMP_MAX_PATHS;
    sx_next_hop_t ecmp_next_hops[ECMP_MAX_PATHS];
    sx_ecmp_id_t  sx_group_id;
    sx_ecmp_id_t  sx_nhop_id;
    sx_next_hop_t next_hop;
    sai_status_t  status;
    uint32_t      ii;

    SX_LOG_ENTER();

    status = nhop_group_member_parse_oid(key->key.object_id, &sx_group_id, &sx_nhop_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = sx_api_router_ecmp_get(gh_sdk, sx_group_id, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    status = mlnx_sdk_nhop_by_ecmp_id_get(sx_nhop_id, &next_hop);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_sdk_nhop_find_in_list(ecmp_next_hops, next_hop_count, &next_hop, &ii);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->u32 = ecmp_next_hops[ii].next_hop_data.weight;

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_next_hop_group_member_hop_weight_set(_In_ const sai_object_key_t      *key,
                                                              _In_ const sai_attribute_value_t *value,
                                                              void                             *arg)
{
    uint32_t      next_hop_count = ECMP_MAX_PATHS;
    sx_next_hop_t ecmp_next_hops[ECMP_MAX_PATHS];
    sx_ecmp_id_t  sx_group_id;
    sx_ecmp_id_t  sx_nhop_id;
    sx_next_hop_t next_hop;
    sai_status_t  status;
    uint32_t      ii;

    SX_LOG_ENTER();

    status = nhop_group_member_parse_oid(key->key.object_id, &sx_group_id, &sx_nhop_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = sx_api_router_ecmp_get(gh_sdk, sx_group_id, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    status = mlnx_sdk_nhop_by_ecmp_id_get(sx_nhop_id, &next_hop);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_sdk_nhop_find_in_list(ecmp_next_hops, next_hop_count, &next_hop, &ii);
    if (SAI_ERR(status)) {
        goto out;
    }

    ecmp_next_hops[ii].next_hop_data.weight = value->u32;

    status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &sx_group_id, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

out:
    SX_LOG_EXIT();
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
    const sai_attribute_value_t *group = NULL, *next_hop = NULL, *weight = NULL;
    uint32_t                     group_index, next_hop_index, weight_index;
    uint32_t                     next_hop_count = ECMP_MAX_PATHS;
    sx_next_hop_t                ecmp_next_hops[ECMP_MAX_PATHS];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         value_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_ecmp_id_t                 group_ecmp_id;
    sx_ecmp_id_t                 nhop_ecmp_id;
    sai_status_t                 status;

    SX_LOG_ENTER();

    if (NULL == next_hop_group_member_id) {
        SX_LOG_ERR("NULL next hop group member id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count,
                                    attr_list,
                                    SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                                    next_hop_group_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create next hop group member, %s\n", list_str);

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID,
                                 &group,
                                 &group_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID,
                                 &next_hop,
                                 &next_hop_index);
    assert(SAI_STATUS_SUCCESS == status);

    find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, &weight, &weight_index);

    status = mlnx_object_to_type(group->oid, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, &group_ecmp_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_object_to_type(next_hop->oid, SAI_OBJECT_TYPE_NEXT_HOP, &nhop_ecmp_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    next_hop_group_key_to_str(group->oid, key_str);
    sai_nexthops_to_str(1, &next_hop->oid, MAX_LIST_VALUE_STR_LEN, value_str);
    SX_LOG_NTC("Add next hop %s to %s\n", value_str, key_str);

    status = sx_api_router_ecmp_get(gh_sdk, group_ecmp_id, ecmp_next_hops, &next_hop_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (next_hop_count + 1 > ECMP_MAX_PATHS) {
        SX_LOG_ERR("Next hop count existing %u + added %u bigger than maximum %u\n",
                   next_hop_count, next_hop_count + 1, ECMP_MAX_PATHS);

        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_translate_sai_next_hop_objects(1, &next_hop->oid, &ecmp_next_hops[next_hop_count]);
    if (SAI_ERR(status)) {
        return status;
    }
    if (weight) {
        ecmp_next_hops[next_hop_count].next_hop_data.weight = weight->u32;
    } else {
        ecmp_next_hops[next_hop_count].next_hop_data.weight = 1;
    }

    next_hop_count++;

    status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &group_ecmp_id, ecmp_next_hops, &next_hop_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    status = nhop_group_member_to_oid(group_ecmp_id, nhop_ecmp_id, next_hop_group_member_id);

    SX_LOG_EXIT();
    return status;
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
    sx_next_hop_t next_hops[ECMP_MAX_PATHS];
    sx_next_hop_t next_hop_remove;
    uint32_t      next_hop_count = ECMP_MAX_PATHS;
    sx_ecmp_id_t  sx_group_id;
    sx_ecmp_id_t  sx_nhop_id;
    sai_status_t  status;
    uint32_t      ii;

    SX_LOG_ENTER();

    status = nhop_group_member_parse_oid(next_hop_group_member_id, &sx_group_id, &sx_nhop_id);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_NTC("Remove next hop %u from next hop group %u\n", sx_nhop_id, sx_group_id);

    status = sx_api_router_ecmp_get(gh_sdk, sx_group_id, next_hops, &next_hop_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    status = mlnx_sdk_nhop_by_ecmp_id_get(sx_nhop_id, &next_hop_remove);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_sdk_nhop_find_in_list(next_hops, next_hop_count, &next_hop_remove, &ii);
    if (SAI_ERR(status)) {
        return status;
    }
    next_hops[ii] = next_hops[--next_hop_count];

    status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_SET, &sx_group_id, next_hops, &next_hop_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Bulk next hop group members creation.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_count Number of objects to create
 * @param[in] attr_count List of attr_count. Caller passes the number
 *         of attribute for each object to create.
 * @param[in] attrs List of attributes for every object.
 * @param[in] type bulk operation type.
 *
 * @param[out] object_id List of object ids returned
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are created or #SAI_STATUS_FAILURE when
 * any of the objects fails to create. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
sai_status_t mlnx_create_next_hop_group_members(_In_ sai_object_id_t         switch_id,
                                                _In_ uint32_t                object_count,
                                                _In_ const uint32_t         *attr_count,
                                                _In_ const sai_attribute_t **attrs,
                                                _In_ sai_bulk_op_type_t      type,
                                                _Out_ sai_object_id_t       *object_id,
                                                _Out_ sai_status_t          *object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Bulk next hop group members removal.
 *
 * @param[in] object_count Number of objects to create
 * @param[in] object_id List of object ids
 * @param[in] type bulk operation type.
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or #SAI_STATUS_FAILURE when
 * any of the objects fails to remove. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
sai_status_t mlnx_remove_next_hop_group_members(_In_ uint32_t               object_count,
                                                _In_ const sai_object_id_t *object_id,
                                                _In_ sai_bulk_op_type_t     type,
                                                _Out_ sai_status_t         *object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static void next_hop_group_member_key_to_str(_In_ sai_object_id_t group_member_id, _Out_ char *key_str)
{
    sx_ecmp_id_t sx_group_id;
    sx_ecmp_id_t sx_nhop_id;
    sai_status_t status;

    status = nhop_group_member_parse_oid(group_member_id, &sx_group_id, &sx_nhop_id);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid next hop group id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "next hop group member id %u:%u", sx_group_id, sx_nhop_id);
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
};
