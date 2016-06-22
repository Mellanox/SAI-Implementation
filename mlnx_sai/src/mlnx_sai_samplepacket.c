/*
 *  Copyright (C) 2016. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
#define __MODULE__ SAI_SAMPLEPACKET

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

/* mandatory_on_create, valid_for_create, valid_for_set, valid_for_get */
static const sai_attribute_entry_t samplepacket_attribs[] = {
    { SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE, true, true, true, true,
      "Samplepacket attr sample rate", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SAMPLEPACKET_ATTR_TYPE, false, true, false, true,
      "Samplepacket attr type", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_samplepacket_sample_rate_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg);
static sai_status_t mlnx_samplepacket_type_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_samplepacket_sample_rate_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg);

/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t samplepacket_vendor_attribs[] = {
    { SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_samplepacket_sample_rate_get, NULL,
      mlnx_samplepacket_sample_rate_set, NULL },
    { SAI_SAMPLEPACKET_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_samplepacket_type_get, NULL,
      NULL, NULL },
};
static void samplepacket_key_to_str(_In_ const sai_object_id_t sai_samplepacket_obj_id, _Out_ char *key_str)
{
    uint32_t internal_samplepacket_obj_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_samplepacket_obj_id, SAI_OBJECT_TYPE_SAMPLEPACKET, &internal_samplepacket_obj_idx,
                            NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid sai samplepacket obj ID %" PRId64 "", sai_samplepacket_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "samplepacket obj idx %d",
                 internal_samplepacket_obj_idx);
    }

    SX_LOG_EXIT();
}

static sai_status_t mlnx_samplepacket_sample_rate_validate(_In_ const uint32_t internal_samplepacket_obj_idx)
{
    uint32_t               index             = 0;
    uint32_t               value_sample_rate = 0;
    sx_port_sflow_params_t sdk_sflow_params;
    sai_status_t           status = SAI_STATUS_FAILURE;

    assert(NULL != g_sai_db_ptr);

    /* caller of this function should use read lock to guard the callsite */

    value_sample_rate = g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].sai_sample_rate;

    for (index = 0; index < MAX_PORTS; index++) {
        if (internal_samplepacket_obj_idx == g_sai_db_ptr->ports_db[index].internal_ingress_samplepacket_obj_idx) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     (sdk_to_sai(sx_api_port_sflow_get(gh_sdk, g_sai_db_ptr->ports_db[index].logical,
                                                       &sdk_sflow_params))))) {
                SX_LOG_ERR("Error getting sflow params for sdk port id %d with internal samplepacket obj id %d\n",
                           g_sai_db_ptr->ports_db[index].logical,
                           internal_samplepacket_obj_idx);
                goto cleanup;
            }

            if (sdk_sflow_params.ratio != value_sample_rate) {
                SX_LOG_ERR("Error: sdk sflow params ratio %d does not equal to internal sai sample rate %d\n",
                           sdk_sflow_params.ratio,
                           value_sample_rate);
                status = SAI_STATUS_FAILURE;
                goto cleanup;
            }

            if (0 != sdk_sflow_params.deviation) {
                SX_LOG_ERR("Error: sdk sflow params deviation %d does not equal to %d\n", sdk_sflow_params.deviation,
                           0);
                status = SAI_STATUS_FAILURE;
                goto cleanup;
            }

            if (true != sdk_sflow_params.packet_types.uc) {
                SX_LOG_ERR("Error: sdk sflow params packet type uc %d does not equal to %d\n",
                           sdk_sflow_params.packet_types.uc,
                           true);
            }

            if (true != sdk_sflow_params.packet_types.mc) {
                SX_LOG_ERR("Error: sdk sflow params packet type mc %d does not equal to %d\n",
                           sdk_sflow_params.packet_types.mc,
                           true);
            }

            if (true != sdk_sflow_params.packet_types.bc) {
                SX_LOG_ERR("Error: sdk sflow params packet type bc %d does not equal to %d\n",
                           sdk_sflow_params.packet_types.bc,
                           true);
            }

            if (true != sdk_sflow_params.packet_types.uuc) {
                SX_LOG_ERR("Error: sdk sflow params packet type uuc %d does not equal to %d\n",
                           sdk_sflow_params.packet_types.uuc,
                           true);
            }

            if (true != sdk_sflow_params.packet_types.umc) {
                SX_LOG_ERR("Error: sdk sflow params packet type umc %d does not equal to %d\n",
                           sdk_sflow_params.packet_types.umc,
                           true);
            }

            SX_LOG_DBG("Verified sflow params for sdk port id %d\n", g_sai_db_ptr->ports_db[index].logical);
        }
    }
    status = SAI_STATUS_SUCCESS;

cleanup:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_samplepacket_sample_rate_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg)
{
    sai_status_t status                        = SAI_STATUS_FAILURE;
    uint32_t     internal_samplepacket_obj_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_SAMPLEPACKET, &internal_samplepacket_obj_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai samplepacket obj id: %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    if (g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].in_use) {
        value->u32 = g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].sai_sample_rate;
    } else {
        SX_LOG_ERR("Non-exist internal samplepacket obj idx: %d\n", internal_samplepacket_obj_idx);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto cleanup;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_samplepacket_sample_rate_validate(internal_samplepacket_obj_idx))) {
        SX_LOG_ERR("Error validating sample rate for internal samplepacket obj idx: %d\n",
                   internal_samplepacket_obj_idx);
        status = SAI_STATUS_FAILURE;
        goto cleanup;
    }

    status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_samplepacket_type_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t status                        = SAI_STATUS_FAILURE;
    uint32_t     internal_samplepacket_obj_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_SAMPLEPACKET, &internal_samplepacket_obj_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai samplepacket obj id: %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    if (g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].in_use) {
        value->s32 = g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].sai_type;
    } else {
        SX_LOG_ERR("Non-exist internal samplepacket obj idx: %d\n", internal_samplepacket_obj_idx);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto cleanup;
    }

    status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_samplepacket_sample_rate_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg)
{
    sai_status_t           status                        = SAI_STATUS_FAILURE;
    uint32_t               internal_samplepacket_obj_idx = 0;
    uint32_t               index                         = 0;
    sx_port_sflow_params_t sdk_sflow_params;

    memset(&sdk_sflow_params, 0, sizeof(sx_port_sflow_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_SAMPLEPACKET, &internal_samplepacket_obj_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai samplepacket obj id: %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    assert(NULL != g_sai_db_ptr);

    sai_db_write_lock();

    if (g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].in_use) {
        g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].sai_sample_rate = value->u32;
    } else {
        SX_LOG_ERR("Non-exist internal samplepacket obj idx: %d\n", internal_samplepacket_obj_idx);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto cleanup;
    }

    for (index = 0; index < MAX_PORTS; index++) {
        if (internal_samplepacket_obj_idx == g_sai_db_ptr->ports_db[index].internal_ingress_samplepacket_obj_idx) {
            sdk_sflow_params.ratio            = value->u32;
            sdk_sflow_params.deviation        = 0;
            sdk_sflow_params.packet_types.uc  = true;
            sdk_sflow_params.packet_types.mc  = true;
            sdk_sflow_params.packet_types.bc  = true;
            sdk_sflow_params.packet_types.uuc = true;
            sdk_sflow_params.packet_types.umc = true;

            if (SAI_STATUS_SUCCESS !=
                (status =
                     (sdk_to_sai(sx_api_port_sflow_set(gh_sdk, SX_ACCESS_CMD_EDIT,
                                                       g_sai_db_ptr->ports_db[index].logical,
                                                       &sdk_sflow_params))))) {
                SX_LOG_ERR("Error updating sflow params for sdk port id %d with internal samplepacket obj idx %d\n",
                           g_sai_db_ptr->ports_db[index].logical,
                           internal_samplepacket_obj_idx);
                goto cleanup;
            }

            SX_LOG_NTC("Updated sflow params for sdk port id %d with internal samplepacket obj idx %d\n",
                       g_sai_db_ptr->ports_db[index].logical,
                       internal_samplepacket_obj_idx);
        }
    }

    status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_create_empty_samplepacket_session(_Out_ uint32_t *internal_samplepacket_obj_idx)
{
    uint32_t     index  = 0;
    sai_status_t status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    assert(NULL != g_sai_db_ptr);

    /* caller of this function should use read lock to guard the callsite */

    for (index = MLNX_SAMPLEPACKET_SESSION_MIN; index < MLNX_SAMPLEPACKET_SESSION_MAX; index++) {
        if (!g_sai_db_ptr->mlnx_samplepacket_session[index].in_use) {
            *internal_samplepacket_obj_idx = index;
            status                         = SAI_STATUS_SUCCESS;
            goto cleanup;
        }
    }

    SX_LOG_NTC(
        "Not enough resources for sai samplepacket session, at most %d sai samplepacket sessions can be created\n",
        MLNX_SAMPLEPACKET_SESSION_MAX - MLNX_SAMPLEPACKET_SESSION_MIN);
    status = SAI_STATUS_INSUFFICIENT_RESOURCES;

cleanup:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_create_samplepacket_session(_Out_ sai_object_id_t      *sai_samplepacket_obj_id,
                                                     _In_ uint32_t               attr_count,
                                                     _In_ const sai_attribute_t *attr_list)
{
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    const sai_attribute_value_t *samplepacket_sample_rate      = NULL, *samplepacket_type = NULL;
    sai_status_t                 status                        = SAI_STATUS_FAILURE, status_type = SAI_STATUS_FAILURE;
    uint32_t                     index                         = 0;
    uint32_t                     internal_samplepacket_obj_idx = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = check_attribs_metadata(attr_count, attr_list, samplepacket_attribs, samplepacket_vendor_attribs,
                                         SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Samplepacket: metadata check failed\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, samplepacket_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("SAI Samplepacket attributes: %s\n", list_str);

    if (SAI_STATUS_SUCCESS !=
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE, &samplepacket_sample_rate,
                                 &index))) {
        SX_LOG_ERR("Samplepacket rate is missing on create\n");
        SX_LOG_EXIT();
        return status;
    }

    status_type = find_attrib_in_list(attr_count, attr_list, SAI_SAMPLEPACKET_ATTR_TYPE, &samplepacket_type, &index);

    if (SAI_STATUS_SUCCESS == status_type) {
        if (SAI_SAMPLEPACKET_SLOW_PATH != samplepacket_type->s32) {
            SX_LOG_ERR("Samplepacket type should be SAI_SAMPLEPACKET_SLOW_PATH but get %d instead\n",
                       samplepacket_type->s32);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + samplepacket_type->s32;
        }
    }

    assert(NULL != g_sai_db_ptr);

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_empty_samplepacket_session(&internal_samplepacket_obj_idx))) {
        SX_LOG_ERR("Failed to create empty samplepacket session\n");
        goto cleanup;
    }

    SX_LOG_DBG("Created internal samplepacket obj idx: %d\n", internal_samplepacket_obj_idx);

    memset(&g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx], 0, sizeof(mlnx_samplepacket_t));

    g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].in_use = true;

    g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].sai_sample_rate =
        samplepacket_sample_rate->u32;

    if (SAI_STATUS_SUCCESS == status_type) {
        g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].sai_type = samplepacket_type->s32;
    } else {
        g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].sai_type = SAI_SAMPLEPACKET_SLOW_PATH;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_create_object(SAI_OBJECT_TYPE_SAMPLEPACKET, internal_samplepacket_obj_idx, NULL,
                                sai_samplepacket_obj_id))) {
        memset(&g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx], 0,
               sizeof(mlnx_samplepacket_t));
        SX_LOG_ERR("Error creating sai samplepacket obj id from internal samplepacket obj id %d\n",
                   internal_samplepacket_obj_idx);
        goto cleanup;
    }

    SX_LOG_NTC("Created SAI samplepacket obj id: %" PRId64 "\n", *sai_samplepacket_obj_id);

    status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_remove_samplepacket_session(_In_ const sai_object_id_t sai_samplepacket_obj_id)
{
    sai_status_t status                        = SAI_STATUS_FAILURE;
    uint32_t     internal_samplepacket_obj_idx = 0;
    uint32_t     index                         = 0;
    bool         port_associated               = false;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(sai_samplepacket_obj_id, SAI_OBJECT_TYPE_SAMPLEPACKET, &internal_samplepacket_obj_idx,
                                 NULL))) {
        SX_LOG_ERR("Invalid sai samplepacket obj id: %" PRId64 "\n", sai_samplepacket_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    assert(NULL != g_sai_db_ptr);

    sai_db_write_lock();

    for (index = 0; index < MAX_PORTS; index++) {
        if (internal_samplepacket_obj_idx == g_sai_db_ptr->ports_db[index].internal_ingress_samplepacket_obj_idx) {
            SX_LOG_ERR(
                "Please disassociate sdk port id %d with internal samplepacket obj id %d before removing samplepacket obj idx\n",
                g_sai_db_ptr->ports_db[index].logical,
                internal_samplepacket_obj_idx);
            port_associated = true;
        }
    }

    if (port_associated) {
        SX_LOG_ERR("Please disassociate ports before removing sai samplepacket obj id: %" PRId64 "\n",
                   sai_samplepacket_obj_id);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto cleanup;
    }

    if (g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx].in_use) {
        memset(&g_sai_db_ptr->mlnx_samplepacket_session[internal_samplepacket_obj_idx], 0,
               sizeof(mlnx_samplepacket_t));
    } else {
        SX_LOG_ERR("Invalid sai samplepacket obj id: %" PRId64 "\n", sai_samplepacket_obj_id);
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto cleanup;
    }

    SX_LOG_NTC("Removed SAI samplepacket obj id %" PRId64 "\n", sai_samplepacket_obj_id);

    status = SAI_STATUS_SUCCESS;

cleanup:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_set_samplepacket_attribute(_In_ const sai_object_id_t  sai_samplepacket_obj_id,
                                                    _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = sai_samplepacket_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    samplepacket_key_to_str(sai_samplepacket_obj_id, key_str);

    status = sai_set_attribute(&key, key_str, samplepacket_attribs, samplepacket_vendor_attribs, attr);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_get_samplepacket_attribute(_In_ const sai_object_id_t sai_samplepacket_obj_id,
                                                    _In_ uint32_t              attr_count,
                                                    _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .object_id = sai_samplepacket_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    samplepacket_key_to_str(sai_samplepacket_obj_id, key_str);

    status =
        sai_get_attributes(&key, key_str, samplepacket_attribs, samplepacket_vendor_attribs, attr_count, attr_list);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_samplepacket_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_samplepacket_api_t mlnx_samplepacket_api = {
    mlnx_create_samplepacket_session,
    mlnx_remove_samplepacket_session,
    mlnx_set_samplepacket_attribute,
    mlnx_get_samplepacket_attribute
};
