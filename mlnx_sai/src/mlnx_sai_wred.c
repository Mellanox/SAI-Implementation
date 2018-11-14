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
#include <complib/cl_math.h>

#undef  __MODULE__
#define __MODULE__ SAI_WRED

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

/* SAI support range 0 - 15 for weight, but according to sdk limitation we support only 0 - 11 */
#define MAX_WEIGHT_VAL           11
#define DEFAULT_WRED_PROBABILITY 100
#define DEFAULT_WEIGHT_VAL       0

static uint32_t sai_sx_weight_map[] = {1000, 500, 250, 125, 62, 31, 15, 8, 4, 2, 1, 0, 0, 0, 0, 0};

typedef enum _flow_color_type_t {
    FLOW_COLOR_GREEN = 0,
    FLOW_COLOR_YELLOW,
    FLOW_COLOR_RED
} flow_color_type_t;

static sai_status_t mlnx_wred_attr_getter(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_wred_attr_setter(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
static sai_status_t mlnx_wred_attr_enable_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_wred_weight_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_wred_weight_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
static sai_status_t mlnx_wred_ecn_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_wred_ecn_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static sai_status_t mlnx_wred_ecn_enable_set(sx_port_log_id_t        port,
                                             sx_cos_traffic_class_t *tc_list,
                                             uint32_t                tc_count,
                                             bool                    red_enable,
                                             bool                    ecn_enable);
static const sai_vendor_attribute_entry_t wred_vendor_attribs[] = {
    { SAI_WRED_ATTR_GREEN_ENABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_GREEN_ENABLE,
      mlnx_wred_attr_enable_set, (void*)SAI_WRED_ATTR_GREEN_ENABLE },
    { SAI_WRED_ATTR_GREEN_MIN_THRESHOLD,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_GREEN_MIN_THRESHOLD,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_GREEN_MIN_THRESHOLD },
    { SAI_WRED_ATTR_GREEN_MAX_THRESHOLD,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_GREEN_MAX_THRESHOLD,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_GREEN_MAX_THRESHOLD },
    { SAI_WRED_ATTR_GREEN_DROP_PROBABILITY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_GREEN_DROP_PROBABILITY,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_GREEN_DROP_PROBABILITY },
    { SAI_WRED_ATTR_YELLOW_ENABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_YELLOW_ENABLE,
      mlnx_wred_attr_enable_set, (void*)SAI_WRED_ATTR_YELLOW_ENABLE },
    { SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD },
    { SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD },
    { SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY },
    { SAI_WRED_ATTR_RED_ENABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_RED_ENABLE,
      mlnx_wred_attr_enable_set, (void*)SAI_WRED_ATTR_RED_ENABLE },
    { SAI_WRED_ATTR_RED_MIN_THRESHOLD,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_RED_MIN_THRESHOLD,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_RED_MIN_THRESHOLD },
    { SAI_WRED_ATTR_RED_MAX_THRESHOLD,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_RED_MAX_THRESHOLD,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_RED_MAX_THRESHOLD },
    { SAI_WRED_ATTR_RED_DROP_PROBABILITY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_attr_getter, (void*)SAI_WRED_ATTR_RED_DROP_PROBABILITY,
      mlnx_wred_attr_setter, (void*)SAI_WRED_ATTR_RED_DROP_PROBABILITY },
    { SAI_WRED_ATTR_WEIGHT,
      {true, false, true, true},
      {true, false, true, true},
      mlnx_wred_weight_get, NULL,
      mlnx_wred_weight_set, NULL},
    { SAI_WRED_ATTR_ECN_MARK_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_wred_ecn_get, NULL,
      mlnx_wred_ecn_set, NULL},
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t wred_enum_info[] = {
    [SAI_WRED_ATTR_ECN_MARK_MODE] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t mlnx_wred_obj_type_info =
    { wred_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(wred_enum_info)};

/*
 * Routine Description:
 *   Add new SAI WRED profile to DB, create new wred object
 *
 * Arguments:
 *    [out] wred_id - obj id of WRED profile
 *    [in] new_wred - wred profile to add to DB
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS if found
 *    SAI_STATUS_FAILURE if DB is full or can't create wred object
 */
static sai_status_t mlnx_wred_db_create(sai_object_id_t *wred_id, mlnx_wred_profile_t  *new_wred)
{
    uint32_t     ii     = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    for (; ii < g_resource_limits.cos_redecn_profiles_max; ii++) {
        if (!g_sai_qos_db_ptr->wred_db[ii].in_use) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_create_object(SAI_OBJECT_TYPE_WRED, ii, NULL, wred_id))) {
                break;
            }
            memcpy(&g_sai_qos_db_ptr->wred_db[ii], new_wred, sizeof(mlnx_wred_profile_t));
            g_sai_qos_db_ptr->wred_db[ii].in_use = true;
            sai_qos_db_sync();
            break;
        }
    }

    if (g_resource_limits.cos_redecn_profiles_max == ii) {
        return SAI_STATUS_TABLE_FULL;
    }

    return status;
}

/*
 * Routine Description:
 *   Remove SAI WRED profile with specified wred obj ID.
 *
 * Arguments:
 *    [in] wred_id - object id of WRED profile
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS if found and removed
 *    SAI_STATUS_FAILURE if profile doesn't exist
 */
static sai_status_t mlnx_wred_db_remove(sai_object_id_t wred_id)
{
    uint32_t     wred_num = 0;
    sai_status_t status   = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(wred_id, SAI_OBJECT_TYPE_WRED, &wred_num, NULL)) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if ((wred_num >= g_resource_limits.cos_redecn_profiles_max) ||
        (!g_sai_qos_db_ptr->wred_db[wred_num].in_use)) {
        status = SAI_STATUS_ITEM_NOT_FOUND;
    } else {
        memset(&g_sai_qos_db_ptr->wred_db[wred_num], 0, sizeof(g_sai_qos_db_ptr->wred_db[wred_num]));
        g_sai_qos_db_ptr->wred_db[wred_num].in_use = false;
        sai_qos_db_sync();
    }

    return status;
}

/* Read lock is required */
sai_status_t __mlnx_wred_db_get(sai_object_id_t wred_oid, mlnx_wred_profile_t **wred)
{
    uint32_t     wred_idx = 0;
    sai_status_t status;

    assert(wred != NULL);

    status = mlnx_object_to_type(wred_oid, SAI_OBJECT_TYPE_WRED, &wred_idx, NULL);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if ((wred_idx >= g_resource_limits.cos_redecn_profiles_max) ||
        (!g_sai_qos_db_ptr->wred_db[wred_idx].in_use)) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    *wred = &g_sai_qos_db_ptr->wred_db[wred_idx];
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Get SAI WRED profile by specified wred obj ID.
 *
 * Arguments:
 *    [in] wred_id - id of WRED profile
 *    [out] wred_profile - copy of SAI WRED profile with specified obj ID
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS if found
 *    SAI_STATUS_FAILURE if profile doesn't exist
 *
 * Note : copy the profile from DB to input parameter
 */
static sai_status_t mlnx_wred_db_get(sai_object_id_t wred_id, mlnx_wred_profile_t *wred_profile)
{
    sai_status_t         status = SAI_STATUS_SUCCESS;
    mlnx_wred_profile_t *profile;

    status = __mlnx_wred_db_get(wred_id, &profile);
    if (!SAI_ERR(status)) {
        memcpy(wred_profile, profile, sizeof(mlnx_wred_profile_t));
    }

    return status;
}

/*
 * Update SAI WRED profile by specified wred obj ID.
 *
 * Arguments:
 *    [in] wred_id - id of WRED profile
 *    [in] wred_profile - updated SAI WRED profile with specified obj ID
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS if found
 *    SAI_STATUS_FAILURE if profile doesn't exist
 *
 * Note : copy the profile to DB from input parameter
 */
static sai_status_t mlnx_wred_db_set(sai_object_id_t wred_id, mlnx_wred_profile_t *wred_profile)
{
    uint32_t     wred_num = 0;
    sai_status_t status   = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(wred_id, SAI_OBJECT_TYPE_WRED, &wred_num, NULL)) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if ((wred_num >= g_resource_limits.cos_redecn_profiles_max) ||
        (!g_sai_qos_db_ptr->wred_db[wred_num].in_use)) {
        status = SAI_STATUS_ITEM_NOT_FOUND;
    } else {
        memcpy(&g_sai_qos_db_ptr->wred_db[wred_num], wred_profile, sizeof(mlnx_wred_profile_t));
        g_sai_qos_db_ptr->wred_db[wred_num].in_use = true;
        sai_qos_db_sync();
    }

    return status;
}

/*
 * Routine Description:
 *   Check if WRED DB is full
 *
 * Arguments: none
 *
 * Return Values:
 *    true/false
 */
static bool mlnx_wred_db_isfull()
{
    uint32_t ii = 0;

    for (; ii < g_resource_limits.cos_redecn_profiles_max; ii++) {
        if (!g_sai_qos_db_ptr->wred_db[ii].in_use) {
            break;
        }
    }

    if (g_resource_limits.cos_redecn_profiles_max == ii) {
        return true;
    }

    return false;
}

static void tc_list_to_str(sx_cos_traffic_class_t *tc_list, uint32_t tc_count, char* buf)
{
    uint32_t ii         = 0;
    char     tc_buf[10] = {0};

    for (; ii < tc_count; ii++) {
        sprintf(tc_buf, "%u ", tc_list[ii]);
        strcat(buf, tc_buf);
    }
}

/* Util to convert SAI threshold in bytes to sx threshold in cells
 * Note SDK further rounds up to 64 cells g_resource_limits.cos_redecn_cell_multiplier */
static uint16_t mlnx_wred_sai_threshold_to_sx(uint32_t sai_threshold)
{
    uint16_t new_threshold = ROUNDUP(sai_threshold, g_resource_limits.shared_buff_buffer_unit_size) /
                             g_resource_limits.shared_buff_buffer_unit_size;

    if (ROUNDUP(sai_threshold, g_resource_limits.shared_buff_buffer_unit_size) != sai_threshold) {
        SX_LOG_NTC("Threshold %u not alligned, round to %u multiply\n", sai_threshold,
                   g_resource_limits.shared_buff_buffer_unit_size);
    }

    return new_threshold;
}

/* Util to convert sx threshold in cells to SAI threshold in bytes */
static uint32_t mlnx_wred_sx_threshold_to_sai(uint16_t sx_threshold)
{
    return (uint32_t)sx_threshold * g_resource_limits.shared_buff_buffer_unit_size;
}

/*
 * Get list of TC that have wred_id configured for specified port
 *
 * Arguments:
 *    [in]  port_id - logical port id
 *    [in]  wred_id - wred id
 *    [in/out] tc_list - list to store TC num
 *    [in/out] tc_count - on input it's a size of tc_list, on output - number of elements in tc_list
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 * Notes: wrap the function call with a lock
 */
static sai_status_t mlnx_wred_get_tc_configured_list(mlnx_port_config_t     *port,
                                                     sai_object_id_t         wred_id,
                                                     sx_cos_traffic_class_t *tc_list,
                                                     uint32_t               *tc_count)
{
    uint32_t                 ii    = 0;
    uint32_t                 count = 0;
    mlnx_qos_queue_config_t *queue_cfg;
    sai_status_t             status = SAI_STATUS_SUCCESS;

    if (*tc_count < g_resource_limits.cos_port_ets_traffic_class_max + 1) {
        SX_LOG_ERR("Invalid tc_list size\n");
        return SAI_STATUS_FAILURE;
    }

    /* TODO change max to <= g_resource_limits.cos_port_ets_traffic_class_max when sdk support rm */
    port_queues_foreach(port, queue_cfg, ii) {
        /* TODO: might be removed when resource manager variable will be used */
        if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
            break;
        }

        if (queue_cfg->wred_id == wred_id) {
            tc_list[count++] = ii;
        }
    }
    *tc_count = count;

    return status;
}

/*
 * Bind / unbind profile_id for / from specific port.
 *
 * Arguments:
 *    [in] wred_id - id of WRED profile
 *    [in] profile_id - sx profile id
 *    [in] tc_list   - list of TC to apply WRED on
 *    [in] tc_count  - number of TCs in tc_list
 *    [in] flow_type - specify sx flow type
 *    [in] cmd - SX_ACCESS_CMD_BIND / SX_ACCESS_CMD_UNBIND
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
static sai_status_t mlnx_wred_bind_sxwred_to_port(sx_port_log_id_t          port,
                                                  sx_cos_redecn_profile_t   profile_id,
                                                  sx_cos_traffic_class_t  * tc_list,
                                                  uint32_t                  tc_count,
                                                  sx_cos_redecn_flow_type_e flow_type,
                                                  sx_access_cmd_t           cmd)
{
    sx_cos_redecn_bind_params_t bind_param;
    char                        buf[MAX_VALUE_STR_LEN] = {0};
    sx_status_t                 sx_status              = SX_STATUS_SUCCESS;

    memset(&bind_param, 0, sizeof(bind_param));
    bind_param.tc_profile = profile_id;

    sx_status = sx_api_cos_redecn_profile_tc_bind_set(gh_sdk, port, cmd,
                                                      tc_list, tc_count,
                                                      flow_type, &bind_param);
    tc_list_to_str(tc_list, tc_count, buf);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to %s sx profile %d %s port 0%x tc list %s - %s\n",
                   (cmd == SX_ACCESS_CMD_BIND) ? "bind" : "unbind", profile_id,
                   (cmd == SX_ACCESS_CMD_BIND) ? "to" : "from", port, buf, SX_STATUS_MSG(sx_status));
    } else {
        SX_LOG_DBG("sx profile %d %s %s port 0%x tc list %s\n", profile_id,
                   (cmd == SX_ACCESS_CMD_BIND) ? "bind" : "unbind",
                   (cmd == SX_ACCESS_CMD_BIND) ? "to" : "from", port, buf);
    }
    return sdk_to_sai(sx_status);
}

/*
 * Bind / unbind profile_id for / from all ports where wred_id is set.
 *
 * Arguments:
 *    [in] wred_id - id of WRED profile
 *    [in] profile_id - sx profile id
 *    [in] flow_type - specify sx flow type
 *    [in] cmd - SX_ACCESS_CMD_BIND / SX_ACCESS_CMD_UNBIND
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
static sai_status_t mlnx_wred_bind_sxwred_to_all_port(sai_object_id_t           wred_id,
                                                      sx_cos_redecn_profile_t   profile_id,
                                                      sx_cos_redecn_flow_type_e flow_type,
                                                      sx_access_cmd_t           cmd)
{
    uint32_t                ii = 0;
    sx_cos_traffic_class_t *tc_list;
    uint32_t                tc_count  = g_resource_limits.cos_port_ets_traffic_class_max + 1;
    sx_status_t             sx_status = SX_STATUS_SUCCESS;
    mlnx_port_config_t     *port;

    tc_list = calloc(tc_count, sizeof(sx_cos_traffic_class_t));
    if (NULL == tc_list) {
        SX_LOG_ERR("Failed to alloc memory for tc list\n");
        return SAI_STATUS_NO_MEMORY;
    }


    mlnx_port_not_in_lag_foreach(port, ii) {
        tc_count = g_resource_limits.cos_port_ets_traffic_class_max + 1;
        if (SAI_STATUS_SUCCESS !=
            mlnx_wred_get_tc_configured_list(port, wred_id, tc_list, &tc_count)) {
            sx_status = SX_STATUS_ERROR;
            break;
        }
        if (tc_count > 0) {
            sx_status = mlnx_wred_bind_sxwred_to_port(port->logical, profile_id,
                                                      tc_list, tc_count, flow_type, cmd);
            if (SX_STATUS_SUCCESS != sx_status) {
                break;
            }
        }
    }


    if (tc_list) {
        free(tc_list);
    }
    return sdk_to_sai(sx_status);
}

/*
 * Check if WRED is configured on any port or queue
 *
 * Arguments:
 *    [in] wred_id - id of WRED profile
 *
 * Return Values:
 *    true / false
 *
 */
static bool mlnx_wred_check_in_use(sai_object_id_t wred_id)
{
    mlnx_port_config_t      *port;
    mlnx_qos_queue_config_t *queue;
    uint32_t                 ii, jj;

    mlnx_port_foreach(port, ii) {
        port_queues_foreach(port, queue, jj) {
            if (queue->wred_id == wred_id) {
                return true;
            }
        }
    }

    return false;
}

/* Apply all sx profiles from sai profile to a specified port */
static sai_status_t mlnx_wred_apply_saiwred_to_port(mlnx_wred_profile_t    *wred_profile,
                                                    sx_port_log_id_t        port_id,
                                                    sx_cos_traffic_class_t *tc_list,
                                                    uint32_t                tc_count,
                                                    sx_access_cmd_t         cmd)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (SAI_INVALID_PROFILE_ID != wred_profile->green_profile_id) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_wred_bind_sxwred_to_port(port_id, wred_profile->green_profile_id,
                                                    tc_list, tc_count,
                                                    SX_COS_REDECN_FLOW_TYPE_TCP_GREEN, cmd))) {
            return status;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_wred_bind_sxwred_to_port(port_id, wred_profile->green_profile_id,
                                                    tc_list, tc_count,
                                                    SX_COS_REDECN_FLOW_TYPE_NON_TCP_GREEN, cmd))) {
            return status;
        }
    }
    if (SAI_INVALID_PROFILE_ID != wred_profile->yellow_profile_id) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_wred_bind_sxwred_to_port(port_id, wred_profile->yellow_profile_id,
                                                    tc_list, tc_count,
                                                    SX_COS_REDECN_FLOW_TYPE_TCP_YELLOW, cmd))) {
            return status;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_wred_bind_sxwred_to_port(port_id, wred_profile->yellow_profile_id,
                                                    tc_list, tc_count,
                                                    SX_COS_REDECN_FLOW_TYPE_NON_TCP_YELLOW, cmd))) {
            return status;
        }
    }
    if (SAI_INVALID_PROFILE_ID != wred_profile->red_profile_id) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_wred_bind_sxwred_to_port(port_id, wred_profile->red_profile_id,
                                                    tc_list, tc_count,
                                                    SX_COS_REDECN_FLOW_TYPE_TCP_RED, cmd))) {
            return status;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_wred_bind_sxwred_to_port(port_id, wred_profile->red_profile_id,
                                                    tc_list, tc_count,
                                                    SX_COS_REDECN_FLOW_TYPE_NON_TCP_RED, cmd))) {
            return status;
        }
    }

    return status;
}

/*
 * Bind / unbind sai profile to / from all ports where wred_id is set.
 *
 * Arguments:
 *    [in] wred_id - id of WRED profile
 *    [in] cmd     - SX_ACCESS_CMD_BIND / SX_ACCESS_CMD_UNBIND
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
static sai_status_t mlnx_wred_bind_saiwred_to_all_port(sai_object_id_t wred_id, sx_access_cmd_t cmd)
{
    uint32_t                ii = 0;
    mlnx_wred_profile_t     wred_profile;
    sx_cos_traffic_class_t *tc_list;
    uint32_t                tc_count = g_resource_limits.cos_port_ets_traffic_class_max + 1;
    sai_status_t            status   = SAI_STATUS_SUCCESS;
    mlnx_port_config_t     *port;

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        return status;
    }

    tc_list = calloc(tc_count, sizeof(sx_cos_traffic_class_t));
    if (NULL == tc_list) {
        SX_LOG_ERR("Failed to alloc memory for tc list\n");
        return SAI_STATUS_NO_MEMORY;
    }

    mlnx_port_not_in_lag_foreach(port, ii) {
        tc_count = g_resource_limits.cos_port_ets_traffic_class_max + 1;
        if (SAI_STATUS_SUCCESS !=
            mlnx_wred_get_tc_configured_list(port, wred_id, tc_list, &tc_count)) {
            status = SAI_STATUS_FAILURE;
            break;
        }
        if (tc_count > 0) {
            if (cmd == SX_ACCESS_CMD_BIND) {
                bool wred_enabled = wred_profile.wred_enabled;
                bool ecn_enabled  = wred_profile.ecn_enabled;

                status = mlnx_wred_ecn_enable_set(port->logical, tc_list, tc_count, wred_enabled, ecn_enabled);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed update WRED/ECN enabled on port oid %" PRIx64 "\n", port->saiport);
                    break;
                }
            }

            status = mlnx_wred_apply_saiwred_to_port(&wred_profile, port->logical, tc_list, tc_count, cmd);
            if (SAI_ERR(status)) {
                break;
            }
        }
    }

    free(tc_list);
    return status;
}

/* Enable/disable RED and ECN mark for specified port and TC list */
static sai_status_t mlnx_wred_ecn_enable_set(sx_port_log_id_t        port,
                                             sx_cos_traffic_class_t *tc_list,
                                             uint32_t                tc_count,
                                             bool                    red_enable,
                                             bool                    ecn_enable)
{
    sx_status_t                   sx_status = SX_STATUS_SUCCESS;
    sx_cos_redecn_enable_params_t ecn_param;
    char                          buf[MAX_VALUE_STR_LEN] = {0};

    memset(&ecn_param, 0, sizeof(ecn_param));

    ecn_param.mode        = SX_COS_REDECN_MODE_ABSOLUTE;
    ecn_param.ecn_enabled = ecn_enable;
    ecn_param.red_enabled = red_enable;

    tc_list_to_str(tc_list, tc_count, buf);
    SX_LOG_INF("Set ecn_enabled (%d), red_enabled (%d) for port 0%x tc = %s\n",
               ecn_enable, red_enable, port, buf);

    sx_status = sx_api_cos_redecn_tc_enable_set(gh_sdk, port, tc_list, tc_count, &ecn_param);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to set redecn tc enable params - %s\n", SX_STATUS_MSG(sx_status));
    }

    return sdk_to_sai(sx_status);
}

sai_status_t mlnx_wred_apply_to_queue(_In_ mlnx_port_config_t *port,
                                      _In_ uint32_t            queue_idx,
                                      _In_ sai_object_id_t     wred_id)
{
    sai_status_t             status;
    mlnx_wred_profile_t      wred_profile;
    sai_object_id_t          curr_wred_id;
    sx_cos_traffic_class_t   tc;
    mlnx_qos_queue_config_t *queue_cfg;

    tc = queue_idx;

    if (tc > g_resource_limits.cos_port_ets_traffic_class_max) {
        SX_LOG_ERR("Invalid TC num (%u)\n", tc);
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_port_fetch_lag_if_lag_member(&port);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_queue_cfg_lookup(port->logical, tc, &queue_cfg);
    if (SAI_ERR(status)) {
        return status;
    }

    curr_wred_id = queue_cfg->wred_id;

    if (curr_wred_id == wred_id) {
        /* Nothing changed, return success */
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_NULL_OBJECT_ID != curr_wred_id) {
        status = mlnx_wred_db_get(curr_wred_id, &wred_profile);
        if (SAI_ERR(status)) {
            return status;
        }

        SX_LOG_DBG("Unbinding current wred %lx on port %x queue %d\n", curr_wred_id, port->logical, tc);

        status = mlnx_wred_apply_saiwred_to_port(&wred_profile, port->logical, &tc, 1, SX_ACCESS_CMD_UNBIND);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove WRED profile from port 0%x tc %d\n", port->logical, tc);
            return status;
        }
    }

    if (SAI_NULL_OBJECT_ID != wred_id) {
        status = mlnx_wred_db_get(wred_id, &wred_profile);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_wred_ecn_enable_set(port->logical, &tc, 1, wred_profile.wred_enabled, wred_profile.ecn_enabled);
        if (SAI_ERR(status)) {
            return status;
        }

        SX_LOG_DBG("Binding wred %lx to port %x queue %d\n", wred_id, port->logical, tc);

        status = mlnx_wred_apply_saiwred_to_port(&wred_profile, port->logical, &tc, 1, SX_ACCESS_CMD_BIND);
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        status = mlnx_wred_ecn_enable_set(port->logical, &tc, 1, false, false);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    queue_cfg->wred_id = wred_id;

    return SAI_STATUS_SUCCESS;
}

/*
 * Apply / remove SAI WRED profile to / from port or queue.
 *
 * Arguments:
 *    [in] new_wred_id - id of WRED profile
 *    [in] to_obj_id - SAI port or queue object id to apply WRED on
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
sai_status_t mlnx_wred_apply_to_queue_oid(_In_ sai_object_id_t wred_id, _In_ sai_object_id_t queue_oid)
{
    sai_status_t        status;
    uint32_t            queue_index;
    sx_port_log_id_t    port_id;
    uint8_t             ext_data[EXTENDED_DATA_SIZE] = {0};
    mlnx_port_config_t *port;

    status = mlnx_object_to_type(queue_oid, SAI_OBJECT_TYPE_QUEUE, &port_id, ext_data);
    if (SAI_ERR(status)) {
        return status;
    }

    queue_index = ext_data[0];

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        return status;
    }

    return mlnx_wred_apply_to_queue(port, queue_index, wred_id);
}

sai_status_t mlnx_wred_port_queue_db_clear(_In_ mlnx_port_config_t *port)
{
    mlnx_qos_queue_config_t *queue_cfg;
    uint32_t                 ii;

    port_queues_foreach(port, queue_cfg, ii) {
        queue_cfg->wred_id = SAI_NULL_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Remove SAI WRED profile.
 *
 * Arguments:
 *    [in] wred_id - id of WRED profile
 *    [in] profile_id - sx profile id
 *    [in] color - flow color type (green / yellow / red)
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
static sai_status_t mlnx_wred_remove_profile(sai_object_id_t         wred_id,
                                             sx_cos_redecn_profile_t profile_id,
                                             flow_color_type_t       color)
{
    sx_status_t                        sx_status;
    sai_status_t                       status;
    sx_cos_redecn_profile_attributes_t redecn_attr;
    sx_cos_redecn_flow_type_e          flows[2] = {0};

    memset(&redecn_attr, 0, sizeof(redecn_attr));

    switch (color) {
    case FLOW_COLOR_GREEN:
        flows[0] = SX_COS_REDECN_FLOW_TYPE_TCP_GREEN;
        flows[1] = SX_COS_REDECN_FLOW_TYPE_NON_TCP_GREEN;
        break;

    case FLOW_COLOR_YELLOW:
        flows[0] = SX_COS_REDECN_FLOW_TYPE_TCP_YELLOW;
        flows[1] = SX_COS_REDECN_FLOW_TYPE_NON_TCP_YELLOW;
        break;

    case FLOW_COLOR_RED:
        flows[0] = SX_COS_REDECN_FLOW_TYPE_TCP_RED;
        flows[1] = SX_COS_REDECN_FLOW_TYPE_NON_TCP_RED;
        break;

    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* unbind this profile from all ports it's currently bind */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_wred_bind_sxwred_to_all_port(wred_id, profile_id, flows[0],
                                                    SX_ACCESS_CMD_UNBIND))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_wred_bind_sxwred_to_all_port(wred_id, profile_id, flows[1],
                                                    SX_ACCESS_CMD_UNBIND))) {
        return status;
    }

    /* remove profile */
    sx_status = sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_DELETE,
                                              &redecn_attr, &profile_id);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to remove profile - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
    }
    return status;
}

static void wred_key_to_str(_In_ sai_object_id_t wred_id, _Out_ char *key_str)
{
    uint32_t wred;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(wred_id, SAI_OBJECT_TYPE_WRED, &wred, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid wred profile id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "wred profile id  %u", wred);
    }
}
/*
 * Get WRED profile attributes */
static sai_status_t mlnx_wred_attr_getter(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_object_id_t                    wred_id = key->key.object_id;
    sx_cos_redecn_profile_attributes_t redecn_attr;
    mlnx_wred_profile_t                wred_profile;
    sx_cos_redecn_profile_t            sx_profile               = SAI_INVALID_PROFILE_ID;
    char                               key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t                       status                   = SAI_STATUS_SUCCESS;
    sx_status_t                        sx_status                = SX_STATUS_SUCCESS;
    long                               attr                     = (long)arg;

    memset(&redecn_attr, 0, sizeof(redecn_attr));
    memset(&wred_profile, 0, sizeof(wred_profile));

    SX_LOG_ENTER();

    wred_key_to_str(wred_id, key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to get attr, %s not exists\n", key_str);
        return status;
    }

    switch (attr) {
    case SAI_WRED_ATTR_GREEN_ENABLE:
    case SAI_WRED_ATTR_GREEN_MIN_THRESHOLD:
    case SAI_WRED_ATTR_GREEN_MAX_THRESHOLD:
    case SAI_WRED_ATTR_GREEN_DROP_PROBABILITY:
        sx_profile = wred_profile.green_profile_id;
        break;

    case SAI_WRED_ATTR_YELLOW_ENABLE:
    case SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY:
        sx_profile = wred_profile.yellow_profile_id;
        break;

    case SAI_WRED_ATTR_RED_ENABLE:
    case SAI_WRED_ATTR_RED_MIN_THRESHOLD:
    case SAI_WRED_ATTR_RED_MAX_THRESHOLD:
    case SAI_WRED_ATTR_RED_DROP_PROBABILITY:
        sx_profile = wred_profile.red_profile_id;
        break;

    default:
        SX_LOG_ERR("Failed to set profile attr %lu : invalid attribute\n", attr);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_INVALID_PROFILE_ID != sx_profile) {
        sx_status = sx_api_cos_redecn_profile_get(gh_sdk, sx_profile, &redecn_attr);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to get attr - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    switch (attr) {
    case SAI_WRED_ATTR_GREEN_ENABLE:
    case SAI_WRED_ATTR_YELLOW_ENABLE:
    case SAI_WRED_ATTR_RED_ENABLE:
        if (wred_profile.wred_enabled && (SAI_INVALID_PROFILE_ID != sx_profile)) {
            value->booldata = true;
        } else {
            value->booldata = false;
        }
        break;

    case SAI_WRED_ATTR_GREEN_MIN_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD:
    case SAI_WRED_ATTR_RED_MIN_THRESHOLD:
        if (SAI_INVALID_PROFILE_ID != sx_profile) {
            value->u32 = mlnx_wred_sx_threshold_to_sai(redecn_attr.values.absolute_mode.min);
        } else {
            value->u32 = 0;
        }
        break;

    case SAI_WRED_ATTR_GREEN_MAX_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD:
    case SAI_WRED_ATTR_RED_MAX_THRESHOLD:
        if (SAI_INVALID_PROFILE_ID != sx_profile) {
            value->u32 = mlnx_wred_sx_threshold_to_sai(redecn_attr.values.absolute_mode.max);
        } else {
            value->u32 = 0;
        }
        break;

    case SAI_WRED_ATTR_GREEN_DROP_PROBABILITY:
    case SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY:
    case SAI_WRED_ATTR_RED_DROP_PROBABILITY:
        if (SAI_INVALID_PROFILE_ID != sx_profile) {
            value->u32 = redecn_attr.high_drop_percent;
        } else {
            value->u32 = DEFAULT_WRED_PROBABILITY;
        }
        break;
    }

    SX_LOG_EXIT();
    return status;
}

/* Set WRED profile attributes */
static sai_status_t mlnx_wred_attr_setter(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sai_object_id_t                    wred_id = key->key.object_id;
    sx_cos_redecn_profile_attributes_t redecn_attr;
    mlnx_wred_profile_t                wred_profile;
    sx_cos_redecn_profile_t           *profile                  = NULL;
    char                               key_str[MAX_KEY_STR_LEN] = {0};
    sx_status_t                        sx_status                = SX_STATUS_SUCCESS;
    sai_status_t                       status                   = SAI_STATUS_SUCCESS;
    long                               attr                     = (long)arg;
    sx_cos_redecn_flow_type_e          flows[2]                 = {0};

    memset(&redecn_attr, 0, sizeof(redecn_attr));
    memset(&wred_profile, 0, sizeof(wred_profile));

    SX_LOG_ENTER();

    wred_key_to_str(wred_id, key_str);

    if (SAI_STATUS_SUCCESS != (sx_status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to get attr, %s not exists\n", key_str);
        return sx_status;
    }

    switch (attr) {
    case SAI_WRED_ATTR_GREEN_MIN_THRESHOLD:
    case SAI_WRED_ATTR_GREEN_MAX_THRESHOLD:
    case SAI_WRED_ATTR_GREEN_DROP_PROBABILITY:
        profile  = &wred_profile.green_profile_id;
        flows[0] = SX_COS_REDECN_FLOW_TYPE_TCP_GREEN;
        flows[1] = SX_COS_REDECN_FLOW_TYPE_NON_TCP_GREEN;
        break;

    case SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY:
        profile  = &wred_profile.yellow_profile_id;
        flows[0] = SX_COS_REDECN_FLOW_TYPE_TCP_YELLOW;
        flows[1] = SX_COS_REDECN_FLOW_TYPE_NON_TCP_YELLOW;
        break;

    case SAI_WRED_ATTR_RED_MIN_THRESHOLD:
    case SAI_WRED_ATTR_RED_MAX_THRESHOLD:
    case SAI_WRED_ATTR_RED_DROP_PROBABILITY:
        profile  = &wred_profile.red_profile_id;
        flows[0] = SX_COS_REDECN_FLOW_TYPE_TCP_RED;
        flows[1] = SX_COS_REDECN_FLOW_TYPE_NON_TCP_RED;
        break;

    default:
        SX_LOG_ERR("Failed to set profile attr %lu : invalid attribute\n", attr);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_INVALID_PROFILE_ID == *profile) {
        SX_LOG_ERR("Failed to set profile attr %lu - profile is not configured\n", attr);
        return SAI_STATUS_FAILURE;
    }

    sx_status = sx_api_cos_redecn_profile_get(gh_sdk, *profile, &redecn_attr);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get profile attr - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    switch (attr) {
    case SAI_WRED_ATTR_GREEN_MIN_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD:
    case SAI_WRED_ATTR_RED_MIN_THRESHOLD:
        redecn_attr.values.absolute_mode.min = mlnx_wred_sai_threshold_to_sx(value->u32);
        break;

    case SAI_WRED_ATTR_GREEN_MAX_THRESHOLD:
    case SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD:
    case SAI_WRED_ATTR_RED_MAX_THRESHOLD:
        redecn_attr.values.absolute_mode.max = mlnx_wred_sai_threshold_to_sx(value->u32);
        break;

    case SAI_WRED_ATTR_GREEN_DROP_PROBABILITY:
    case SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY:
    case SAI_WRED_ATTR_RED_DROP_PROBABILITY:
        if (value->u32 > 100) {
            SX_LOG_ERR("Failed to set profile attr %lu - invalid range for drop probability\n", attr);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        redecn_attr.high_drop_percent = value->u32;
        break;
    }

    /* unbind from all ports */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_wred_bind_sxwred_to_all_port(wred_id, *profile, flows[0],
                                                    SX_ACCESS_CMD_UNBIND))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_wred_bind_sxwred_to_all_port(wred_id, *profile, flows[1],
                                                    SX_ACCESS_CMD_UNBIND))) {
        return status;
    }


    sx_status = sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_EDIT,
                                              &redecn_attr, profile);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to set profile attr - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* bind profile back to all ports */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_wred_bind_sxwred_to_all_port(wred_id, *profile, flows[0],
                                                    SX_ACCESS_CMD_BIND))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_wred_bind_sxwred_to_all_port(wred_id, *profile, flows[1],
                                                    SX_ACCESS_CMD_BIND))) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* Set WRED profile attributes */
static sai_status_t mlnx_wred_attr_enable_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_object_id_t          wred_id = key->key.object_id;
    mlnx_wred_profile_t      wred_profile;
    sx_cos_redecn_profile_t *sx_profile_p             = NULL;
    flow_color_type_t        color                    = FLOW_COLOR_GREEN;
    char                     key_str[MAX_KEY_STR_LEN] = {0};
    bool                     wred_enabled;
    sai_status_t             status = SAI_STATUS_SUCCESS;
    long                     attr   = (long)arg;

    memset(&wred_profile, 0, sizeof(wred_profile));

    SX_LOG_ENTER();

    wred_key_to_str(wred_id, key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to get attr, %s not exists\n", key_str);
        return status;
    }

    if (!value->booldata && !wred_profile.wred_enabled) {
        return SAI_STATUS_SUCCESS;
    }

    wred_enabled = wred_profile.wred_enabled;

    switch (attr) {
    case SAI_WRED_ATTR_GREEN_ENABLE:
        if (wred_profile.ecn_enabled) {
            if (value->booldata) {
                if (wred_profile.green_profile_id == SAI_INVALID_PROFILE_ID) {
                    if ((wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) ||
                        (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
                        SX_LOG_ERR("Can't set Green WRED enable when Yellow or Red ECN mark mode enabled\n");
                        return SAI_STATUS_INVALID_PARAMETER;
                    }
                }
            } else {
                if (wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) {
                    SX_LOG_ERR("Can't set Green WRED disable when Green ECN mark mode enabled\n");
                    return SAI_STATUS_INVALID_PARAMETER;
                }
            }
        }
        if (value->booldata) {
            if (wred_profile.green_profile_id == SAI_INVALID_PROFILE_ID) {
                SX_LOG_ERR("Can't set WRED enable - no profile created\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            wred_enabled = value->booldata;
        } else {
            sx_profile_p = &wred_profile.green_profile_id;
            color        = FLOW_COLOR_GREEN;
        }
        break;

    case SAI_WRED_ATTR_YELLOW_ENABLE:
        if (wred_profile.ecn_enabled) {
            if (value->booldata) {
                if (wred_profile.yellow_profile_id == SAI_INVALID_PROFILE_ID) {
                    if ((wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) ||
                        (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
                        SX_LOG_ERR("Can't set Yellow WRED enable when Green or Red ECN mark mode enabled\n");
                        return SAI_STATUS_INVALID_PARAMETER;
                    }
                }
            } else {
                if (wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) {
                    SX_LOG_ERR("Can't set Yellow WRED disable when Yellow ECN mark mode enabled\n");
                    return SAI_STATUS_INVALID_PARAMETER;
                }
            }
        }
        if (value->booldata) {
            if (wred_profile.yellow_profile_id == SAI_INVALID_PROFILE_ID) {
                SX_LOG_ERR("Can't set WRED enable - no profile created\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            wred_enabled = value->booldata;
        } else {
            sx_profile_p = &wred_profile.yellow_profile_id;
            color        = FLOW_COLOR_YELLOW;
        }
        break;

    case SAI_WRED_ATTR_RED_ENABLE:
        if (wred_profile.ecn_enabled) {
            if (value->booldata) {
                if (wred_profile.red_profile_id == SAI_INVALID_PROFILE_ID) {
                    if ((wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) ||
                        (wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID)) {
                        SX_LOG_ERR("Can't set Red WRED enable when Green or Yellow ECN mark mode enabled\n");
                        return SAI_STATUS_INVALID_PARAMETER;
                    }
                }
            } else {
                if (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID) {
                    SX_LOG_ERR("Can't set Red WRED disable when Red ECN mark mode enabled\n");
                    return SAI_STATUS_INVALID_PARAMETER;
                }
            }
        }
        if (value->booldata) {
            if (wred_profile.red_profile_id == SAI_INVALID_PROFILE_ID) {
                SX_LOG_ERR("Can't set WRED enable - no profile created\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            wred_enabled = value->booldata;
        } else {
            sx_profile_p = &wred_profile.red_profile_id;
            color        = FLOW_COLOR_RED;
        }
        break;

    default:
        SX_LOG_ERR("Failed to set profile attr %lu - invalid attribute\n", attr);
        status = SAI_STATUS_INVALID_PARAMETER;
    }

    /* Do re-bind WRED profiles only if ECN enabled */
    if (wred_profile.ecn_enabled && (wred_enabled != wred_profile.wred_enabled)) {
        status = mlnx_wred_bind_saiwred_to_all_port(wred_id, SX_ACCESS_CMD_UNBIND);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set ecn for %s\n", key_str);
            return status;
        }

        wred_profile.wred_enabled = wred_enabled;
        status                    = mlnx_wred_db_set(wred_id, &wred_profile);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set ecn for %s\n", key_str);
            return status;
        }

        status = mlnx_wred_bind_saiwred_to_all_port(wred_id, SX_ACCESS_CMD_BIND);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set ecn for %s\n", key_str);
            return status;
        }

        return status;
    }

    if ((sx_profile_p) && (SAI_INVALID_PROFILE_ID != *sx_profile_p)) {
        if (SAI_STATUS_SUCCESS ==
            (status = mlnx_wred_remove_profile(wred_id, *sx_profile_p, color))) {
            *sx_profile_p = SAI_INVALID_PROFILE_ID;

            if ((wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) &&
                (wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) &&
                (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
                wred_profile.wred_enabled = false;
            }
            if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_set(wred_id, &wred_profile))) {
                SX_LOG_ERR("Failed to update WRED db for %s\n", key_str);
            }
        } else {
            SX_LOG_ERR("Failed to remove profile %u\n", *sx_profile_p);
        }
    }

    SX_LOG_EXIT();
    return status;
}

static uint32_t mlnx_wred_weight_to_sx(uint8_t sai_weight)
{
    uint32_t sx_weight = 0;

    if (sai_weight < sizeof(sai_sx_weight_map) / sizeof(sai_sx_weight_map[0])) {
        sx_weight = sai_sx_weight_map[sai_weight];
    }

    return sx_weight;
}

/* Conversion from sx weight to sai weight.
 * I used the approach same as sdk_to_prm conversion.*/
static uint8_t mlnx_wred_weight_to_sai(uint32_t sx_weight)
{
    uint8_t weight = 0;

    for (weight = 0; sx_weight < sai_sx_weight_map[weight]; weight++) {
    }

    weight =
        (sai_sx_weight_map[weight] - sx_weight <= sx_weight - sai_sx_weight_map[weight + 1]) ? weight : weight + 1;

    return weight;
}

static sai_status_t mlnx_wred_sx_weight_validate(sai_object_id_t wred_id, uint8_t weight_val)
{
    sai_status_t           status    = SAI_STATUS_SUCCESS;
    uint32_t               wred_num  = 0, count = 0, wred_last_num = 0;
    sai_object_id_t        wred_last = SAI_NULL_OBJECT_ID;
    sx_cos_redecn_global_t redecn_global;
    sx_status_t            sx_status = SX_STATUS_SUCCESS;

    memset(&redecn_global, 0, sizeof(redecn_global));

    if (weight_val > MAX_WEIGHT_VAL) {
        SX_LOG_ERR("Failed to set weight, invalid value %u\n", weight_val);
        return SAI_STATUS_NOT_SUPPORTED;
    }
    /* Check for how many WREDs are configured,
     * actually we only need to know if it 0, 1 or more than 1 */
    while ((wred_num < g_resource_limits.cos_redecn_profiles_max) && (count < 2)) {
        if (g_sai_qos_db_ptr->wred_db[wred_num].in_use) {
            count++;
            wred_last_num = wred_num;
        }
        wred_num++;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_WRED, wred_last_num,
                                                           NULL, &wred_last))) {
        return status;
    }

    /* Weight is a global value in SDK, and not per profile value
     * Therefor we are validating all profiles have the same weight value
     * If count equal 0 that means that no profiles currently created and no further check is required.
     * If count is 1 and obj id is same, this means that only one profile is created
     * and we modify this profile - allow change weight.
     * In all other cases - we must verify that weight that we try set is the same
     * as currently configured in system.
     */
    if (((count == 1) && (wred_last != wred_id)) || (count > 1)) {
        sx_status = sx_api_cos_redecn_general_param_get(gh_sdk, &redecn_global);
        if (SX_STATUS_SUCCESS == sx_status) {
            if (redecn_global.weight != mlnx_wred_weight_to_sx(weight_val)) {
                SX_LOG_ERR("Invalid weight, all profiles must have same weight value %u\n",
                           mlnx_wred_weight_to_sai(redecn_global.weight));
                status = SAI_STATUS_FAILURE;
            }
        } else {
            SX_LOG_ERR("Failed to get redecn global config - %s.\n", SX_STATUS_MSG(sx_status));
            status = SAI_STATUS_FAILURE;
        }
    }

    return status;
}

/* Helper routine to set weight */
static sai_status_t mlnx_wred_sx_weight_set(uint8_t weight_val)
{
    sx_cos_redecn_global_t redecn_global;
    uint32_t               sx_weight = mlnx_wred_weight_to_sx(weight_val);
    sx_status_t            sx_status = SX_STATUS_SUCCESS;

    memset(&redecn_global, 0, sizeof(redecn_global));

    sx_status = sx_api_cos_redecn_general_param_get(gh_sdk, &redecn_global);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get redecn global config - %s.\n", SX_STATUS_MSG(sx_status));
    } else if (redecn_global.weight != sx_weight) {
        redecn_global.weight = sx_weight;

        sx_status = sx_api_cos_redecn_general_param_set(gh_sdk, &redecn_global);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to set redecn global config - %s.\n", SX_STATUS_MSG(sx_status));
        }
    }

    return sdk_to_sai(sx_status);
}

/* Init global variables */
sai_status_t mlnx_wred_init()
{
    sx_cos_redecn_global_t redecn_global;
    sx_status_t            sx_status = SX_STATUS_SUCCESS;

    memset(&redecn_global, 0, sizeof(redecn_global));

    redecn_global.source_congestion_detection_only = false;
    redecn_global.weight                           = mlnx_wred_weight_to_sx(DEFAULT_WEIGHT_VAL);

    sx_status = sx_api_cos_redecn_general_param_set(gh_sdk, &redecn_global);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to set redecn global config - %s.\n", SX_STATUS_MSG(sx_status));
    }

    return sdk_to_sai(sx_status);
}

/* Set global average queue size weight
 * Note : SDK/FW requires 2^SAI_WRED_ATTR_WEIGHT < SAI_WRED_ATTR_[GREEN/YELLOW/RED]_MIN_THRESHOLD / Cell size (=96 in SPC)
 * The rational being
 * average queue size = 2^-weight * current size + previous average * (1-2^-weight)
 * thus min size has to be bigger than 2^-weight
 * and also min size is measured in cells
 */
static sai_status_t mlnx_wred_weight_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg)
{
    sai_object_id_t     wred_id = key->key.object_id;
    mlnx_wred_profile_t wred_profile;
    char                key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t        status                   = SAI_STATUS_SUCCESS;

    memset(&wred_profile, 0, sizeof(wred_profile));

    SX_LOG_ENTER();

    wred_key_to_str(wred_id, key_str);
    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to set weight, %s not exists\n", key_str);
        return status;
    }

    if (SAI_STATUS_SUCCESS ==
        (status = mlnx_wred_sx_weight_validate(wred_id, value->u8))) {
        status = mlnx_wred_sx_weight_set(value->u8);
    }

    SX_LOG_EXIT();
    return status;
}

/* Get global average queue size weight */
static sai_status_t mlnx_wred_weight_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    sai_object_id_t        wred_id = key->key.object_id;
    mlnx_wred_profile_t    wred_profile;
    char                   key_str[MAX_KEY_STR_LEN] = {0};
    sx_status_t            status                   = SX_STATUS_SUCCESS;
    sx_cos_redecn_global_t redecn_global;

    memset(&wred_profile, 0, sizeof(wred_profile));
    memset(&redecn_global, 0, sizeof(redecn_global));

    SX_LOG_ENTER();

    wred_key_to_str(wred_id, key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to get weight, %s not exists\n", key_str);
        return status;
    }

    status = sx_api_cos_redecn_general_param_get(gh_sdk, &redecn_global);
    if (SX_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to get redecn global config - %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u8 = mlnx_wred_weight_to_sai(redecn_global.weight);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Set whether ECN mark is enabled for WRED profile */
static sai_status_t mlnx_wred_ecn_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    char                     key_str[MAX_KEY_STR_LEN] = {0};
    sai_object_id_t          wred_id                  = key->key.object_id;
    sx_cos_redecn_profile_t *disable_profiles[3];
    uint32_t                 disable_count = 0;
    mlnx_wred_profile_t      wred_profile;
    bool                     ecn_enable;
    sai_status_t             status = SAI_STATUS_SUCCESS;
    uint32_t                 ii;

    ecn_enable = (SAI_ECN_MARK_MODE_NONE != value->s32) ? true : false;

    memset(&wred_profile, 0, sizeof(wred_profile));

    SX_LOG_ENTER();

    wred_key_to_str(wred_id, key_str);

    status = mlnx_wred_db_get(wred_id, &wred_profile);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get ecn, %s not exists\n", key_str);
        goto out;
    }

    if (value->s32 == SAI_ECN_MARK_MODE_NONE) {
        if ((wred_profile.green_profile_id == SAI_INVALID_PROFILE_ID) &&
            (wred_profile.yellow_profile_id == SAI_INVALID_PROFILE_ID) &&
            (wred_profile.red_profile_id == SAI_INVALID_PROFILE_ID)) {
            status = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

    switch (value->s32) {
    case SAI_ECN_MARK_MODE_NONE:
        break;

    case SAI_ECN_MARK_MODE_ALL:
        if ((wred_profile.green_profile_id == SAI_INVALID_PROFILE_ID) ||
            (wred_profile.yellow_profile_id == SAI_INVALID_PROFILE_ID) ||
            (wred_profile.red_profile_id == SAI_INVALID_PROFILE_ID)) {
            SX_LOG_ERR("Can't set ECN mark mode - no profiles created\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
        break;

    case SAI_ECN_MARK_MODE_GREEN:
        if (wred_profile.wred_enabled) {
            if ((wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) ||
                (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
                SX_LOG_ERR("Can't set Green ECN mark mode when WRED Yellow or Red enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        if (wred_profile.green_profile_id == SAI_INVALID_PROFILE_ID) {
            SX_LOG_ERR("Can't set ECN mark mode - no profile created\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        disable_profiles[0] = &wred_profile.yellow_profile_id;
        disable_profiles[1] = &wred_profile.red_profile_id;
        disable_count       = 2;
        break;

    case SAI_ECN_MARK_MODE_YELLOW:
        if (wred_profile.wred_enabled) {
            if ((wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) ||
                (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
                SX_LOG_ERR("Can't set Yellow ECN mark mode when WRED Green or Red enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        if (wred_profile.yellow_profile_id == SAI_INVALID_PROFILE_ID) {
            SX_LOG_ERR("Can't set ECN mark mode - no profile created\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        disable_profiles[0] = &wred_profile.green_profile_id;
        disable_profiles[1] = &wred_profile.red_profile_id;
        disable_count       = 2;
        break;

    case SAI_ECN_MARK_MODE_RED:
        if (wred_profile.wred_enabled) {
            if ((wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) ||
                (wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID)) {
                SX_LOG_ERR("Can't set Red ECN mark mode when WRED Green or Yellow enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        if (wred_profile.red_profile_id == SAI_INVALID_PROFILE_ID) {
            SX_LOG_ERR("Can't set ECN mark mode - no profile created\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        disable_profiles[0] = &wred_profile.green_profile_id;
        disable_profiles[1] = &wred_profile.yellow_profile_id;
        disable_count       = 2;
        break;

    case SAI_ECN_MARK_MODE_GREEN_YELLOW:
        if (wred_profile.wred_enabled) {
            if (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID) {
                SX_LOG_ERR("Can't set Green-Yellow ECN mark mode when WRED Red enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        if ((wred_profile.green_profile_id == SAI_INVALID_PROFILE_ID) ||
            (wred_profile.yellow_profile_id == SAI_INVALID_PROFILE_ID)) {
            SX_LOG_ERR("Can't set ECN mark mode - no profiles created\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        disable_profiles[0] = &wred_profile.red_profile_id;
        disable_count       = 1;
        break;

    case SAI_ECN_MARK_MODE_GREEN_RED:
        if (wred_profile.wred_enabled) {
            if (wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) {
                SX_LOG_ERR("Can't set Green-Red ECN mark mode when WRED Yellow enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        if ((wred_profile.green_profile_id == SAI_INVALID_PROFILE_ID) ||
            (wred_profile.red_profile_id == SAI_INVALID_PROFILE_ID)) {
            SX_LOG_ERR("Can't set ECN mark mode - no profiles created\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        disable_profiles[0] = &wred_profile.yellow_profile_id;
        disable_count       = 1;
        break;

    case SAI_ECN_MARK_MODE_YELLOW_RED:
        if (wred_profile.wred_enabled) {
            if (wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) {
                SX_LOG_ERR("Can't set Yellow-Red ECN mark mode when WRED Green enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        if ((wred_profile.yellow_profile_id == SAI_INVALID_PROFILE_ID) ||
            (wred_profile.red_profile_id == SAI_INVALID_PROFILE_ID)) {
            SX_LOG_ERR("Can't set ECN mark mode - no profiles created\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        disable_profiles[0] = &wred_profile.green_profile_id;
        disable_count       = 1;
        break;

    default:
        SX_LOG_ERR("Invalid attribute value ecn mark mode must be in range %d - %d, %d\n",
                   SAI_ECN_MARK_MODE_NONE,
                   SAI_ECN_MARK_MODE_ALL,
                   value->s32);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0;
        goto out;
    }

    /* Do re-bind WRED profiles only if ECN is really need to be updated */
    if (wred_profile.ecn_enabled != ecn_enable) {
        status = mlnx_wred_bind_saiwred_to_all_port(wred_id, SX_ACCESS_CMD_UNBIND);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set ecn for %s\n", key_str);
            goto out;
        }

        wred_profile.ecn_enabled = ecn_enable;
        status                   = mlnx_wred_db_set(wred_id, &wred_profile);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set ecn for %s\n", key_str);
            goto out;
        }

        status = mlnx_wred_bind_saiwred_to_all_port(wred_id, SX_ACCESS_CMD_BIND);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set ecn for %s\n", key_str);
            goto out;
        }
    }

    for (ii = 0; ii < disable_count; ii++) {
        sx_cos_redecn_profile_t *sx_profile = disable_profiles[ii];
        flow_color_type_t        color;

        if (sx_profile == &wred_profile.yellow_profile_id) {
            color = FLOW_COLOR_YELLOW;
        } else if (sx_profile == &wred_profile.green_profile_id) {
            color = FLOW_COLOR_GREEN;
        } else if (sx_profile == &wred_profile.red_profile_id) {
            color = FLOW_COLOR_RED;
        } else {
            assert(false);
        }

        status = mlnx_wred_remove_profile(wred_id, *sx_profile, color);
        if (SAI_ERR(status)) {
            goto out;
        }
        *sx_profile = SAI_INVALID_PROFILE_ID;
        if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_set(wred_id, &wred_profile))) {
            SX_LOG_ERR("Failed to update WRED db for %s\n", key_str);
        }
    }

out:
    SX_LOG_EXIT();
    return status;
}

/* Get if ECN mark is enabled for WRED profile */
static sai_status_t mlnx_wred_ecn_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_object_id_t     wred_id = key->key.object_id;
    mlnx_wred_profile_t wred_profile;
    char                key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t        status                   = SAI_STATUS_SUCCESS;

    memset(&wred_profile, 0, sizeof(wred_profile));

    SX_LOG_ENTER();

    wred_key_to_str(wred_id, key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to get ecn, %s not exists\n", key_str);
        SX_LOG_EXIT();
        return status;
    }

    if (!wred_profile.ecn_enabled) {
        value->s32 = SAI_ECN_MARK_MODE_NONE;
    } else if ((wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) &&
               (wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) &&
               (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
        value->s32 = SAI_ECN_MARK_MODE_ALL;
    } else if ((wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) &&
               (wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID)) {
        value->s32 = SAI_ECN_MARK_MODE_GREEN_YELLOW;
    } else if ((wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) &&
               (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
        value->s32 = SAI_ECN_MARK_MODE_GREEN_RED;
    } else if ((wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) &&
               (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID)) {
        value->s32 = SAI_ECN_MARK_MODE_YELLOW_RED;
    } else if (wred_profile.green_profile_id != SAI_INVALID_PROFILE_ID) {
        value->s32 = SAI_ECN_MARK_MODE_GREEN;
    } else if (wred_profile.yellow_profile_id != SAI_INVALID_PROFILE_ID) {
        value->s32 = SAI_ECN_MARK_MODE_YELLOW;
    } else if (wred_profile.red_profile_id != SAI_INVALID_PROFILE_ID) {
        value->s32 = SAI_ECN_MARK_MODE_RED;
    }

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_wred_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_cos_redecn_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

/*
 * Routine Description:
 *   Set WRED attribute value.
 *
 * Arguments:
 *    [in] wred_id - wred id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_wred_attribute(_In_ sai_object_id_t wred_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key  = { .key.object_id = wred_id };
    uint32_t               wred = 0;
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(wred_id, SAI_OBJECT_TYPE_WRED, &wred, NULL)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    wred_key_to_str(wred_id, key_str);

    sai_db_write_lock();
    status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_WRED, wred_vendor_attribs, attr);
    sai_db_unlock();

    return status;
}


/*
 * Routine Description:
 *   Get WRED attribute value.
 *
 * Arguments:
 *    [in] wred_id - WRED id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_wred_attribute(_In_ sai_object_id_t     wred_id,
                                            _In_ uint32_t            attr_count,
                                            _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = wred_id };
    char                   key_str[MAX_KEY_STR_LEN];
    uint32_t               wred = 0;
    sai_status_t           status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(wred_id, SAI_OBJECT_TYPE_WRED, &wred, NULL)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    wred_key_to_str(wred_id, key_str);

    sai_db_read_lock();
    status = sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_WRED, wred_vendor_attribs, attr_count, attr_list);
    sai_db_unlock();

    return status;
}

/* Remove all profiles from wred_profile structure if they exist
 */
static void mlnx_wred_cleanup_profiles(mlnx_wred_profile_t *wred_profile_p)
{
    sx_cos_redecn_profile_attributes_t redecn_attr;

    memset(&redecn_attr, 0, sizeof(redecn_attr));

    if (wred_profile_p->green_profile_id != SAI_INVALID_PROFILE_ID) {
        sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_DELETE,
                                      &redecn_attr, &wred_profile_p->green_profile_id);
    }
    if (wred_profile_p->yellow_profile_id != SAI_INVALID_PROFILE_ID) {
        sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_DELETE,
                                      &redecn_attr, &wred_profile_p->yellow_profile_id);
    }
    if (wred_profile_p->red_profile_id != SAI_INVALID_PROFILE_ID) {
        sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_DELETE,
                                      &redecn_attr, &wred_profile_p->red_profile_id);
    }
}

#define WRED_ECN_INVALID_FMT "Can't create WRED profile for drop & ECN mark enabled"
/*
 * Routine Description:
 *    Create WRED profile
 *
 * Arguments:
 *    [out] wred_id - WRED profile entry
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 */
static sai_status_t mlnx_create_wred_profile(_Out_ sai_object_id_t      *wred_id,
                                             _In_ sai_object_id_t        switch_id,
                                             _In_ uint32_t               attr_count,
                                             _In_ const sai_attribute_t *attr_list)
{
    sx_cos_redecn_profile_attributes_t redecn_attr_green, redecn_attr_yellow, redecn_attr_red;
    const sai_attribute_value_t       *green_en_attr       = NULL, *yellow_en_attr = NULL, *red_en_attr = NULL;
    const sai_attribute_value_t       *ecn_en_attr         = NULL, *weight = NULL;
    const sai_attribute_value_t       *green_min_th        = NULL, *green_max_th = NULL, *green_prob = NULL;
    const sai_attribute_value_t       *yellow_min_th       = NULL, *yellow_max_th = NULL, *yellow_prob = NULL;
    const sai_attribute_value_t       *red_min_th          = NULL, *red_max_th = NULL, *red_prob = NULL;
    uint8_t                            weight_val          = 0;
    uint32_t                           index               = 0;
    bool                               wred_green_enabled  = false;
    bool                               wred_yellow_enabled = false;
    bool                               wred_red_enabled    = false;
    bool                               ecn_green_enabled   = false;
    bool                               ecn_yellow_enabled  = false;
    bool                               ecn_red_enabled     = false;
    bool                               green_enabled       = false;
    bool                               yellow_enabled      = false;
    bool                               red_enabled         = false;
    mlnx_wred_profile_t                wred_profile;
    sai_status_t                       status                           = SAI_STATUS_SUCCESS;
    sx_status_t                        sx_status                        = SX_STATUS_SUCCESS;
    char                               list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                               key_str[MAX_KEY_STR_LEN]         = {0};

    memset(&redecn_attr_green, 0, sizeof(redecn_attr_green));
    memset(&redecn_attr_yellow, 0, sizeof(redecn_attr_yellow));
    memset(&redecn_attr_red, 0, sizeof(redecn_attr_red));
    memset(&wred_profile, 0, sizeof(wred_profile));

    wred_profile.green_profile_id  = SAI_INVALID_PROFILE_ID;
    wred_profile.yellow_profile_id = SAI_INVALID_PROFILE_ID;
    wred_profile.red_profile_id    = SAI_INVALID_PROFILE_ID;

    SX_LOG_ENTER();

    if (NULL == wred_id) {
        SX_LOG_ERR("NULL wred id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_WRED, wred_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attributes check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_WRED, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create wred profile, %s\n", list_str);

    /* WRED Green - enable, drop prob */
    status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_GREEN_ENABLE, &green_en_attr, &index);
    if (!SAI_ERR(status)) {
        wred_green_enabled = green_en_attr->booldata;
    }
    status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_GREEN_DROP_PROBABILITY, &green_prob, &index);
    if (!SAI_ERR(status)) {
        if (!wred_green_enabled) {
            SX_LOG_ERR("Invalid SAI_WRED_ATTR_GREEN_DROP_PROBABILITY if GREEN is disabled\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + index;
        }

        if (green_prob->u32 > 100) {
            SX_LOG_ERR("Invalid attribute green drop probability must be in range 0 - 100\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + index;
        }

        redecn_attr_green.high_drop_percent = green_prob->u32;
    } else {
        redecn_attr_green.high_drop_percent = DEFAULT_WRED_PROBABILITY;
    }

    /* WRED Yellow - enable, drop prob */
    status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_YELLOW_ENABLE, &yellow_en_attr, &index);
    if (!SAI_ERR(status)) {
        wred_yellow_enabled = yellow_en_attr->booldata;
    }
    status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY, &yellow_prob, &index);
    if (!SAI_ERR(status)) {
        if (!wred_yellow_enabled) {
            SX_LOG_ERR("Invalid SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY if YELLOW is disabled\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + index;
        }

        if (yellow_prob->u32 > 100) {
            SX_LOG_ERR("Invalid attribute yellow drop probability must be in range 0 - 100\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + index;
        }

        redecn_attr_yellow.high_drop_percent = yellow_prob->u32;
    } else {
        redecn_attr_yellow.high_drop_percent = DEFAULT_WRED_PROBABILITY;
    }

    /* WRED Red - enable, drop prob */
    status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_RED_ENABLE, &red_en_attr, &index);
    if (!SAI_ERR(status)) {
        wred_red_enabled = red_en_attr->booldata;
    }
    status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_RED_DROP_PROBABILITY, &red_prob, &index);
    if (!SAI_ERR(status)) {
        if (!wred_red_enabled) {
            SX_LOG_ERR("Invalid SAI_WRED_ATTR_RED_DROP_PROBABILITY if RED is disabled\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + index;
        }

        if (red_prob->u32 > 100) {
            SX_LOG_ERR("Invalid attribute value red drop probability must be in range 0 - 100, %u\n",
                       red_prob->u32);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }

        redecn_attr_red.high_drop_percent = red_prob->u32;
    } else {
        redecn_attr_red.high_drop_percent = DEFAULT_WRED_PROBABILITY;
    }

    /* ECN mark */
    status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_ECN_MARK_MODE, &ecn_en_attr, &index);
    if (!SAI_ERR(status)) {
        switch (ecn_en_attr->s32) {
        case SAI_ECN_MARK_MODE_NONE:
            break;

        case SAI_ECN_MARK_MODE_ALL:
            ecn_green_enabled  = true;
            ecn_yellow_enabled = true;
            ecn_red_enabled    = true;
            break;

        case SAI_ECN_MARK_MODE_GREEN:
            if (wred_yellow_enabled || wred_red_enabled) {
                SX_LOG_ERR("Can't set Green ECN mark mode when WRED Yellow or Red enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            ecn_green_enabled = true;
            break;

        case SAI_ECN_MARK_MODE_YELLOW:
            if (wred_green_enabled || wred_red_enabled) {
                SX_LOG_ERR("Can't set Yellow ECN mark mode when WRED Green or Red enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            ecn_yellow_enabled = true;
            break;

        case SAI_ECN_MARK_MODE_RED:
            if (wred_green_enabled || wred_yellow_enabled) {
                SX_LOG_ERR("Can't set Red ECN mark mode when WRED Green or Yellow enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            ecn_red_enabled = true;
            break;

        case SAI_ECN_MARK_MODE_GREEN_YELLOW:
            if (wred_red_enabled) {
                SX_LOG_ERR("Can't set Green-Yellow ECN mark mode when WRED Red enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            ecn_green_enabled  = true;
            ecn_yellow_enabled = true;
            break;

        case SAI_ECN_MARK_MODE_GREEN_RED:
            if (wred_yellow_enabled) {
                SX_LOG_ERR("Can't set Green-Red ECN mark mode when WRED Yellow enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            ecn_green_enabled = true;
            ecn_red_enabled   = true;
            break;

        case SAI_ECN_MARK_MODE_YELLOW_RED:
            if (wred_green_enabled) {
                SX_LOG_ERR("Can't set Yellow-Red ECN mark mode when WRED Green enabled\n");
                return SAI_STATUS_INVALID_PARAMETER;
            }

            ecn_yellow_enabled = true;
            ecn_red_enabled    = true;
            break;

        default:
            SX_LOG_ERR("Not supported attribute value ecn mark mode %d\n", ecn_en_attr->s32);
            return SAI_STATUS_NOT_SUPPORTED;
        }
    }

    wred_profile.wred_enabled = wred_green_enabled || wred_yellow_enabled || wred_red_enabled;
    wred_profile.ecn_enabled  = ecn_green_enabled || ecn_yellow_enabled || ecn_red_enabled;

    if (!wred_profile.wred_enabled && !wred_profile.ecn_enabled) {
        SX_LOG_ERR("Failed create WRED profile, no data specified\n");
        return SAI_STATUS_FAILURE;
    }

    green_enabled  = wred_green_enabled || ecn_green_enabled;
    yellow_enabled = wred_yellow_enabled || ecn_yellow_enabled;
    red_enabled    = wred_red_enabled || ecn_red_enabled;

    if (green_enabled) {
        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_GREEN_MIN_THRESHOLD,
                                          &green_min_th, &index))) {
            SX_LOG_ERR("Missing mandatory attribute min threshold for green enable\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_GREEN_MAX_THRESHOLD,
                                          &green_max_th, &index))) {
            SX_LOG_ERR("Missing mandatory attribute max threshold for green enable\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        redecn_attr_green.mode                     = SX_COS_REDECN_MODE_ABSOLUTE;
        redecn_attr_green.values.absolute_mode.min = mlnx_wred_sai_threshold_to_sx(green_min_th->u32);
        redecn_attr_green.values.absolute_mode.max = mlnx_wred_sai_threshold_to_sx(green_max_th->u32);
    }

    if (yellow_enabled) {
        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD,
                                          &yellow_min_th, &index))) {
            SX_LOG_ERR("Missing mandatory attribute min threshold for yellow enable\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD,
                                          &yellow_max_th, &index))) {
            SX_LOG_ERR("Missing mandatory attribute max threshold for yellow enable\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        redecn_attr_yellow.mode                     = SX_COS_REDECN_MODE_ABSOLUTE;
        redecn_attr_yellow.values.absolute_mode.min = mlnx_wred_sai_threshold_to_sx(yellow_min_th->u32);
        redecn_attr_yellow.values.absolute_mode.max = mlnx_wred_sai_threshold_to_sx(yellow_max_th->u32);
    }

    if (red_enabled) {
        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_RED_MIN_THRESHOLD,
                                          &red_min_th, &index))) {
            SX_LOG_ERR("Missing mandatory attribute min threshold for red enable\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_RED_MAX_THRESHOLD,
                                          &red_max_th, &index))) {
            SX_LOG_ERR("Missing mandatory attribute max threshold for red enable\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        redecn_attr_red.mode                     = SX_COS_REDECN_MODE_ABSOLUTE;
        redecn_attr_red.values.absolute_mode.min = mlnx_wred_sai_threshold_to_sx(red_min_th->u32);
        redecn_attr_red.values.absolute_mode.max = mlnx_wred_sai_threshold_to_sx(red_max_th->u32);
    }

    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list, SAI_WRED_ATTR_WEIGHT,
                                      &weight, &index))) {
        weight_val = weight->u8;
    } else {
        weight_val = DEFAULT_WEIGHT_VAL;
    }

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS != mlnx_wred_sx_weight_validate(SAI_NULL_OBJECT_ID, weight_val)) {
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + index;
        goto out;
    }

    /* check if we have free slot for profile */
    if (mlnx_wred_db_isfull()) {
        SX_LOG_ERR("Failed to create redecn profile - WRED DB is full\n");
        status = SAI_STATUS_TABLE_FULL;
        goto out;
    }

    /* Create new SAI WRED profile */
    if (green_enabled) {
        sx_status = sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                                  &redecn_attr_green, &wred_profile.green_profile_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to create redecn green profile - %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (yellow_enabled) {
        sx_status = sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                                  &redecn_attr_yellow, &wred_profile.yellow_profile_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to create redecn yellow profile - %s\n", SX_STATUS_MSG(sx_status));

            /* clean up previously created profile */
            mlnx_wred_cleanup_profiles(&wred_profile);

            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (red_enabled) {
        sx_status = sx_api_cos_redecn_profile_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                                  &redecn_attr_red, &wred_profile.red_profile_id);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to create redecn red profile - %s\n", SX_STATUS_MSG(sx_status));

            /* clean up previously created profiles */
            mlnx_wred_cleanup_profiles(&wred_profile);

            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_create(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to create wred profile object\n");

        /* clean up previously created profiles */
        mlnx_wred_cleanup_profiles(&wred_profile);
    } else {
        wred_key_to_str(*wred_id, key_str);
        SX_LOG_NTC("Created %s\n", key_str);
        SX_LOG_DBG("Green profile %d, yellow %d, red %d \n",
                   wred_profile.green_profile_id,
                   wred_profile.yellow_profile_id,
                   wred_profile.red_profile_id);
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_sx_weight_set(weight_val))) {
        SX_LOG_ERR("Failed to set weight %u\n", weight_val);
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *        Remove WRED Profile
 *
 * @param[in] wred_id Wred profile Id.
 *
 * @return SAI_STATUS_SUCCESS on success
 *         Failure status code on error
 */
static sai_status_t mlnx_remove_wred_profile(_In_ sai_object_id_t wred_id)
{
    sx_cos_redecn_profile_attributes_t redecn_attr;
    mlnx_wred_profile_t                wred_profile;
    uint32_t                           wred                     = 0;
    sai_status_t                       status                   = SAI_STATUS_SUCCESS;
    char                               key_str[MAX_KEY_STR_LEN] = {0};

    memset(&redecn_attr, 0, sizeof(redecn_attr));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(wred_id, SAI_OBJECT_TYPE_WRED, &wred, NULL)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    wred_key_to_str(wred_id, key_str);

    sai_db_write_lock();

    if (SAI_STATUS_SUCCESS != (status = mlnx_wred_db_get(wred_id, &wred_profile))) {
        SX_LOG_ERR("Failed to remove, %s not exists\n", key_str);
        goto out;
    }

    if (mlnx_wred_check_in_use(wred_id)) {
        SX_LOG_ERR("Failed to remove %s, profile is in use\n", key_str);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    if (SAI_INVALID_PROFILE_ID != wred_profile.green_profile_id) {
        status = mlnx_wred_remove_profile(wred_id, wred_profile.green_profile_id, FLOW_COLOR_GREEN);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to remove redecn green profile \n");
            goto out;
        }
    }

    if (SAI_INVALID_PROFILE_ID != wred_profile.yellow_profile_id) {
        status = mlnx_wred_remove_profile(wred_id, wred_profile.yellow_profile_id, FLOW_COLOR_YELLOW);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to remove redecn yellow profile \n");
            goto out;
        }
    }

    if (SAI_INVALID_PROFILE_ID != wred_profile.red_profile_id) {
        status = mlnx_wred_remove_profile(wred_id, wred_profile.red_profile_id, FLOW_COLOR_RED);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to remove redecn red profile \n");
            goto out;
        }
    }

    SX_LOG_NTC("Removed %s\n", key_str);

    mlnx_wred_db_remove(wred_id);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

const sai_wred_api_t mlnx_wred_api = {
    mlnx_create_wred_profile,
    mlnx_remove_wred_profile,
    mlnx_set_wred_attribute,
    mlnx_get_wred_attribute
};
