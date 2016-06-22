/*
 *  Copyright (C) 2015. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
#define __MODULE__ SAI_QUEUE

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

typedef sai_status_t (*queue_profile_setter_t) (sai_object_id_t profile_id, sai_object_id_t queue_id);

static sai_status_t mlnx_queue_config_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
static sai_status_t mlnx_queue_config_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_queue_type_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static const sai_attribute_entry_t        queue_attribs[] = {
    { SAI_QUEUE_ATTR_TYPE, false, false, false, true,
      "Queue type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_QUEUE_ATTR_WRED_PROFILE_ID, false, false, true, true,
      "Queue WRED profile ID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_QUEUE_ATTR_BUFFER_PROFILE_ID, false, false, true, true,
      "Queue buffer profile ID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, false, false, true, true,
      "Queue scheduler profile ID", SAI_ATTR_VAL_TYPE_OID },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t queue_vendor_attribs[] = {
    { SAI_QUEUE_ATTR_TYPE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_queue_type_get, (void*)SAI_QUEUE_ATTR_TYPE,
      NULL, NULL },
    { SAI_QUEUE_ATTR_WRED_PROFILE_ID,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_queue_config_get, (void*)SAI_QUEUE_ATTR_WRED_PROFILE_ID,
      mlnx_queue_config_set, (void*)SAI_QUEUE_ATTR_WRED_PROFILE_ID },
    { SAI_QUEUE_ATTR_BUFFER_PROFILE_ID,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_queue_config_get, (void*)SAI_QUEUE_ATTR_BUFFER_PROFILE_ID,
      mlnx_queue_config_set, (void*)SAI_QUEUE_ATTR_BUFFER_PROFILE_ID },
    { SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_queue_config_get, (void*)SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID,
      mlnx_queue_config_set, (void*)SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID }
};

sai_status_t mlnx_queue_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_cos_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

static void queue_key_to_str(_In_ sai_object_id_t queue_id, _Out_ char *key_str)
{
    uint32_t port_num;
    uint8_t  ext_data[EXTENDED_DATA_SIZE] = {0};

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(queue_id, SAI_OBJECT_TYPE_QUEUE, &port_num, ext_data)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid queue");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "queue %u:%u", port_num, ext_data[0]);
    }
}

/*
 * Get index of port configuration in port qos db
 *
 * Arguments:
 *    [in]  log_port_id - logical port id
 *    [out] index       - index of the port in qos db
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS
 *    SAI_STATUS_FAILURE
 *
 */
sai_status_t mlnx_qos_get_port_index(sx_port_log_id_t log_port_id, uint32_t *index)
{
    uint32_t ii = 0;

    if (NULL == index) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_read_lock();
    for (; ii < MAX_PORTS; ii++) {
        if (log_port_id == g_sai_qos_db_ptr->qos_port_db[ii].log_port_id) {
            *index = ii;
            sai_db_unlock();
            return SAI_STATUS_SUCCESS;
        }
    }

    sai_db_unlock();
    SX_LOG_ERR("Port 0x%x not found in DB\n", log_port_id);
    return SAI_STATUS_INVALID_PORT_NUMBER;
}

/* Set queue buffer and scheduler profiles */
static sai_status_t mlnx_queue_config_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sai_object_id_t        queue_id                     = key->object_id;
    sai_object_id_t        profile_id                   = value->oid;
    uint8_t                ext_data[EXTENDED_DATA_SIZE] = {0};
    sx_port_log_id_t       port_num;
    uint32_t               queue_num    = 0, profile_num = 0;
    long                   attr         = (long)arg;
    sai_object_type_t      profile_type = SAI_NULL_OBJECT_ID;
    sai_status_t           status       = SAI_STATUS_SUCCESS;
    queue_profile_setter_t func_setter  = NULL;

    SX_LOG_ENTER();
    assert((SAI_QUEUE_ATTR_BUFFER_PROFILE_ID == attr) ||
           (SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID == attr) ||
           (SAI_QUEUE_ATTR_WRED_PROFILE_ID == attr));

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(queue_id, SAI_OBJECT_TYPE_QUEUE, &port_num, ext_data)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    queue_num = ext_data[0];
    if (queue_num > g_resource_limits.cos_port_ets_traffic_class_max) {
        SX_LOG_ERR("Invalid queue num %u - exceed maximum %u\n", queue_num,
                   g_resource_limits.cos_port_ets_traffic_class_max);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attr) {
    case SAI_QUEUE_ATTR_WRED_PROFILE_ID:
        profile_type = SAI_OBJECT_TYPE_WRED;
        func_setter  = mlnx_wred_apply;
        break;

    case SAI_QUEUE_ATTR_BUFFER_PROFILE_ID:
        profile_type = SAI_OBJECT_TYPE_BUFFER_PROFILE;
        func_setter  = mlnx_buffer_apply;
        break;

    case SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID:
        profile_type = SAI_OBJECT_TYPE_SCHEDULER;
        func_setter  = mlnx_scheduler_to_queue_apply;
        break;
    }

    if (SAI_NULL_OBJECT_ID != profile_id) {
        if (SAI_STATUS_SUCCESS != mlnx_object_to_type(profile_id, profile_type, &profile_num, NULL)) {
            SX_LOG_ERR("Failed to set profile for queue - Invalid object id\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    status = func_setter(profile_id, queue_id);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_queue_config_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_object_id_t          queue_id                     = key->object_id;
    uint8_t                  ext_data[EXTENDED_DATA_SIZE] = {0};
    sx_port_log_id_t         port_num;
    uint32_t                 queue_num = 0;
    long                     attr      = (long)arg;
    sai_status_t             status;
    mlnx_qos_queue_config_t *queue_cfg;
    uint32_t                 buffer_db_index;

    SX_LOG_ENTER();

    assert((SAI_QUEUE_ATTR_WRED_PROFILE_ID == attr) ||
           (SAI_QUEUE_ATTR_BUFFER_PROFILE_ID == attr) ||
           (SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID == attr));

    status = mlnx_object_to_type(queue_id, SAI_OBJECT_TYPE_QUEUE, &port_num, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }
    queue_num = ext_data[0];

    sai_db_read_lock();

    status = mlnx_queue_cfg_lookup(port_num, queue_num, &queue_cfg);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    switch (attr) {
    case SAI_QUEUE_ATTR_WRED_PROFILE_ID:
        value->oid = queue_cfg->wred_id;
        break;

    case SAI_QUEUE_ATTR_BUFFER_PROFILE_ID:
        if (SAI_STATUS_SUCCESS == (status = get_buffer_profile_db_index(queue_cfg->buffer_id, &buffer_db_index))) {
            value->oid = queue_cfg->buffer_id;
        }
        break;

    case SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID:
        value->oid = queue_cfg->sched_obj.scheduler_id;
        break;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_queue_type_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_object_id_t  queue_id                     = key->object_id;
    uint8_t          ext_data[EXTENDED_DATA_SIZE] = {0};
    sx_port_log_id_t port_num;
    uint32_t         queue_num = 0;
    boolean_t        mc_aware  = false;
    sx_status_t      sx_status = SX_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(queue_id, SAI_OBJECT_TYPE_QUEUE, &port_num, ext_data)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    queue_num = ext_data[0];
    if (queue_num > g_resource_limits.cos_port_ets_traffic_class_max) {
        SX_LOG_ERR("Invalid queue num %u - exceed maximum %u\n", queue_num,
                   g_resource_limits.cos_port_ets_traffic_class_max);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sx_status = sx_api_cos_port_tc_mcaware_get(gh_sdk, port_num, &mc_aware);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to get MC status for the port 0x%x - %s\n", port_num, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (false == mc_aware) {
        value->s32 = SAI_QUEUE_TYPE_ALL;
    } else {
        value->s32 = (queue_num < ((g_resource_limits.cos_port_ets_traffic_class_max + 1) / 2)) ?
                     SAI_QUEUE_TYPE_UNICAST : SAI_QUEUE_TYPE_MULTICAST;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Set queue attribute value.
 *
 * Arguments:
 *    [in] queue_id - queue id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_queue_attribute(_In_ sai_object_id_t queue_id, _In_ const sai_attribute_t *attr)
{
    sai_status_t           sai_status;
    const sai_object_key_t key                      = { .object_id = queue_id };
    char                   key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    queue_key_to_str(queue_id, key_str);
    sai_status = sai_set_attribute(&key, key_str, queue_attribs, queue_vendor_attribs, attr);
    SX_LOG_EXIT();
    return sai_status;
}

/*
 * Routine Description:
 *   Get queue attribute value.
 *
 * Arguments:
 *    [in] queue_id - queue id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_queue_attribute(_In_ sai_object_id_t     queue_id,
                                             _In_ uint32_t            attr_count,
                                             _Inout_ sai_attribute_t *attr_list)
{
    sai_status_t           sai_status;
    const sai_object_key_t key                      = { .object_id = queue_id };
    char                   key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    queue_key_to_str(queue_id, key_str);
    sai_status = sai_get_attributes(&key, key_str, queue_attribs, queue_vendor_attribs, attr_count, attr_list);
    SX_LOG_EXIT();
    return sai_status;
}

/*
 * Routine Description:
 *   Get queue statistics counters.
 *
 * Arguments:
 *    [in] queue_id - queue id
 *    [in] counter_ids - specifies the array of counter ids
 *    [in] number_of_counters - number of counters in the array
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_queue_statistics(_In_ sai_object_id_t                 queue_id,
                                              _In_ const sai_queue_stat_counter_t *counter_ids,
                                              _In_ uint32_t                        number_of_counters,
                                              _Out_ uint64_t                     * counters)
{
    sai_status_t                     status;
    uint8_t                          ext_data[EXTENDED_DATA_SIZE] = {0};
    uint8_t                          queue_num                    = 0;
    sx_port_log_id_t                 port_num;
    sx_cos_redecn_port_counters_t    redecn_cnts;
    uint32_t                         ii = 0;
    char                             key_str[MAX_KEY_STR_LEN];
    sx_port_statistic_usage_params_t stats_usage;
    sx_port_occupancy_statistics_t   occupancy_stats;
    sx_port_cntr_prio_t              prio_cnts;
    uint32_t                         usage_cnt = 1;

    SX_LOG_ENTER();

    memset(&redecn_cnts, 0, sizeof(redecn_cnts));

    queue_key_to_str(queue_id, key_str);
    SX_LOG_NTC("Get queue stats %s\n", key_str);

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(queue_id, SAI_OBJECT_TYPE_QUEUE, &port_num, ext_data)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    queue_num = ext_data[0];
    /* TODO : change to > g_resource_limits.cos_port_ets_traffic_class_max when sdk is updated to use rm */
    if (queue_num >= RM_API_COS_TRAFFIC_CLASS_NUM) {
        SX_LOG_ERR("Invalid queue num %u - exceed maximum %u\n", queue_num,
                   g_resource_limits.cos_port_ets_traffic_class_max);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_cos_redecn_counters_get(gh_sdk, SX_ACCESS_CMD_READ, port_num, &redecn_cnts))) {
        SX_LOG_ERR("Failed to get port redecn counters - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* TODO : assumes one to one mapping, with same value, of IEEE prio = queue num
     * SDK extension may do the mapping from IEEE prio to TC, and remove this limitation 
     * and use sx_api_port_counter_tc_get */
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_port_counter_prio_get(gh_sdk, SX_ACCESS_CMD_READ, port_num, queue_num, &prio_cnts))) {
        SX_LOG_ERR("Failed to get port tc counters - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    memset(&stats_usage, 0, sizeof(stats_usage));
    stats_usage.port_cnt                                 = 1;
    stats_usage.log_port_list_p                          = &port_num;
    stats_usage.sx_port_params.port_params_type          = SX_COS_EGRESS_PORT_TRAFFIC_CLASS_ATTR_E;
    stats_usage.sx_port_params.port_params_cnt           = 1;
    stats_usage.sx_port_params.port_param.port_tc_list_p = &queue_num;

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_cos_port_buff_type_statistic_get(gh_sdk, SX_ACCESS_CMD_READ, &stats_usage, 1,
                                                          &occupancy_stats, &usage_cnt))) {
        SX_LOG_ERR("Failed to get port buff statistics - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_QUEUE_STAT_DROPPED_PACKETS:
        case SAI_QUEUE_STAT_DROPPED_BYTES:
        case SAI_QUEUE_STAT_GREEN_PACKETS:
        case SAI_QUEUE_STAT_GREEN_BYTES:
        case SAI_QUEUE_STAT_GREEN_DROPPED_PACKETS:
        case SAI_QUEUE_STAT_GREEN_DROPPED_BYTES:
        case SAI_QUEUE_STAT_YELLOW_PACKETS:
        case SAI_QUEUE_STAT_YELLOW_BYTES:
        case SAI_QUEUE_STAT_YELLOW_DROPPED_PACKETS:
        case SAI_QUEUE_STAT_YELLOW_DROPPED_BYTES:
        case SAI_QUEUE_STAT_RED_PACKETS:
        case SAI_QUEUE_STAT_RED_BYTES:
        case SAI_QUEUE_STAT_RED_DROPPED_PACKETS:
        case SAI_QUEUE_STAT_RED_DROPPED_BYTES:
        case SAI_QUEUE_STAT_GREEN_DISCARD_DROPPED_PACKETS:
        case SAI_QUEUE_STAT_GREEN_DISCARD_DROPPED_BYTES:
        case SAI_QUEUE_STAT_YELLOW_DISCARD_DROPPED_PACKETS:
        case SAI_QUEUE_STAT_YELLOW_DISCARD_DROPPED_BYTES:
        case SAI_QUEUE_STAT_RED_DISCARD_DROPPED_PACKETS:
        case SAI_QUEUE_STAT_RED_DISCARD_DROPPED_BYTES:
        case SAI_QUEUE_STAT_DISCARD_DROPPED_BYTES:
        case SAI_QUEUE_STAT_SHARED_CURR_OCCUPANCY_BYTES:
        case SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES:
            SX_LOG_ERR("Queue counter %d set item %u not supported\n", counter_ids[ii], ii);
            return SAI_STATUS_ATTR_NOT_SUPPORTED_0;

        case SAI_QUEUE_STAT_PACKETS:
            counters[ii] = prio_cnts.tx_frames;
            break;

        case SAI_QUEUE_STAT_BYTES:
            counters[ii] = prio_cnts.tx_octets;
            break;

        case SAI_QUEUE_STAT_DISCARD_DROPPED_PACKETS:
            counters[ii] = redecn_cnts.tc_red_dropped_packets[queue_num];
            break;

        case SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES:
            counters[ii] = (uint64_t)occupancy_stats.statistics.curr_occupancy *
                           g_resource_limits.shared_buff_buffer_unit_size;
            break;

        case SAI_QUEUE_STAT_WATERMARK_BYTES:
            counters[ii] = (uint64_t)occupancy_stats.statistics.watermark *
                           g_resource_limits.shared_buff_buffer_unit_size;
            break;

        default:
            SX_LOG_ERR("Invalid queue counter %d\n", counter_ids[ii]);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief   Clear queue statistics counters.
 *
 * @param[in] queue_id Queue id
 * @param[in] counter_ids specifies the array of counter ids
 * @param[in] number_of_counters number of counters in the array
 *
 * @return SAI_STATUS_SUCCESS on success
 *         Failure status code on error
 */
static sai_status_t mlnx_clear_queue_stats(_In_ sai_object_id_t                 queue_id,
                                           _In_ const sai_queue_stat_counter_t *counter_ids,
                                           _In_ uint32_t                        number_of_counters)
{
    UNREFERENCED_PARAMETER(queue_id);
    UNREFERENCED_PARAMETER(number_of_counters);

    SX_LOG_ENTER();

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* QoS DB lock is required */
sai_status_t mlnx_queue_cfg_lookup(sx_port_log_id_t log_port_id, uint32_t queue_idx, mlnx_qos_queue_config_t **cfg)
{
    mlnx_qos_port_config_t *port;
    uint32_t                ii;

    if (queue_idx >= MAX_QUEUES) {
        SX_LOG_ERR("Invalid queue num %u - exceed maximum %u\n", queue_idx,
                   MAX_QUEUES - 1);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    qos_port_foreach(port, ii) {
        if (port->log_port_id != log_port_id) {
            continue;
        }

        *cfg = &g_sai_qos_db_ptr->queue_db[port->start_queues_index + queue_idx];
        return SAI_STATUS_SUCCESS;
    }

    SX_LOG_ERR("Filed to lookup queue by index %u on port log id %x\n",
               queue_idx, log_port_id);

    return SAI_STATUS_INVALID_PARAMETER;
}

const sai_queue_api_t mlnx_queue_api = {
    mlnx_set_queue_attribute,
    mlnx_get_queue_attribute,
    mlnx_get_queue_statistics,
    mlnx_clear_queue_stats
};
